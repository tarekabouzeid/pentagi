package hitl

import (
	"encoding/json"
	"regexp"
	"strings"
)

type Classification struct {
	Risk   RiskClass
	Reason string
}

// blockedWords are commands rated blocked wherever they appear as a word.
var blockedWords = []string{"shutdown", "reboot", "halt", "poweroff"}

// blockedFragments are rated blocked wherever they appear in the command text.
var blockedFragments = []string{
	"> /dev/sd", "of=/dev/sd", ":(){ :|:& };:", "/etc/shadow", "/etc/gshadow",
}

// wipeTargets are the targets that make a recursive rm destructive.
var wipeTargets = map[string]struct{}{
	"/": {}, "/*": {}, "~": {}, "~/*": {}, "$home": {}, "$home/*": {}, "${home}": {},
	"*": {}, "/etc": {}, "/usr": {}, "/var": {}, "/home": {}, "/bin": {}, "/boot": {}, "/lib": {}, "/root": {},
}

var exploitTools = []string{
	"sqlmap", "hydra", "medusa", "john", "hashcat", "metasploit",
	"msfconsole", "msfvenom", "crackmapexec", "responder", "mimikatz",
}

var scanTools = []string{
	"nmap", "masscan", "nikto", "dirb", "gobuster", "ffuf",
	"nuclei", "whatweb", "wpscan", "amass", "subfinder",
}

var networkCommands = []string{
	"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp",
}

var credentialIndicators = []string{
	"password", "passwd", "/auth", "/login", "signin", "sign-in", "credential", "token=",
}

// reverseShellRe matches reverse-shell and remote-code-execution shapes:
// bash -i >& /dev/tcp/..., nc -e /bin/sh, or piping remote content to an interpreter.
var reverseShellRe = regexp.MustCompile(`/dev/tcp/|-e\s+(/bin/(sh|bash)|cmd\.exe)|\|\s*(sh|bash|zsh|dash|python3?|perl|ruby|node)\b`)

// writeHTTPRe matches a state-changing HTTP request, as opposed to a plain GET:
// curl -X POST / --request PUT / --data / --form. Matched against the ORIGINAL
// (non-lowercased) command because curl's short flags are case sensitive and
// collide when lowercased: -d data vs -D dump-header, -F form vs -f fail,
// -X request vs -x proxy.
var writeHTTPRe = regexp.MustCompile(`--request\s+(?i:post|put|delete|patch)\b|-X\s*(?i:post|put|delete|patch)\b|--data(-raw|-binary|-urlencode)?[=\s]|--form[=\s]|-d\s|-F\s`)

var readOnlyCommands = map[string]struct{}{
	"ls": {}, "cat": {}, "head": {}, "tail": {}, "grep": {}, "find": {}, "which": {},
	"whoami": {}, "id": {}, "pwd": {}, "echo": {}, "date": {}, "uname": {}, "hostname": {},
	"wc": {}, "sort": {}, "uniq": {}, "diff": {}, "file": {}, "stat": {}, "readlink": {},
	"ps": {}, "top": {}, "df": {}, "du": {}, "free": {}, "env": {}, "printenv": {}, "ss": {},
}

var sensitivePathParts = []string{
	"/etc/", "/root/", "/boot/", "/usr/", "/bin/", "/sbin/", "/lib/",
	"/proc/", "/sys/", "/dev/", ".ssh/", ".bashrc", ".bash_profile", ".profile",
	"authorized_keys", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "crontab",
}

type terminalArgs struct {
	Input  string `json:"input"`
	Detach bool   `json:"detach"`
}

type fileArgs struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}

// Classify: only environment tools (sandbox execution) are classified on their arguments; all others are low risk. An unparseable environment call is high risk, never waved through.
func Classify(toolName string, isEnvironment bool, args json.RawMessage) Classification {
	if !isEnvironment {
		return Classification{Risk: RiskLow, Reason: "non-sandbox tool"}
	}

	switch toolName {
	case "terminal":
		return classifyTerminal(args)
	case "file":
		return classifyFile(args)
	default:
		return Classification{Risk: RiskLow, Reason: "read-only sandbox tool"}
	}
}

func classifyTerminal(args json.RawMessage) Classification {
	var ta terminalArgs
	if err := json.Unmarshal(args, &ta); err != nil {
		return Classification{Risk: RiskHigh, Reason: "terminal arguments could not be parsed"}
	}

	cmd := strings.ToLower(ta.Input)

	if hit, ok := blockedCommand(cmd); ok {
		return Classification{Risk: RiskBlocked, Reason: "destructive or host-takeover command (" + hit + ")"}
	}
	if reverseShellRe.MatchString(cmd) {
		return Classification{Risk: RiskHigh, Reason: "reverse shell or remote code execution"}
	}
	if hit, ok := containsWord(cmd, exploitTools); ok {
		return Classification{Risk: RiskHigh, Reason: "active exploitation tool (" + hit + ")"}
	}
	if _, ok := containsWord(cmd, networkCommands); ok {
		if writeHTTPRe.MatchString(ta.Input) {
			if _, cred := containsAny(cmd, credentialIndicators); cred {
				return Classification{Risk: RiskHigh, Reason: "state-changing request against an authentication surface"}
			}
		}
	}
	if hit, ok := containsWord(cmd, scanTools); ok {
		return Classification{Risk: RiskMedium, Reason: "network scanning tool (" + hit + ")"}
	}
	if hit, ok := containsWord(cmd, networkCommands); ok {
		return Classification{Risk: RiskMedium, Reason: "outbound network command (" + hit + ")"}
	}
	if target, ok := sensitiveRedirect(cmd); ok {
		return Classification{Risk: RiskHigh, Reason: "write to a sensitive path (" + target + ")"}
	}
	if ta.Detach {
		return Classification{Risk: RiskMedium, Reason: "detached long-running command"}
	}
	if isReadOnly(cmd) {
		return Classification{Risk: RiskLow, Reason: "read-only command"}
	}

	return Classification{Risk: RiskMedium, Reason: "command with side effects"}
}

func classifyFile(args json.RawMessage) Classification {
	var fa fileArgs
	if err := json.Unmarshal(args, &fa); err != nil {
		return Classification{Risk: RiskHigh, Reason: "file arguments could not be parsed"}
	}

	if fa.Action == "read_file" {
		return Classification{Risk: RiskLow, Reason: "file read"}
	}

	path := strings.ToLower(fa.Path)
	if hit, ok := containsAny(path, sensitivePathParts); ok {
		return Classification{Risk: RiskHigh, Reason: "write to a sensitive path (" + hit + ")"}
	}

	return Classification{Risk: RiskMedium, Reason: "file write"}
}

var (
	benignRedirectRe = regexp.MustCompile(`\d*>&\d+|\d*>>?\s*/dev/null`)
	redirectRe       = regexp.MustCompile(`>>?\s*(\S+)`)
	segmentSplitRe   = regexp.MustCompile(`[;&|\n]`)
)

// wordRe returns a matcher for word as a whole shell word, so "john" does not match "johnson.txt".
func wordRe(word string) *regexp.Regexp {
	return regexp.MustCompile("(^|[\\s;&|(`\"'/=])" + regexp.QuoteMeta(word) + "($|[\\s;&|)`\"'])")
}

var wordMatchers = map[string]*regexp.Regexp{}

func init() {
	for _, list := range [][]string{blockedWords, exploitTools, scanTools, networkCommands} {
		for _, w := range list {
			wordMatchers[w] = wordRe(w)
		}
	}
}

func containsWord(s string, words []string) (string, bool) {
	for _, w := range words {
		if wordMatchers[w].MatchString(s) {
			return w, true
		}
	}
	return "", false
}

func containsAny(s string, needles []string) (string, bool) {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return n, true
		}
	}
	return "", false
}

// segments splits a command line on its separators into simple commands.
func segments(cmd string) [][]string {
	var out [][]string
	for _, seg := range segmentSplitRe.Split(cmd, -1) {
		if fields := strings.Fields(seg); len(fields) > 0 {
			out = append(out, fields)
		}
	}
	return out
}

func commandName(field string) string {
	if idx := strings.LastIndex(field, "/"); idx >= 0 {
		return field[idx+1:]
	}
	return field
}

func normalizeTarget(t string) string {
	if trimmed := strings.TrimRight(t, "/"); trimmed != "" {
		return trimmed
	}
	return t
}

func recursiveFlag(fields []string) bool {
	for _, f := range fields[1:] {
		if f == "--recursive" || (strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.ContainsAny(f, "r")) {
			return true
		}
	}
	return false
}

// blockedCommand reports destructive and host-takeover commands.
func blockedCommand(cmd string) (string, bool) {
	if hit, ok := containsAny(cmd, blockedFragments); ok {
		return hit, true
	}
	if hit, ok := containsWord(cmd, blockedWords); ok {
		return hit, true
	}
	for _, fields := range segments(cmd) {
		name := commandName(fields[0])
		switch {
		case strings.HasPrefix(name, "mkfs"):
			return "mkfs", true
		case name == "dd" && strings.Contains(strings.Join(fields[1:], " "), "if="):
			return "dd if=", true
		case (name == "init" || name == "telinit") && len(fields) > 1 && fields[1] == "0":
			return "init 0", true
		case name == "chown" && recursiveFlag(fields):
			return "chown -R", true
		case name == "rm":
			for _, f := range fields[1:] {
				if f == "--no-preserve-root" {
					return "rm --no-preserve-root", true
				}
				if _, wipe := wipeTargets[normalizeTarget(f)]; wipe && recursiveFlag(fields) {
					return "rm -r " + f, true
				}
			}
		case name == "chmod" && recursiveFlag(fields):
			for _, f := range fields[1:] {
				if f == "/" {
					return "chmod -R /", true
				}
			}
		}
	}
	return "", false
}

// sensitiveRedirect reports an output redirection into a sensitive path.
func sensitiveRedirect(cmd string) (string, bool) {
	cmd = benignRedirectRe.ReplaceAllString(cmd, "")
	for _, m := range redirectRe.FindAllStringSubmatch(cmd, -1) {
		if hit, ok := containsAny(m[1], sensitivePathParts); ok {
			return hit, true
		}
	}
	return "", false
}

// isReadOnly is true only when every simple command of the line is on the
// read-only list and nothing in it can write, substitute or execute.
func isReadOnly(cmd string) bool {
	cmd = benignRedirectRe.ReplaceAllString(cmd, "")
	if strings.ContainsAny(cmd, ">`<") || strings.Contains(cmd, "$(") {
		return false
	}
	segs := segments(cmd)
	if len(segs) == 0 {
		return true
	}
	for _, fields := range segs {
		name := commandName(fields[0])
		if _, ok := readOnlyCommands[name]; !ok {
			return false
		}
		if !readOnlyArgs(name, fields[1:]) {
			return false
		}
	}
	return true
}

func readOnlyArgs(name string, args []string) bool {
	switch name {
	case "env", "printenv":
		return name == "printenv" || len(args) == 0
	case "find":
		for _, a := range args {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls":
				return false
			}
		}
	case "sort":
		for _, a := range args {
			if a == "-o" || strings.HasPrefix(a, "--output") {
				return false
			}
		}
	}
	return true
}
