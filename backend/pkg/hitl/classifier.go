package hitl

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Classification is a risk class with the human-readable reason it was chosen,
// stored on the approval so the operator sees why a call was flagged.
type Classification struct {
	Risk   RiskClass
	Reason string
}

// dangerousCommands take over or destroy the host; always blocked so the
// operator sees them even in risk_classified mode.
var dangerousCommands = []string{
	"rm -rf /", "rm -fr /", "mkfs", "dd if=", "> /dev/sd", "of=/dev/sd",
	":(){ :|:& };:", "shutdown", "reboot", "halt", "poweroff", "init 0",
	"chmod -r 777 /", "chown -r", "/etc/shadow", "/etc/gshadow",
}

// exploitTools actively exploit or crack, unlike the discovery tools below;
// running one is high risk whatever its target.
var exploitTools = []string{
	"sqlmap", "hydra", "medusa", "john", "hashcat", "metasploit",
	"msfconsole", "msfvenom", "crackmapexec", "responder", "mimikatz",
}

// scanTools are noisy but non-destructive discovery tools.
var scanTools = []string{
	"nmap", "masscan", "nikto", "dirb", "gobuster", "ffuf",
	"nuclei", "whatweb", "wpscan", "amass", "subfinder",
}

// networkCommands reach out over the network.
var networkCommands = []string{
	"curl", "wget", "nc ", "ncat", "netcat", "ssh ", "scp ", "sftp", "rsync", "ftp ",
}

// credentialIndicators mark a request aimed at an authentication surface.
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

// readOnlyCommands are the first words of commands that only observe.
var readOnlyCommands = map[string]struct{}{
	"ls": {}, "cat": {}, "head": {}, "tail": {}, "grep": {}, "find": {}, "which": {},
	"whoami": {}, "id": {}, "pwd": {}, "echo": {}, "date": {}, "uname": {}, "hostname": {},
	"wc": {}, "sort": {}, "uniq": {}, "diff": {}, "file": {}, "stat": {}, "readlink": {},
	"ps": {}, "top": {}, "df": {}, "du": {}, "free": {}, "env": {}, "printenv": {}, "ss": {},
}

// sensitivePathParts mark a filesystem write that can subvert the host.
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

// Classify scores a tool call. toolName and isEnvironment come from the tool
// registry: an environment tool runs in the sandbox and is classified on its
// arguments, while every other tool (agent delegation, search, memory) is a
// low-risk orchestration step. An unparseable environment call is treated as
// high risk, never waved through.
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

	if hit, ok := containsAny(cmd, dangerousCommands); ok {
		return Classification{Risk: RiskBlocked, Reason: "destructive or host-takeover command (" + hit + ")"}
	}
	if reverseShellRe.MatchString(cmd) {
		return Classification{Risk: RiskHigh, Reason: "reverse shell or remote code execution"}
	}
	if hit, ok := containsAny(cmd, exploitTools); ok {
		return Classification{Risk: RiskHigh, Reason: "active exploitation tool (" + hit + ")"}
	}
	if _, ok := containsAny(cmd, networkCommands); ok {
		if writeHTTPRe.MatchString(ta.Input) {
			if _, cred := containsAny(cmd, credentialIndicators); cred {
				return Classification{Risk: RiskHigh, Reason: "state-changing request against an authentication surface"}
			}
		}
	}
	if hit, ok := containsAny(cmd, scanTools); ok {
		return Classification{Risk: RiskMedium, Reason: "network scanning tool (" + hit + ")"}
	}
	if hit, ok := containsAny(cmd, networkCommands); ok {
		return Classification{Risk: RiskMedium, Reason: "outbound network command (" + strings.TrimSpace(hit) + ")"}
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

func containsAny(s string, needles []string) (string, bool) {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return n, true
		}
	}
	return "", false
}

func isReadOnly(cmd string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return true
	}
	first := fields[0]
	if idx := strings.LastIndex(first, "/"); idx >= 0 {
		first = first[idx+1:]
	}
	_, ok := readOnlyCommands[first]
	return ok
}
