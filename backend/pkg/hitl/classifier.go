package hitl

import (
	"encoding/json"
	"regexp"
	"strings"
)

// dangerousCommands are destructive/host-takeover shell commands; always high risk.
var dangerousCommands = []string{
	"sudo",
	"rm -rf",
	"rm -fr",
	"mkfs",
	"dd if=",
	"chmod 777",
	"chmod +s",
	"> /dev/",
	":(){ :|:& };:",
	"shutdown",
	"reboot",
	"init 0",
	"halt",
	"poweroff",
}

// exploitTools actively attempt exploitation or credential cracking against a target,
// unlike passive discovery tools; running them is inherently high risk.
var exploitTools = []string{
	"sqlmap",
	"hydra",
	"medusa",
	"john",
	"hashcat",
	"metasploit",
	"msfconsole",
	"msfvenom",
	"crackmapexec",
	"responder",
}

// scanTools are passive/discovery tools: noisy but non-destructive by default.
var scanTools = []string{
	"nmap",
	"masscan",
	"nikto",
	"dirb",
	"gobuster",
	"ffuf",
	"nuclei",
	"burpsuite",
	"whatweb",
	"wpscan",
}

// networkCommands are commands that make outbound network connections.
var networkCommands = []string{
	"curl",
	"wget",
	"nc ",
	"ncat",
	"netcat",
	"ssh ",
	"scp ",
	"sftp",
	"rsync",
	"ftp ",
}

// credentialIndicators flag requests that target an authentication/credential surface.
var credentialIndicators = []string{
	"password", "passwd", "/auth", "/login", "signin", "sign-in", "credential", "token=",
}

// writeHTTPRe matches a state-changing HTTP request (vs. a plain read-only GET), e.g.
// curl -X POST/--request PUT/--data/--form. Matched against the ORIGINAL (non-lowercased)
// command because curl's short flags are case-sensitive and collide when lowercased
// (-d data vs -D dump-header, -F form vs -f fail, -X request vs -x proxy).
var writeHTTPRe = regexp.MustCompile(`--request\s+(?i:post|put|delete|patch)\b|-X\s*(?i:post|put|delete|patch)\b|--data(-raw|-binary|-urlencode)?[=\s]|--form[=\s]|-d\s|-F\s`)

// reverseShellRe matches classic reverse-shell / remote-code-execution techniques:
// bash -i >& /dev/tcp/..., nc -e /bin/sh, or piping remote content into an interpreter.
var reverseShellRe = regexp.MustCompile(`/dev/tcp/|-e\s+(/bin/(sh|bash)|cmd\.exe)|\|\s*(sh|bash|zsh|dash|python3?|perl|ruby|node)\b`)

// sqlInjectionRe matches common SQL-injection payload markers in a command/URL.
var sqlInjectionRe = regexp.MustCompile(`(?i)union\s+select|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1|\bsleep\(\d|\bbenchmark\(|\bxp_cmdshell\b|\bwaitfor\s+delay\b`)

// TerminalArgs represents the expected JSON structure for terminal tool calls.
// Field names must match tools.TerminalAction (backend/pkg/tools/args.go).
type TerminalArgs struct {
	Input  string `json:"input"`
	Detach bool   `json:"detach"`
}

// FileArgs represents the expected JSON structure for file tool calls.
// Field names must match tools.FileAction (backend/pkg/tools/args.go).
type FileArgs struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Action  string `json:"action"` // "read_file" or "update_file"
}

// ClassifyRisk assesses the risk level of a tool call based on the tool name and arguments.
func ClassifyRisk(toolName string, args json.RawMessage) RiskClass {
	switch toolName {
	case "terminal":
		return classifyTerminalRisk(args)
	case "file":
		return classifyFileRisk(args)
	case "browser":
		// Browser tool only extracts page content (markdown/html/links); it never
		// submits forms or executes anything, so it's no riskier than a file read.
		return RiskLow
	default:
		return RiskLow
	}
}

func classifyTerminalRisk(args json.RawMessage) RiskClass {
	var ta TerminalArgs
	if err := json.Unmarshal(args, &ta); err != nil {
		return RiskHigh // can't parse = assume high risk
	}

	cmd := strings.ToLower(ta.Input)

	// Destructive/host-takeover commands are always high risk.
	if containsAny(cmd, dangerousCommands) {
		return RiskHigh
	}

	// Remote code execution patterns: reverse shells, piping remote content into an interpreter.
	if reverseShellRe.MatchString(cmd) {
		return RiskHigh
	}

	// Active exploitation/credential-cracking tools are high risk regardless of target.
	if containsAny(cmd, exploitTools) {
		return RiskHigh
	}

	// SQL-injection payloads indicate active exploitation, not passive recon.
	if sqlInjectionRe.MatchString(cmd) {
		return RiskHigh
	}

	// A state-changing HTTP request against an auth/credential endpoint is an active
	// account-takeover/brute-force attempt, not passive recon.
	if containsAny(cmd, networkCommands) && writeHTTPRe.MatchString(ta.Input) && containsAny(cmd, credentialIndicators) {
		return RiskHigh
	}

	// Outbound network activity and passive scanning tools: real but non-destructive recon.
	if containsAny(cmd, networkCommands) || containsAny(cmd, scanTools) {
		return RiskMedium
	}

	// Detached commands are riskier (long-running, harder to track)
	if ta.Detach {
		return RiskMedium
	}

	// Simple read-only or benign commands
	if isLikelyReadOnly(cmd) {
		return RiskLow
	}

	// Unrecognized and not obviously read-only: err on the side of caution.
	return RiskMedium
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func classifyFileRisk(args json.RawMessage) RiskClass {
	var fa FileArgs
	if err := json.Unmarshal(args, &fa); err != nil {
		return RiskMedium
	}

	// Read operations are low risk
	if fa.Action == "read_file" {
		return RiskLow
	}

	// Writing to sensitive paths
	path := strings.ToLower(fa.Path)
	sensitivePaths := []string{
		"/etc/", "/root/", "/var/", "/usr/",
		".ssh/", ".bashrc", ".profile", ".env",
		"/proc/", "/sys/", "/dev/",
	}
	if containsAny(path, sensitivePaths) {
		return RiskHigh
	}

	return RiskMedium
}

func isLikelyReadOnly(cmd string) bool {
	readOnlyPrefixes := []string{
		"ls", "cat", "head", "tail", "grep", "find", "which",
		"whoami", "id", "pwd", "echo", "date", "uname",
		"wc", "sort", "uniq", "diff", "file", "stat",
		"ps", "top", "df", "du", "free", "env", "printenv",
	}

	// Get the first word of the command
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return true
	}
	first := parts[0]
	// Strip any path prefix
	if idx := strings.LastIndex(first, "/"); idx >= 0 {
		first = first[idx+1:]
	}

	for _, prefix := range readOnlyPrefixes {
		if first == prefix {
			return true
		}
	}
	return false
}
