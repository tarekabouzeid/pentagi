package hitl

import (
	"encoding/json"
	"strings"
)

// dangerousCommands are shell commands/patterns that escalate risk.
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

// reconTools are commands often used in penetration testing.
var reconTools = []string{
	"nmap",
	"masscan",
	"nikto",
	"dirb",
	"gobuster",
	"ffuf",
	"sqlmap",
	"hydra",
	"john",
	"hashcat",
	"metasploit",
	"msfconsole",
	"msfvenom",
	"burpsuite",
	"nuclei",
}

// TerminalArgs represents the expected JSON structure for terminal tool calls.
type TerminalArgs struct {
	Command string `json:"command"`
	Detach  bool   `json:"detach"`
}

// FileArgs represents the expected JSON structure for file tool calls.
type FileArgs struct {
	Filepath string `json:"filepath"`
	Content  string `json:"content"`
	Action   string `json:"action"` // "read" or "write"
}

// ClassifyRisk assesses the risk level of a tool call based on the tool name and arguments.
func ClassifyRisk(toolName string, args json.RawMessage) RiskClass {
	switch toolName {
	case "terminal":
		return classifyTerminalRisk(args)
	case "file":
		return classifyFileRisk(args)
	case "browser":
		return RiskMedium
	default:
		return RiskLow
	}
}

func classifyTerminalRisk(args json.RawMessage) RiskClass {
	var ta TerminalArgs
	if err := json.Unmarshal(args, &ta); err != nil {
		return RiskHigh // can't parse = assume high risk
	}

	cmd := strings.ToLower(ta.Command)

	// Check for blocked/dangerous commands
	for _, pattern := range dangerousCommands {
		if strings.Contains(cmd, pattern) {
			return RiskHigh
		}
	}

	// Check for network activity
	for _, pattern := range networkCommands {
		if strings.Contains(cmd, pattern) {
			return RiskMedium
		}
	}

	// Check for recon/exploitation tools
	for _, pattern := range reconTools {
		if strings.Contains(cmd, pattern) {
			return RiskMedium
		}
	}

	// Detached commands are riskier (long-running, harder to track)
	if ta.Detach {
		return RiskMedium
	}

	// Simple read-only or benign commands
	if isLikelyReadOnly(cmd) {
		return RiskLow
	}

	// Default: low risk for unrecognized but non-flagged commands
	return RiskLow
}

func classifyFileRisk(args json.RawMessage) RiskClass {
	var fa FileArgs
	if err := json.Unmarshal(args, &fa); err != nil {
		return RiskMedium
	}

	// Read operations are low risk
	if fa.Action == "read" {
		return RiskLow
	}

	// Writing to sensitive paths
	path := strings.ToLower(fa.Filepath)
	sensitivePaths := []string{
		"/etc/", "/root/", "/var/", "/usr/",
		".ssh/", ".bashrc", ".profile", ".env",
		"/proc/", "/sys/", "/dev/",
	}
	for _, sp := range sensitivePaths {
		if strings.Contains(path, sp) {
			return RiskHigh
		}
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
