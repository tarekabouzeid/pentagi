package hitl

import (
	"strings"
	"testing"
)

func TestHITL_requiresApproval_FollowsTheMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		tool string
		env  bool
		risk RiskClass
		want bool
	}{
		{"off never asks", Config{Mode: ModeOff}, "terminal", true, RiskHigh, false},
		{"off still asks for a blocked call", Config{Mode: ModeOff}, "terminal", true, RiskBlocked, true},
		{"all_tools asks for a low sandbox call", Config{Mode: ModeAllTools}, "file", true, RiskLow, true},
		{"all_tools skips an orchestration tool", Config{Mode: ModeAllTools}, "done", false, RiskLow, false},
		{"all_tools asks for an orchestration tool the list names", Config{Mode: ModeAllTools, Tools: []string{"done"}}, "done", false, RiskLow, true},
		{"all_tools still catches a blocked orchestration call", Config{Mode: ModeAllTools}, "done", false, RiskBlocked, true},
		{"risk_classified asks at the threshold", Config{Mode: ModeRiskClassified, MinRisk: RiskMedium}, "terminal", true, RiskMedium, true},
		{"risk_classified skips below the threshold", Config{Mode: ModeRiskClassified, MinRisk: RiskHigh}, "terminal", true, RiskMedium, false},
		{"the default threshold is high", Config{Mode: ModeRiskClassified}, "terminal", true, RiskMedium, false},
		{"the default threshold asks at high", Config{Mode: ModeRiskClassified}, "terminal", true, RiskHigh, true},
		{"an explicit tool list gates only its tools", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "terminal", true, RiskLow, true},
		{"an explicit tool list skips other tools", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "file", true, RiskHigh, false},
		{"an explicit tool list still catches a blocked call", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "file", true, RiskBlocked, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.requiresApproval(tc.tool, tc.env, tc.risk); got != tc.want {
				t.Fatalf("requiresApproval(%q, %s) = %v, want %v", tc.tool, tc.risk, got, tc.want)
			}
		})
	}
}

func TestHITL_Enabled_IsOffByDefault(t *testing.T) {
	if (Config{}).Enabled() {
		t.Fatal("the zero config must be disabled so an unconfigured flow runs unattended")
	}
	if !(Config{Mode: ModeRiskClassified}).Enabled() {
		t.Fatal("a risk_classified policy must be enabled")
	}
}

func TestHITL_ConfigFromFunctions_ReadsOnlyTheHITLKey(t *testing.T) {
	cfg, err := ConfigFromFunctions([]byte(`{"sandbox":{"backend":"docker"},"hitl":{"mode":"all_tools","max_denials":2}}`))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.Mode != ModeAllTools || cfg.MaxDenials != 2 {
		t.Fatalf("read %+v, want all_tools with max_denials 2", cfg)
	}

	empty, err := ConfigFromFunctions([]byte(`{"sandbox":{"backend":"docker"}}`))
	if err != nil {
		t.Fatalf("read config without hitl: %v", err)
	}
	if empty.Enabled() {
		t.Fatal("functions without a hitl key must leave HITL disabled")
	}
}

func TestHITL_Validate_RejectsAPolicyTheDispatcherCannotHonour(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"the zero config is valid", Config{}, ""},
		{"a full policy is valid", Config{Mode: ModeRiskClassified, MinRisk: RiskMedium, OnTimeout: OnTimeoutApprove, TimeoutSec: 30, MaxDenials: 3}, ""},
		{"a mode typo", Config{Mode: "risk_classfied"}, `unknown HITL mode "risk_classfied"`},
		{"a min_risk typo", Config{Mode: ModeRiskClassified, MinRisk: "hgih"}, `unknown HITL min_risk "hgih"`},
		{"an on_timeout typo", Config{Mode: ModeAllTools, OnTimeout: "allow"}, `unknown HITL on_timeout "allow"`},
		{"a negative timeout", Config{Mode: ModeAllTools, TimeoutSec: -1}, "must not be negative"},
		{"a negative denial budget", Config{Mode: ModeAllTools, MaxDenials: -2}, "must not be negative"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestHITL_requiresApproval_AsksForAnUnrecognisedMode(t *testing.T) {
	if !(Config{Mode: "bogus"}).requiresApproval("terminal", false, RiskLow) {
		t.Fatal("an unrecognised mode must gate the call, not wave it through")
	}
}
