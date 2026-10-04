package hitl

import "testing"

func TestHITL_requiresApproval_FollowsTheMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		tool string
		risk RiskClass
		want bool
	}{
		{"off never asks", Config{Mode: ModeOff}, "terminal", RiskHigh, false},
		{"off still asks for a blocked call", Config{Mode: ModeOff}, "terminal", RiskBlocked, true},
		{"all_tools asks for a low call", Config{Mode: ModeAllTools}, "file", RiskLow, true},
		{"risk_classified asks at the threshold", Config{Mode: ModeRiskClassified, MinRisk: RiskMedium}, "terminal", RiskMedium, true},
		{"risk_classified skips below the threshold", Config{Mode: ModeRiskClassified, MinRisk: RiskHigh}, "terminal", RiskMedium, false},
		{"the default threshold is high", Config{Mode: ModeRiskClassified}, "terminal", RiskMedium, false},
		{"the default threshold asks at high", Config{Mode: ModeRiskClassified}, "terminal", RiskHigh, true},
		{"an explicit tool list gates only its tools", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "terminal", RiskLow, true},
		{"an explicit tool list skips other tools", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "file", RiskHigh, false},
		{"an explicit tool list still catches a blocked call", Config{Mode: ModeRiskClassified, Tools: []string{"terminal"}}, "file", RiskBlocked, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.requiresApproval(tc.tool, tc.risk); got != tc.want {
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
