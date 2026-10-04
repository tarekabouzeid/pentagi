package graph

import (
	"context"
	"fmt"
	"slices"

	"pentagi/pkg/config"
	"pentagi/pkg/database"
	"pentagi/pkg/database/converter"
	"pentagi/pkg/graph/model"
	"pentagi/pkg/hitl"
	"pentagi/pkg/sandbox"
	"pentagi/pkg/sandbox/openshell"
	"pentagi/pkg/tools"
)

// flowFunctions builds the Functions a flow is created with from the optional
// GraphQL HITL and sandbox inputs. Both nil leaves the defaults: no approval
// policy, and the server's default sandbox backend.
func flowFunctions(hitlIn *model.HitlConfigInput, sandboxIn *model.SandboxConfigInput) (*tools.Functions, error) {
	if hitlIn == nil && sandboxIn == nil {
		return nil, nil
	}

	functions := &tools.Functions{}
	if hitlIn != nil {
		cfg, err := hitlConfig(hitlIn)
		if err != nil {
			return nil, err
		}
		functions.HITL = cfg
	}
	if sandboxIn != nil {
		selection := &sandbox.Selection{}
		if sandboxIn.Backend != nil {
			selection.Backend = sandbox.Kind(*sandboxIn.Backend)
		}
		if sandboxIn.Profile != nil {
			selection.Profile = *sandboxIn.Profile
		}
		functions.Sandbox = selection
	}

	return functions, nil
}

// sandboxSettings tells the UI which sandbox backends this server runs and the
// policy presets the OpenShell backend offers.
func sandboxSettings(cfg *config.Config) *model.SandboxSettings {
	backends := []string{string(sandbox.KindDocker)}
	presets := []string{}
	if cfg.OpenShellEnabled {
		backends = append(backends, string(sandbox.KindOpenShell))
		presets = openshell.Presets()
		slices.Sort(presets)
	}

	def := cfg.ExecutorBackend
	if def == "" {
		def = string(sandbox.KindDocker)
	}

	return &model.SandboxSettings{Backends: backends, DefaultBackend: def, OpenshellPresets: presets}
}

func hitlConfig(in *model.HitlConfigInput) (*hitl.Config, error) {
	mode := hitl.Mode(in.Mode)
	if !mode.Valid() {
		return nil, fmt.Errorf("unknown HITL mode %q", in.Mode)
	}

	cfg := hitl.Config{Mode: mode, Tools: in.Tools}
	if in.MinRisk != nil {
		cfg.MinRisk = hitl.RiskClass(*in.MinRisk)
	}
	if in.TimeoutSeconds != nil {
		cfg.TimeoutSec = *in.TimeoutSeconds
	}
	if in.OnTimeout != nil {
		onTimeout := hitl.OnTimeout(*in.OnTimeout)
		if onTimeout != hitl.OnTimeoutDeny && onTimeout != hitl.OnTimeoutApprove {
			return nil, fmt.Errorf("on_timeout must be %q or %q", hitl.OnTimeoutDeny, hitl.OnTimeoutApprove)
		}
		cfg.OnTimeout = onTimeout
	}
	if in.AllowEdit != nil {
		cfg.AllowEdit = *in.AllowEdit
	}
	if in.MaxDenials != nil {
		cfg.MaxDenials = *in.MaxDenials
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// convertToolApprovalChannel adapts the hub's database-row channel to the
// GraphQL model the subscription serves, closing when the source does.
func convertToolApprovalChannel(ctx context.Context, source <-chan database.ToolApproval) <-chan *model.ToolApproval {
	out := make(chan *model.ToolApproval)
	go func() {
		defer close(out)
		for {
			select {
			case row, ok := <-source:
				if !ok {
					return
				}
				select {
				case out <- converter.ConvertToolApproval(row):
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
