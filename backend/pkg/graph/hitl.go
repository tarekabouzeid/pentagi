package graph

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
	"pentagi/pkg/database/converter"
	"pentagi/pkg/graph/model"
	"pentagi/pkg/hitl"
	"pentagi/pkg/tools"
)

// hitlFunctions turns the optional GraphQL HITL input into the Functions blob
// the flow is created with. A nil input leaves HITL unset, so the flow runs
// unattended.
func hitlFunctions(in *model.HitlConfigInput) (*tools.Functions, error) {
	if in == nil {
		return nil, nil
	}

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

	return &tools.Functions{HITL: &cfg}, nil
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
