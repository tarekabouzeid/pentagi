package controller

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
	"pentagi/pkg/graph/subscriptions"
	"pentagi/pkg/hitl"
)

type hitlPublisher struct {
	subs subscriptions.SubscriptionsController
}

func NewHITLPublisher(subs subscriptions.SubscriptionsController) hitl.Publisher {
	return &hitlPublisher{subs: subs}
}

func (p *hitlPublisher) ToolApprovalRequested(ctx context.Context, approval database.ToolApproval) {
	p.subs.NewFlowPublisher(0, approval.FlowID).ToolApprovalRequested(ctx, approval)
}

func (p *hitlPublisher) ToolApprovalUpdated(ctx context.Context, approval database.ToolApproval) {
	p.subs.NewFlowPublisher(0, approval.FlowID).ToolApprovalUpdated(ctx, approval)
}

// PauseFlow sets the flow to waiting, the status the denial-budget guard pauses into.
func (fc *flowController) PauseFlow(ctx context.Context, flowID int64, reason string) error {
	fw, err := fc.GetFlow(ctx, flowID)
	if err != nil {
		return fmt.Errorf("failed to get flow %d to pause it: %w", flowID, err)
	}
	if err := fw.SetStatus(ctx, database.FlowStatusWaiting); err != nil {
		return fmt.Errorf("failed to pause flow %d: %w", flowID, err)
	}
	return nil
}
