package hitl

import (
	"context"

	"pentagi/pkg/graph/model"
	"pentagi/pkg/graph/subscriptions"
)

// SubscriptionPublisher adapts the subscriptions system to the hitl.Publisher interface.
type SubscriptionPublisher struct {
	subs subscriptions.SubscriptionsController
}

// NewSubscriptionPublisher creates a publisher that sends approval events to GraphQL subscriptions.
func NewSubscriptionPublisher(subs subscriptions.SubscriptionsController) *SubscriptionPublisher {
	return &SubscriptionPublisher{subs: subs}
}

// ApprovalRequested notifies subscribers that a new approval is pending.
func (p *SubscriptionPublisher) ApprovalRequested(ctx context.Context, flowID int64, req *ApprovalRequest) {
	pub := p.subs.NewFlowPublisher(0, flowID)
	pub.ToolApprovalRequested(ctx, convertToModel(req))
}

// ApprovalUpdated notifies subscribers that an approval decision was made.
func (p *SubscriptionPublisher) ApprovalUpdated(ctx context.Context, flowID int64, req *ApprovalRequest) {
	pub := p.subs.NewFlowPublisher(0, flowID)
	pub.ToolApprovalUpdated(ctx, convertToModel(req))
}

func convertToModel(req *ApprovalRequest) *model.ToolApproval {
	ta := &model.ToolApproval{
		ID:          req.ID,
		FlowID:      req.FlowID,
		ToolCallID:  req.ToolCallID,
		ToolName:    req.ToolName,
		Args:        string(req.Args),
		RiskClass:   model.RiskClass(req.RiskClass),
		Decision:    string(req.Decision),
		RequestedAt: req.RequestedAt,
	}

	if req.TaskID != nil {
		ta.TaskID = req.TaskID
	}
	if req.EditedArgs != nil {
		s := string(req.EditedArgs)
		ta.EditedArgs = &s
	}
	if req.Reason != "" {
		ta.Reason = &req.Reason
	}
	if req.DecidedAt != nil {
		ta.DecidedAt = req.DecidedAt
	}

	return ta
}
