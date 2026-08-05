package graph

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
	"pentagi/pkg/database/converter"
	"pentagi/pkg/graph/model"
	"pentagi/pkg/hitl"
)

// DecideToolApproval is the resolver for the decideToolApproval field.
func (r *mutationResolver) DecideToolApproval(ctx context.Context, approvalID int64, decision model.ApprovalDecision, editedArgs *string, reason *string) (*model.ToolApproval, error) {
	_, _, err := validatePermission(ctx, "flows.update")
	if err != nil {
		return nil, err
	}

	resp := &hitl.ApprovalResponse{
		Decision: hitl.Decision(decision),
	}
	if editedArgs != nil {
		resp.EditedArgs = []byte(*editedArgs)
	}
	if reason != nil {
		resp.Reason = *reason
	}

	if err := r.HITL.Submit(ctx, approvalID, resp); err != nil {
		return nil, fmt.Errorf("failed to submit decision: %w", err)
	}

	// Fetch the updated row
	row, err := r.DB.GetToolApproval(ctx, approvalID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch approval: %w", err)
	}

	return converter.ConvertToolApproval(row), nil
}

// PauseFlow is the resolver for the pauseFlow field.
func (r *mutationResolver) PauseFlow(ctx context.Context, flowID int64) (model.ResultType, error) {
	_, _, err := validatePermission(ctx, "flows.update")
	if err != nil {
		return model.ResultTypeError, err
	}

	fw, err := r.Controller.GetFlow(ctx, flowID)
	if err != nil {
		return model.ResultTypeError, fmt.Errorf("flow not found: %w", err)
	}

	if err := fw.SetStatus(ctx, database.FlowStatusWaiting); err != nil {
		return model.ResultTypeError, err
	}

	return model.ResultTypeSuccess, nil
}

// ResumeFlow is the resolver for the resumeFlow field.
func (r *mutationResolver) ResumeFlow(ctx context.Context, flowID int64) (model.ResultType, error) {
	_, _, err := validatePermission(ctx, "flows.update")
	if err != nil {
		return model.ResultTypeError, err
	}

	fw, err := r.Controller.GetFlow(ctx, flowID)
	if err != nil {
		return model.ResultTypeError, fmt.Errorf("flow not found: %w", err)
	}

	if err := fw.SetStatus(ctx, database.FlowStatusRunning); err != nil {
		return model.ResultTypeError, err
	}

	return model.ResultTypeSuccess, nil
}

// InjectCommand is the resolver for the injectCommand field.
func (r *mutationResolver) InjectCommand(ctx context.Context, flowID int64, command string) (model.ResultType, error) {
	_, _, err := validatePermission(ctx, "flows.update")
	if err != nil {
		return model.ResultTypeError, err
	}

	return model.ResultTypeError, fmt.Errorf("command injection is not yet implemented")
}

// ToolApprovals is the resolver for the toolApprovals field.
func (r *queryResolver) ToolApprovals(ctx context.Context, flowID int64) ([]*model.ToolApproval, error) {
	_, _, err := validatePermission(ctx, "flows.view")
	if err != nil {
		return nil, err
	}

	rows, err := r.DB.GetToolApprovalsByFlow(ctx, flowID)
	if err != nil {
		return nil, err
	}

	result := make([]*model.ToolApproval, 0, len(rows))
	for _, row := range rows {
		result = append(result, converter.ConvertToolApproval(row))
	}
	return result, nil
}

// PendingToolApprovals is the resolver for the pendingToolApprovals field.
func (r *queryResolver) PendingToolApprovals(ctx context.Context, flowID int64) ([]*model.ToolApproval, error) {
	_, _, err := validatePermission(ctx, "flows.view")
	if err != nil {
		return nil, err
	}

	rows, err := r.DB.GetPendingToolApprovals(ctx, flowID)
	if err != nil {
		return nil, err
	}

	result := make([]*model.ToolApproval, 0, len(rows))
	for _, row := range rows {
		result = append(result, converter.ConvertToolApproval(row))
	}
	return result, nil
}

// ToolApprovalRequested is the resolver for the toolApprovalRequested field.
func (r *subscriptionResolver) ToolApprovalRequested(ctx context.Context, flowID int64) (<-chan *model.ToolApproval, error) {
	_, _, err := validatePermission(ctx, "flows.subscribe")
	if err != nil {
		return nil, err
	}

	subscriber := r.Subscriptions.NewFlowSubscriber(0, flowID)
	return subscriber.ToolApprovalRequested(ctx)
}

// ToolApprovalUpdated is the resolver for the toolApprovalUpdated field.
func (r *subscriptionResolver) ToolApprovalUpdated(ctx context.Context, flowID int64) (<-chan *model.ToolApproval, error) {
	_, _, err := validatePermission(ctx, "flows.subscribe")
	if err != nil {
		return nil, err
	}

	subscriber := r.Subscriptions.NewFlowSubscriber(0, flowID)
	return subscriber.ToolApprovalUpdated(ctx)
}
