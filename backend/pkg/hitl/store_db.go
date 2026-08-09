package hitl

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"pentagi/pkg/database"
)

// DBStore implements the Store interface using the database layer.
type DBStore struct {
	db database.Querier
}

// NewDBStore creates a new database-backed Store.
func NewDBStore(db database.Querier) *DBStore {
	return &DBStore{db: db}
}

// CreateApproval persists a new pending approval request and returns its ID.
func (s *DBStore) CreateApproval(ctx context.Context, req *ApprovalRequest) (int64, error) {
	var taskID sql.NullInt64
	if req.TaskID != nil {
		taskID = sql.NullInt64{Int64: *req.TaskID, Valid: true}
	}

	args := req.Args
	if args == nil {
		args = json.RawMessage("{}")
	}

	row, err := s.db.CreateToolApproval(ctx, database.CreateToolApprovalParams{
		FlowID:     req.FlowID,
		TaskID:     taskID,
		ToolCallID: req.ToolCallID,
		ToolName:   req.ToolName,
		Args:       args,
		RiskClass:  database.RiskClass(req.RiskClass),
	})
	if err != nil {
		return 0, err
	}

	return row.ID, nil
}

// UpdateApproval persists the operator's decision on an existing approval.
func (s *DBStore) UpdateApproval(ctx context.Context, id int64, resp *ApprovalResponse) error {
	var reason sql.NullString
	if resp.Reason != "" {
		reason = sql.NullString{String: resp.Reason, Valid: true}
	}

	var decidedBy sql.NullInt64
	if resp.DecidedBy > 0 {
		decidedBy = sql.NullInt64{Int64: resp.DecidedBy, Valid: true}
	}

	editedArgs := database.NullRawMessage{RawMessage: resp.EditedArgs, Valid: len(resp.EditedArgs) > 0}

	_, err := s.db.UpdateToolApprovalDecision(ctx, database.UpdateToolApprovalDecisionParams{
		Decision:   database.ToolApprovalDecision(resp.Decision),
		EditedArgs: editedArgs,
		Reason:     reason,
		DecidedBy:  decidedBy,
		ID:         id,
	})
	return err
}

// GetPendingApprovals returns all pending approvals for a flow.
func (s *DBStore) GetPendingApprovals(ctx context.Context, flowID int64) ([]*ApprovalRequest, error) {
	rows, err := s.db.GetPendingToolApprovals(ctx, flowID)
	if err != nil {
		return nil, err
	}

	result := make([]*ApprovalRequest, 0, len(rows))
	for _, row := range rows {
		result = append(result, convertRowToApprovalRequest(row))
	}
	return result, nil
}

// GetAllPending returns all pending approvals across all flows (for recovery on startup).
func (s *DBStore) GetAllPending(ctx context.Context) ([]*ApprovalRequest, error) {
	rows, err := s.db.GetAllPendingToolApprovals(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*ApprovalRequest, 0, len(rows))
	for _, row := range rows {
		result = append(result, convertRowToApprovalRequest(row))
	}
	return result, nil
}

// CountConsecutiveDenials returns the number of consecutive denied approvals for a flow.
func (s *DBStore) CountConsecutiveDenials(ctx context.Context, flowID int64) (int64, error) {
	return s.db.CountConsecutiveDenials(ctx, flowID)
}

func convertRowToApprovalRequest(row database.ToolApproval) *ApprovalRequest {
	req := &ApprovalRequest{
		ID:         row.ID,
		FlowID:     row.FlowID,
		ToolCallID: row.ToolCallID,
		ToolName:   row.ToolName,
		Args:       row.Args,
		RiskClass:  RiskClass(row.RiskClass),
		Decision:   Decision(row.Decision),
	}
	if row.EditedArgs.Valid {
		req.EditedArgs = row.EditedArgs.RawMessage
	}

	if row.TaskID.Valid {
		taskID := row.TaskID.Int64
		req.TaskID = &taskID
	}
	if row.Reason.Valid {
		req.Reason = row.Reason.String
	}
	if row.DecidedBy.Valid {
		decidedBy := row.DecidedBy.Int64
		req.DecidedBy = &decidedBy
	}
	req.RequestedAt = row.RequestedAt
	if row.DecidedAt.Valid {
		t := row.DecidedAt.Time
		req.DecidedAt = &t
	} else {
		req.DecidedAt = nil
	}

	// Ensure zero time gets a reasonable default
	if req.RequestedAt.IsZero() {
		req.RequestedAt = time.Now()
	}

	return req
}
