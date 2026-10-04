package converter

import (
	"pentagi/pkg/database"
	"pentagi/pkg/graph/model"
)

// ConvertToolApprovals converts a batch of approval rows for a GraphQL list.
func ConvertToolApprovals(rows []database.ToolApproval) []*model.ToolApproval {
	out := make([]*model.ToolApproval, 0, len(rows))
	for _, row := range rows {
		out = append(out, ConvertToolApproval(row))
	}
	return out
}

// ConvertToolApproval maps a stored approval to its GraphQL shape. The JSONB
// args and edited args are served as strings, matching the REST handler.
func ConvertToolApproval(row database.ToolApproval) *model.ToolApproval {
	approval := &model.ToolApproval{
		ID:          row.ID,
		FlowID:      row.FlowID,
		TaskID:      database.NullInt64ToInt64(row.TaskID),
		SubtaskID:   database.NullInt64ToInt64(row.SubtaskID),
		AssistantID: database.NullInt64ToInt64(row.AssistantID),
		Agent:       model.AgentType(row.Agent),
		ToolCallID:  row.ToolCallID,
		ToolName:    row.ToolName,
		Args:        string(row.Args),
		RiskClass:   model.RiskClass(row.RiskClass),
		RiskReason:  row.RiskReason,
		Status:      model.ToolApprovalStatus(row.Decision),
		Reason:      row.Reason,
		DecidedBy:   database.NullInt64ToInt64(row.DecidedBy),
		RequestedAt: row.CreatedAt,
	}
	if row.EditedArgs.Valid {
		edited := string(row.EditedArgs.RawMessage)
		approval.EditedArgs = &edited
	}
	if row.DecidedAt.Valid {
		decidedAt := row.DecidedAt.Time
		approval.DecidedAt = &decidedAt
	}
	return approval
}
