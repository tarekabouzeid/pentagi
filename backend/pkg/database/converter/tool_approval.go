package converter

import (
	"pentagi/pkg/database"
	"pentagi/pkg/graph/model"
)

// ConvertToolApproval converts a database ToolApproval row to a GraphQL model.
func ConvertToolApproval(row database.ToolApproval) *model.ToolApproval {
	ta := &model.ToolApproval{
		ID:         row.ID,
		FlowID:     row.FlowID,
		ToolCallID: row.ToolCallID,
		ToolName:   row.ToolName,
		Args:       string(row.Args),
		RiskClass:  model.RiskClass(row.RiskClass),
		Decision:   string(row.Decision),
	}

	if row.TaskID.Valid {
		taskID := row.TaskID.Int64
		ta.TaskID = &taskID
	}
	if row.EditedArgs != nil {
		s := string(row.EditedArgs)
		ta.EditedArgs = &s
	}
	if row.Reason.Valid {
		ta.Reason = &row.Reason.String
	}
	if row.RequestedAt.Valid {
		ta.RequestedAt = row.RequestedAt.Time
	}
	if row.DecidedAt.Valid {
		t := row.DecidedAt.Time
		ta.DecidedAt = &t
	}

	return ta
}
