package database

// ToolApprovalDecision and ToolRiskClass are text columns guarded by CHECK
// constraints rather than PostgreSQL enums, so the migration that creates them
// can run twice without error. sqlc maps the columns onto these types.
type ToolApprovalDecision string

const (
	ToolApprovalDecisionPending   ToolApprovalDecision = "pending"
	ToolApprovalDecisionApproved  ToolApprovalDecision = "approved"
	ToolApprovalDecisionEdited    ToolApprovalDecision = "edited"
	ToolApprovalDecisionDenied    ToolApprovalDecision = "denied"
	ToolApprovalDecisionTimeout   ToolApprovalDecision = "timeout"
	ToolApprovalDecisionCancelled ToolApprovalDecision = "cancelled"
)

type ToolRiskClass string

const (
	ToolRiskClassLow     ToolRiskClass = "low"
	ToolRiskClassMedium  ToolRiskClass = "medium"
	ToolRiskClassHigh    ToolRiskClass = "high"
	ToolRiskClassBlocked ToolRiskClass = "blocked"
)
