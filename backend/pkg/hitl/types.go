// Package hitl implements Human-In-The-Loop approval gates for tool execution.
// It provides risk classification, approval dispatching, and flow-level
// configuration for controlling what agents can execute autonomously.
package hitl

import (
	"context"
	"encoding/json"
	"time"
)

// Mode determines how the HITL gate behaves for a flow.
type Mode string

const (
	// ModePerTool requires approval for every tool call.
	ModePerTool Mode = "per_tool"
	// ModeRiskClassified requires approval only for tool calls classified as medium/high risk.
	ModeRiskClassified Mode = "risk_classified"
	// ModePolicyOnly relies on the sandbox policy; no manual approvals.
	ModePolicyOnly Mode = "policy_only"
)

// RiskClass represents the assessed risk level of a tool call.
type RiskClass string

const (
	RiskLow     RiskClass = "low"
	RiskMedium  RiskClass = "medium"
	RiskHigh    RiskClass = "high"
	RiskBlocked RiskClass = "blocked"
)

// Decision represents the operator's decision on an approval request.
type Decision string

const (
	DecisionPending  Decision = "pending"
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
	DecisionEdited   Decision = "edited"
	DecisionTimeout  Decision = "timeout"
)

// OnTimeout specifies behavior when an approval request times out.
type OnTimeout string

const (
	OnTimeoutDeny    OnTimeout = "deny"
	OnTimeoutApprove OnTimeout = "approve"
)

// Config holds the HITL configuration for a flow.
type Config struct {
	Mode             Mode      `json:"mode"`
	RiskTools        []string  `json:"risk_tools,omitempty"`
	ApprovalTimeout  int       `json:"approval_timeout_seconds,omitempty"` // 0 = no timeout
	OnTimeout        OnTimeout `json:"on_timeout,omitempty"`
	AllowEdit        bool      `json:"allow_edit,omitempty"`
	MaxDenials       int       `json:"max_denials,omitempty"` // consecutive denials before auto-pause
	ExecutorBackend  string    `json:"executor_backend,omitempty"`
}

// DefaultConfig returns the default HITL configuration.
func DefaultConfig() Config {
	return Config{
		Mode:            ModeRiskClassified,
		ApprovalTimeout: 300, // 5 minutes
		OnTimeout:       OnTimeoutDeny,
		AllowEdit:       true,
		MaxDenials:      3,
		ExecutorBackend: "docker",
	}
}

// ApprovalRequest represents a pending approval for a tool call.
type ApprovalRequest struct {
	ID          int64           `json:"id"`
	FlowID      int64           `json:"flow_id"`
	TaskID      *int64          `json:"task_id,omitempty"`
	ToolCallID  string          `json:"tool_call_id"`
	ToolName    string          `json:"tool_name"`
	Args        json.RawMessage `json:"args"`
	RiskClass   RiskClass       `json:"risk_class"`
	Decision    Decision        `json:"decision"`
	EditedArgs  json.RawMessage `json:"edited_args,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	DecidedBy   *int64          `json:"decided_by,omitempty"`
	RequestedAt time.Time       `json:"requested_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
}

// ApprovalResponse is sent back to the dispatcher after an operator decides.
type ApprovalResponse struct {
	Decision   Decision        `json:"decision"`
	EditedArgs json.RawMessage `json:"edited_args,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	DecidedBy  int64           `json:"decided_by,omitempty"`
}

// RequiresApproval determines whether a tool call needs human approval
// given the flow's HITL config and the assessed risk class.
func RequiresApproval(cfg Config, toolName string, risk RiskClass) bool {
	switch cfg.Mode {
	case ModePolicyOnly:
		return false
	case ModePerTool:
		return true
	case ModeRiskClassified:
		// If explicit risk_tools list is set, only those tools require approval
		if len(cfg.RiskTools) > 0 {
			for _, t := range cfg.RiskTools {
				if t == toolName {
					return true
				}
			}
			return false
		}
		// Otherwise, medium and above require approval
		return risk == RiskMedium || risk == RiskHigh || risk == RiskBlocked
	default:
		return false
	}
}

// Gate is the interface that the performer uses to check and wait for approvals.
type Gate interface {
	// Evaluate checks whether a tool call requires approval and, if so,
	// blocks until a decision is made or the context is cancelled.
	// Returns the final args to use (may be edited) and an error if denied/timeout.
	Evaluate(ctx context.Context, req *ApprovalRequest) (*ApprovalResponse, error)
}
