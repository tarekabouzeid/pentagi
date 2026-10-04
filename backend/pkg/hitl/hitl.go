// Package hitl gates an agent's tool calls behind human approval. A flow's
// Config decides which calls need a decision; the classifier scores a call's
// risk; the Dispatcher persists the request, tells the operator, and blocks
// the agent until the operator decides or the request times out.
package hitl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"pentagi/pkg/database"
)

type Mode string

const (
	// ModeOff lets every tool call run without approval.
	ModeOff Mode = "off"
	// ModeRiskClassified asks only for calls at or above the configured risk.
	ModeRiskClassified Mode = "risk_classified"
	// ModeAllTools asks for every tool call that touches the sandbox.
	ModeAllTools Mode = "all_tools"
)

func (m Mode) Valid() bool {
	switch m {
	case ModeOff, ModeRiskClassified, ModeAllTools:
		return true
	default:
		return false
	}
}

type RiskClass string

const (
	RiskLow     RiskClass = "low"
	RiskMedium  RiskClass = "medium"
	RiskHigh    RiskClass = "high"
	RiskBlocked RiskClass = "blocked"
)

// severity orders the classes so MinRisk can be a threshold.
var severity = map[RiskClass]int{RiskLow: 0, RiskMedium: 1, RiskHigh: 2, RiskBlocked: 3}

func (r RiskClass) atLeast(min RiskClass) bool { return severity[r] >= severity[min] }

type Decision string

const (
	DecisionPending   Decision = "pending"
	DecisionApproved  Decision = "approved"
	DecisionEdited    Decision = "edited"
	DecisionDenied    Decision = "denied"
	DecisionTimeout   Decision = "timeout"
	DecisionCancelled Decision = "cancelled"
)

type OnTimeout string

const (
	OnTimeoutDeny    OnTimeout = "deny"
	OnTimeoutApprove OnTimeout = "approve"
)

// Config is a flow's HITL policy, persisted under "hitl" in the flow's
// functions. The zero value is ModeOff, so a flow stored without a policy runs
// unattended exactly as before this package existed.
type Config struct {
	Mode       Mode      `form:"mode,omitempty" json:"mode,omitempty" validate:"omitempty"`
	MinRisk    RiskClass `form:"min_risk,omitempty" json:"min_risk,omitempty" validate:"omitempty"`
	Tools      []string  `form:"tools,omitempty" json:"tools,omitempty" validate:"omitempty"`
	TimeoutSec int       `form:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty" validate:"omitempty"`
	OnTimeout  OnTimeout `form:"on_timeout,omitempty" json:"on_timeout,omitempty" validate:"omitempty"`
	AllowEdit  bool      `form:"allow_edit,omitempty" json:"allow_edit,omitempty" validate:"omitempty"`
	MaxDenials int       `form:"max_denials,omitempty" json:"max_denials,omitempty" validate:"omitempty"`
}

// Normalized fills in the defaults the dispatcher relies on, leaving the
// stored config untouched.
func (c Config) Normalized() Config {
	if c.Mode == "" {
		c.Mode = ModeOff
	}
	if c.MinRisk == "" {
		c.MinRisk = RiskHigh
	}
	if c.OnTimeout == "" {
		c.OnTimeout = OnTimeoutDeny
	}
	return c
}

// Enabled reports whether the policy ever asks for a decision.
func (c Config) Enabled() bool { return c.Normalized().Mode != ModeOff }

// requiresApproval decides whether a call of toolName at the given risk needs a
// decision. An explicit Tools list, when set, is the whole rule in
// risk_classified mode: only those tools are gated. A blocked call is always
// gated, whatever the mode, so the operator can see and refuse it.
func (c Config) requiresApproval(toolName string, risk RiskClass) bool {
	c = c.Normalized()
	if risk == RiskBlocked {
		return true
	}
	switch c.Mode {
	case ModeOff:
		return false
	case ModeAllTools:
		return true
	case ModeRiskClassified:
		if len(c.Tools) > 0 {
			for _, t := range c.Tools {
				if t == toolName {
					return true
				}
			}
			return false
		}
		return risk.atLeast(c.MinRisk)
	default:
		return false
	}
}

// ConfigFromFunctions reads the "hitl" key of a flow's stored functions
// without depending on the rest of their schema.
func ConfigFromFunctions(raw []byte) (Config, error) {
	if len(raw) == 0 {
		return Config{}, nil
	}

	var functions struct {
		HITL *Config `json:"hitl"`
	}
	if err := json.Unmarshal(raw, &functions); err != nil {
		return Config{}, fmt.Errorf("failed to read the hitl policy of the flow functions: %w", err)
	}
	if functions.HITL == nil {
		return Config{}, nil
	}

	return *functions.HITL, nil
}

// Request is a single tool call put to the operator.
type Request struct {
	FlowID      int64
	TaskID      *int64
	SubtaskID   *int64
	AssistantID *int64
	Agent       database.MsgchainType
	ToolCallID  string
	ToolName    string
	// IsEnvironment is true for a tool that runs in the sandbox (terminal,
	// file); the classifier scores only those on their arguments.
	IsEnvironment bool
	Args          json.RawMessage
}

// Resolution is what the gate returns for a call that was allowed to proceed.
// Args is the arguments to run: the original, or the operator's edit.
type Resolution struct {
	Decision Decision
	Args     json.RawMessage
}

var (
	// ErrDenied, ErrTimeout and ErrPaused are the ways a call is refused. The
	// caller turns them into a tool result the agent can read and re-plan
	// around, rather than failing the chain.
	ErrDenied  = errors.New("tool call denied by operator")
	ErrTimeout = errors.New("tool call approval timed out")
	ErrPaused  = errors.New("flow paused after too many denials")
)

// Gate is what the agent runtime calls before executing a tool call.
type Gate interface {
	// Evaluate returns the arguments to run with, or one of ErrDenied,
	// ErrTimeout or ErrPaused. It blocks until the operator decides, the
	// request times out, or ctx is done.
	Evaluate(ctx context.Context, req *Request) (*Resolution, error)
}

// NopGate allows every call; it stands in where a flow has no policy.
type NopGate struct{}

func (NopGate) Evaluate(_ context.Context, req *Request) (*Resolution, error) {
	return &Resolution{Decision: DecisionApproved, Args: req.Args}, nil
}
