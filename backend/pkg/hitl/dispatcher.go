package hitl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	obs "pentagi/pkg/observability"
)

var (
	// ErrApprovalDenied is returned when an operator denies a tool call.
	ErrApprovalDenied = errors.New("tool call denied by operator")
	// ErrApprovalTimeout is returned when an approval request times out.
	ErrApprovalTimeout = errors.New("tool call approval timed out")
)

// Store abstracts the persistence layer for approval requests.
type Store interface {
	CreateApproval(ctx context.Context, req *ApprovalRequest) (int64, error)
	UpdateApproval(ctx context.Context, id int64, resp *ApprovalResponse) error
	GetPendingApprovals(ctx context.Context, flowID int64) ([]*ApprovalRequest, error)
	CountConsecutiveDenials(ctx context.Context, flowID int64) (int64, error)
}

// Publisher abstracts the event notification layer.
type Publisher interface {
	ApprovalRequested(ctx context.Context, flowID int64, req *ApprovalRequest)
	ApprovalUpdated(ctx context.Context, flowID int64, req *ApprovalRequest)
}

// pendingEntry holds the channel waiting for a decision.
type pendingEntry struct {
	ch  chan *ApprovalResponse
	req *ApprovalRequest
}

// Dispatcher manages the lifecycle of approval requests.
// It coordinates between the agent loop (which blocks waiting) and the
// REST/GraphQL layer (which submits decisions).
type Dispatcher struct {
	mu       sync.Mutex
	pending  map[int64]*pendingEntry // keyed by approval ID
	store    Store
	pub      Publisher
}

// NewDispatcher creates a new approval dispatcher.
func NewDispatcher(store Store, pub Publisher) *Dispatcher {
	return &Dispatcher{
		pending: make(map[int64]*pendingEntry),
		store:   store,
		pub:     pub,
	}
}

// Request creates an approval request, persists it, notifies subscribers,
// and blocks until a decision arrives or the context/timeout fires.
func (d *Dispatcher) Request(ctx context.Context, cfg Config, req *ApprovalRequest) (*ApprovalResponse, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "hitl.Request")
	defer span.End()

	// Persist the request
	id, err := d.store.CreateApproval(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to persist approval request: %w", err)
	}
	req.ID = id

	// Create the waiting channel
	ch := make(chan *ApprovalResponse, 1)
	d.mu.Lock()
	d.pending[id] = &pendingEntry{ch: ch, req: req}
	d.mu.Unlock()

	// Notify subscribers
	d.pub.ApprovalRequested(ctx, req.FlowID, req)

	// Set up timeout
	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if cfg.ApprovalTimeout > 0 {
		timer = time.NewTimer(time.Duration(cfg.ApprovalTimeout) * time.Second)
		timeoutCh = timer.C
		defer timer.Stop()
	}

	// Block until decision, timeout, or context cancellation
	select {
	case resp := <-ch:
		d.cleanup(id)
		return resp, nil
	case <-timeoutCh:
		d.cleanup(id)
		timeoutResp := &ApprovalResponse{Decision: DecisionTimeout}
		if err := d.store.UpdateApproval(ctx, id, timeoutResp); err != nil {
			// Log but don't fail — the timeout decision stands
			_ = err
		}
		req.Decision = DecisionTimeout
		d.pub.ApprovalUpdated(ctx, req.FlowID, req)

		if cfg.OnTimeout == OnTimeoutApprove {
			return &ApprovalResponse{Decision: DecisionApproved}, nil
		}
		return nil, ErrApprovalTimeout
	case <-ctx.Done():
		d.cleanup(id)
		return nil, ctx.Err()
	}
}

// Submit delivers an operator's decision to a pending approval.
// It returns an error if the approval ID is not found (already decided/expired).
func (d *Dispatcher) Submit(ctx context.Context, approvalID int64, resp *ApprovalResponse) error {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "hitl.Submit")
	defer span.End()

	// Persist the decision
	if err := d.store.UpdateApproval(ctx, approvalID, resp); err != nil {
		return fmt.Errorf("failed to persist approval decision: %w", err)
	}

	d.mu.Lock()
	entry, ok := d.pending[approvalID]
	d.mu.Unlock()

	if !ok {
		// Already resolved (timeout or context cancel) — decision is persisted but no waiter
		return nil
	}

	// Update the request with the decision for the notification
	entry.req.Decision = resp.Decision
	entry.req.EditedArgs = resp.EditedArgs
	entry.req.Reason = resp.Reason
	now := time.Now()
	entry.req.DecidedAt = &now
	if resp.DecidedBy > 0 {
		entry.req.DecidedBy = &resp.DecidedBy
	}

	// Notify subscribers of the update
	d.pub.ApprovalUpdated(ctx, entry.req.FlowID, entry.req)

	// Deliver to the waiting goroutine
	select {
	case entry.ch <- resp:
	default:
		// Channel already has a response (shouldn't happen, but be safe)
	}

	return nil
}

// RecoverPending re-emits notifications for any approvals that are still
// pending in the store. Call this on server startup.
func (d *Dispatcher) RecoverPending(ctx context.Context, flowID int64) error {
	approvals, err := d.store.GetPendingApprovals(ctx, flowID)
	if err != nil {
		return err
	}
	for _, req := range approvals {
		d.pub.ApprovalRequested(ctx, req.FlowID, req)
	}
	return nil
}

func (d *Dispatcher) cleanup(id int64) {
	d.mu.Lock()
	delete(d.pending, id)
	d.mu.Unlock()
}

// ErrFlowPaused is returned when a flow is auto-paused due to too many consecutive denials.
var ErrFlowPaused = errors.New("flow paused: too many consecutive denials")

// FlowGate implements the Gate interface for a specific flow, using the dispatcher.
type FlowGate struct {
	FlowID     int64
	Config     Config
	Dispatcher *Dispatcher
}

// Evaluate checks whether the tool call needs approval and blocks if so.
func (g *FlowGate) Evaluate(ctx context.Context, req *ApprovalRequest) (*ApprovalResponse, error) {
	ctx, span := obs.Observer.NewSpan(ctx, obs.SpanKindInternal, "hitl.Evaluate")
	defer span.End()

	risk := ClassifyRisk(req.ToolName, req.Args)
	req.RiskClass = risk
	req.FlowID = g.FlowID
	req.RequestedAt = time.Now()
	req.Decision = DecisionPending

	if !RequiresApproval(g.Config, req.ToolName, risk) {
		// Auto-approve: no human needed
		return &ApprovalResponse{
			Decision: DecisionApproved,
		}, nil
	}

	// Denial-loop guard: check if consecutive denials exceeded max
	if g.Config.MaxDenials > 0 && g.Dispatcher.store != nil {
		count, err := g.Dispatcher.store.CountConsecutiveDenials(ctx, g.FlowID)
		if err == nil && count >= int64(g.Config.MaxDenials) {
			return nil, fmt.Errorf("%w: %d consecutive denials", ErrFlowPaused, count)
		}
	}

	resp, err := g.Dispatcher.Request(ctx, g.Config, req)
	if err != nil {
		if errors.Is(err, ErrApprovalDenied) || errors.Is(err, ErrApprovalTimeout) {
			return nil, err
		}
		return nil, err
	}

	if resp.Decision == DecisionDenied {
		return nil, fmt.Errorf("%w: %s", ErrApprovalDenied, resp.Reason)
	}

	// For edited decisions, return the edited args
	if resp.Decision == DecisionEdited && len(resp.EditedArgs) > 0 {
		return resp, nil
	}

	return resp, nil
}

// ParseConfig extracts HITL config from the flow's Functions JSON.
// If no HITL block is present, returns the default config.
func ParseConfig(functionsJSON json.RawMessage) Config {
	if len(functionsJSON) == 0 {
		return DefaultConfig()
	}

	var wrapper struct {
		HITL *Config `json:"hitl,omitempty"`
	}
	if err := json.Unmarshal(functionsJSON, &wrapper); err != nil || wrapper.HITL == nil {
		return DefaultConfig()
	}

	cfg := *wrapper.HITL

	// Apply defaults for zero values
	if cfg.Mode == "" {
		cfg.Mode = ModeRiskClassified
	}
	if cfg.MinRisk == "" {
		cfg.MinRisk = RiskMedium
	}
	if cfg.OnTimeout == "" {
		cfg.OnTimeout = OnTimeoutDeny
	}
	if cfg.MaxDenials == 0 {
		cfg.MaxDenials = 3
	}
	if cfg.ExecutorBackend == "" {
		cfg.ExecutorBackend = "docker"
	}

	return cfg
}
