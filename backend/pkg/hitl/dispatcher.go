package hitl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"pentagi/pkg/database"

	"github.com/sirupsen/logrus"
	"github.com/sqlc-dev/pqtype"
)

type Store interface {
	CreateToolApproval(ctx context.Context, arg database.CreateToolApprovalParams) (database.ToolApproval, error)
	DecideToolApproval(ctx context.Context, arg database.DecideToolApprovalParams) (database.ToolApproval, error)
	GetToolApproval(ctx context.Context, id int64) (database.ToolApproval, error)
	GetFlowToolApprovals(ctx context.Context, flowID int64) ([]database.ToolApproval, error)
	GetFlowPendingToolApprovals(ctx context.Context, flowID int64) ([]database.ToolApproval, error)
	CancelFlowPendingToolApprovals(ctx context.Context, arg database.CancelFlowPendingToolApprovalsParams) ([]database.ToolApproval, error)
	CancelPendingToolApprovals(ctx context.Context, reason string) ([]database.ToolApproval, error)
	CountFlowTrailingDenials(ctx context.Context, flowID int64) (int64, error)
}

type Publisher interface {
	ToolApprovalRequested(ctx context.Context, approval database.ToolApproval)
	ToolApprovalUpdated(ctx context.Context, approval database.ToolApproval)
}

// FlowPauser pauses a flow once its denial budget is exhausted; called at most once per flow before ErrPaused.
type FlowPauser interface {
	PauseFlow(ctx context.Context, flowID int64, reason string) error
}

type Dispatcher struct {
	store  Store
	pub    Publisher
	logger *logrus.Entry

	mx      sync.Mutex
	waiters map[int64]waiter
	pauser  FlowPauser
}

// waiter carries the flow policy's edit rule so a decision is validated before it is recorded.
type waiter struct {
	ch        chan database.ToolApproval
	allowEdit bool
}

func NewDispatcher(store Store, pub Publisher) *Dispatcher {
	return &Dispatcher{
		store:   store,
		pub:     pub,
		logger:  logrus.WithField("component", "hitl"),
		waiters: make(map[int64]waiter),
	}
}

// SetPauser must be called once at startup, before any flow runs.
func (d *Dispatcher) SetPauser(p FlowPauser) { d.pauser = p }

// GateFor returns nil when the flow's policy never asks for a decision.
func (d *Dispatcher) GateFor(flowID int64, cfg Config) Gate {
	if !cfg.Enabled() {
		return nil
	}
	return &flowGate{dispatcher: d, flowID: flowID, cfg: cfg.Normalized()}
}

// Decide is the single entry point for the REST and GraphQL handlers.
func (d *Dispatcher) Decide(
	ctx context.Context, approvalID int64, decision Decision, editedArgs json.RawMessage, reason string, decidedBy int64,
) (database.ToolApproval, error) {
	switch decision {
	case DecisionApproved, DecisionDenied, DecisionEdited:
	default:
		return database.ToolApproval{}, fmt.Errorf("an operator decision must be approved, denied or edited, not %q", decision)
	}

	if decision == DecisionEdited {
		d.mx.Lock()
		w, waiting := d.waiters[approvalID]
		d.mx.Unlock()
		if waiting && !w.allowEdit {
			return database.ToolApproval{}, errors.New("this flow's policy does not allow edited arguments")
		}
	}

	params := database.DecideToolApprovalParams{
		ID:        approvalID,
		Decision:  database.ToolApprovalDecision(decision),
		Reason:    reason,
		DecidedBy: database.Int64ToNullInt64(&decidedBy),
	}
	if decision == DecisionEdited {
		if len(editedArgs) == 0 || !json.Valid(editedArgs) {
			return database.ToolApproval{}, errors.New("an edited decision needs valid replacement arguments")
		}
		params.EditedArgs = pqtype.NullRawMessage{RawMessage: editedArgs, Valid: true}
	}

	updated, err := d.store.DecideToolApproval(ctx, params)
	if err != nil {
		return database.ToolApproval{}, fmt.Errorf("failed to record the decision on approval %d: %w", approvalID, err)
	}

	d.pub.ToolApprovalUpdated(context.WithoutCancel(ctx), updated)
	d.wake(updated)

	return updated, nil
}

func (d *Dispatcher) wake(approval database.ToolApproval) {
	d.mx.Lock()
	w, ok := d.waiters[approval.ID]
	if ok {
		delete(d.waiters, approval.ID)
	}
	d.mx.Unlock()
	if ok {
		w.ch <- approval
	}
}

func (d *Dispatcher) register(id int64, allowEdit bool) chan database.ToolApproval {
	ch := make(chan database.ToolApproval, 1)
	d.mx.Lock()
	d.waiters[id] = waiter{ch: ch, allowEdit: allowEdit}
	d.mx.Unlock()
	return ch
}

func (d *Dispatcher) forget(id int64) {
	d.mx.Lock()
	delete(d.waiters, id)
	d.mx.Unlock()
}

// CancelOrphaned closes requests left pending by a previous process; their agents died with it, so a restored flow asks again if it still needs the call.
func (d *Dispatcher) CancelOrphaned(ctx context.Context) error {
	cancelled, err := d.store.CancelPendingToolApprovals(ctx, "the server restarted while this request was waiting")
	if err != nil {
		return fmt.Errorf("failed to cancel orphaned approvals: %w", err)
	}
	for _, approval := range cancelled {
		d.pub.ToolApprovalUpdated(ctx, approval)
	}
	if len(cancelled) > 0 {
		d.logger.WithField("count", len(cancelled)).Info("cancelled tool approvals orphaned by a restart")
	}
	return nil
}

func (d *Dispatcher) CancelFlow(ctx context.Context, flowID int64, reason string) error {
	cancelled, err := d.store.CancelFlowPendingToolApprovals(ctx, database.CancelFlowPendingToolApprovalsParams{
		FlowID: flowID,
		Reason: reason,
	})
	if err != nil {
		return fmt.Errorf("failed to cancel pending approvals of flow %d: %w", flowID, err)
	}
	for _, approval := range cancelled {
		d.pub.ToolApprovalUpdated(context.WithoutCancel(ctx), approval)
		d.wake(approval)
	}
	return nil
}

func (d *Dispatcher) ListFlow(ctx context.Context, flowID int64) ([]database.ToolApproval, error) {
	return d.store.GetFlowToolApprovals(ctx, flowID)
}

func (d *Dispatcher) Approval(ctx context.Context, id int64) (database.ToolApproval, error) {
	return d.store.GetToolApproval(ctx, id)
}

func (d *Dispatcher) evaluate(ctx context.Context, flowID int64, cfg Config, req *Request) (*Resolution, error) {
	isEnv := req.IsEnvironment
	class := Classify(req.ToolName, isEnv, req.Args)
	if !cfg.requiresApproval(req.ToolName, isEnv, class.Risk) {
		return &Resolution{Decision: DecisionApproved, Args: req.Args}, nil
	}

	created, err := d.store.CreateToolApproval(ctx, database.CreateToolApprovalParams{
		FlowID:      flowID,
		TaskID:      database.Int64ToNullInt64(req.TaskID),
		SubtaskID:   database.Int64ToNullInt64(req.SubtaskID),
		AssistantID: database.Int64ToNullInt64(req.AssistantID),
		Agent:       req.Agent,
		ToolCallID:  req.ToolCallID,
		ToolName:    req.ToolName,
		Args:        req.Args,
		RiskClass:   database.ToolRiskClass(class.Risk),
		RiskReason:  class.Reason,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to record the approval request: %w", err)
	}

	ch := d.register(created.ID, cfg.AllowEdit)
	d.pub.ToolApprovalRequested(context.WithoutCancel(ctx), created)

	decided, err := d.await(ctx, cfg, created.ID, ch)
	if err != nil {
		return nil, err
	}

	return d.resolve(ctx, flowID, cfg, decided)
}

func (d *Dispatcher) await(
	ctx context.Context, cfg Config, approvalID int64, ch chan database.ToolApproval,
) (database.ToolApproval, error) {
	var timeout <-chan time.Time
	if cfg.TimeoutSec > 0 {
		t := time.NewTimer(time.Duration(cfg.TimeoutSec) * time.Second)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case decided := <-ch:
		return decided, nil
	case <-timeout:
		d.forget(approvalID)
		return d.onTimeout(ctx, cfg, approvalID)
	case <-ctx.Done():
		d.forget(approvalID)
		d.cancelAbandoned(ctx, approvalID)
		return database.ToolApproval{}, ctx.Err()
	}
}

// cancelAbandoned closes a request whose agent was cancelled so the operator does not decide a dead request.
func (d *Dispatcher) cancelAbandoned(ctx context.Context, approvalID int64) {
	persistCtx := context.WithoutCancel(ctx)
	updated, err := d.store.DecideToolApproval(persistCtx, database.DecideToolApprovalParams{
		ID:       approvalID,
		Decision: database.ToolApprovalDecisionCancelled,
		Reason:   "the agent stopped waiting for this request",
	})
	if err != nil {
		// Already decided, or the store is down; nothing more to close.
		return
	}
	d.pub.ToolApprovalUpdated(persistCtx, updated)
}

func (d *Dispatcher) onTimeout(ctx context.Context, cfg Config, approvalID int64) (database.ToolApproval, error) {
	reason := "approval timed out"
	updated, err := d.store.DecideToolApproval(context.WithoutCancel(ctx), database.DecideToolApprovalParams{
		ID:       approvalID,
		Decision: database.ToolApprovalDecisionTimeout,
		Reason:   reason,
	})
	if err != nil {
		// The row may have been decided between the timer firing and this write.
		if existing, getErr := d.store.GetToolApproval(context.WithoutCancel(ctx), approvalID); getErr == nil {
			return existing, nil
		}
		return database.ToolApproval{}, fmt.Errorf("failed to time out approval %d: %w", approvalID, err)
	}
	d.pub.ToolApprovalUpdated(context.WithoutCancel(ctx), updated)
	return updated, nil
}

func (d *Dispatcher) resolve(ctx context.Context, flowID int64, cfg Config, decided database.ToolApproval) (*Resolution, error) {
	switch decided.Decision {
	case database.ToolApprovalDecisionApproved:
		return &Resolution{Decision: DecisionApproved, Args: decided.Args}, nil
	case database.ToolApprovalDecisionEdited:
		args := decided.Args
		if cfg.AllowEdit && decided.EditedArgs.Valid {
			args = decided.EditedArgs.RawMessage
		}
		return &Resolution{Decision: DecisionEdited, Args: args}, nil
	case database.ToolApprovalDecisionTimeout:
		if cfg.Normalized().OnTimeout == OnTimeoutApprove {
			return &Resolution{Decision: DecisionApproved, Args: decided.Args}, nil
		}
		return nil, ErrTimeout
	case database.ToolApprovalDecisionCancelled:
		return nil, ErrDenied
	default: // denied
		if d.deniedPastBudget(ctx, flowID, cfg) {
			return nil, ErrPaused
		}
		return nil, ErrDenied
	}
}

func (d *Dispatcher) deniedPastBudget(ctx context.Context, flowID int64, cfg Config) bool {
	if cfg.MaxDenials <= 0 || d.pauser == nil {
		return false
	}
	streak, err := d.store.CountFlowTrailingDenials(context.WithoutCancel(ctx), flowID)
	if err != nil {
		d.logger.WithError(err).WithField("flow_id", flowID).Warn("failed to count denials; not pausing the flow")
		return false
	}
	if streak < int64(cfg.MaxDenials) {
		return false
	}
	reason := fmt.Sprintf("flow paused after %d consecutive denials", streak)
	if err := d.pauser.PauseFlow(context.WithoutCancel(ctx), flowID, reason); err != nil {
		d.logger.WithError(err).WithField("flow_id", flowID).Warn("failed to pause the flow after its denial budget")
	}
	return true
}

type flowGate struct {
	dispatcher *Dispatcher
	flowID     int64
	cfg        Config
}

func (g *flowGate) Evaluate(ctx context.Context, req *Request) (*Resolution, error) {
	return g.dispatcher.evaluate(ctx, g.flowID, g.cfg, req)
}
