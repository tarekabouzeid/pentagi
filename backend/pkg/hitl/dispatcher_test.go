package hitl

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"pentagi/pkg/database"
)

// memStore is an in-memory Store that mirrors the one invariant the dispatcher
// relies on: a decision lands only while a row is pending.
type memStore struct {
	mx        sync.Mutex
	rows      map[int64]*database.ToolApproval
	nextID    int64
	createErr error
}

func newMemStore() *memStore { return &memStore{rows: map[int64]*database.ToolApproval{}} }

func (m *memStore) CreateToolApproval(ctx context.Context, arg database.CreateToolApprovalParams) (database.ToolApproval, error) {
	if err := ctx.Err(); err != nil {
		return database.ToolApproval{}, err
	}
	m.mx.Lock()
	defer m.mx.Unlock()
	if m.createErr != nil {
		return database.ToolApproval{}, m.createErr
	}
	m.nextID++
	row := database.ToolApproval{
		ID: m.nextID, FlowID: arg.FlowID, Agent: arg.Agent, ToolCallID: arg.ToolCallID,
		ToolName: arg.ToolName, Args: arg.Args, RiskClass: arg.RiskClass, RiskReason: arg.RiskReason,
		Decision: database.ToolApprovalDecisionPending,
	}
	m.rows[row.ID] = &row
	return row, nil
}

func (m *memStore) DecideToolApproval(ctx context.Context, arg database.DecideToolApprovalParams) (database.ToolApproval, error) {
	m.mx.Lock()
	defer m.mx.Unlock()
	row, ok := m.rows[arg.ID]
	if !ok || row.Decision != database.ToolApprovalDecisionPending {
		return database.ToolApproval{}, errNoPending
	}
	row.Decision = arg.Decision
	row.EditedArgs = arg.EditedArgs
	row.Reason = arg.Reason
	row.DecidedBy = arg.DecidedBy
	row.DecidedAt = sqlNow()
	return *row, nil
}

func (m *memStore) GetToolApproval(ctx context.Context, id int64) (database.ToolApproval, error) {
	m.mx.Lock()
	defer m.mx.Unlock()
	if row, ok := m.rows[id]; ok {
		return *row, nil
	}
	return database.ToolApproval{}, errNoPending
}

func (m *memStore) GetFlowToolApprovals(ctx context.Context, flowID int64) ([]database.ToolApproval, error) {
	return m.filter(func(r *database.ToolApproval) bool { return r.FlowID == flowID }), nil
}

func (m *memStore) GetFlowPendingToolApprovals(ctx context.Context, flowID int64) ([]database.ToolApproval, error) {
	return m.filter(func(r *database.ToolApproval) bool {
		return r.FlowID == flowID && r.Decision == database.ToolApprovalDecisionPending
	}), nil
}

func (m *memStore) CancelPendingToolApprovals(ctx context.Context, reason string) ([]database.ToolApproval, error) {
	m.mx.Lock()
	defer m.mx.Unlock()
	var out []database.ToolApproval
	for _, r := range m.rows {
		if r.Decision == database.ToolApprovalDecisionPending {
			r.Decision = database.ToolApprovalDecisionCancelled
			r.Reason = reason
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *memStore) CancelFlowPendingToolApprovals(ctx context.Context, arg database.CancelFlowPendingToolApprovalsParams) ([]database.ToolApproval, error) {
	m.mx.Lock()
	defer m.mx.Unlock()
	var out []database.ToolApproval
	for _, r := range m.rows {
		if r.FlowID == arg.FlowID && r.Decision == database.ToolApprovalDecisionPending {
			r.Decision = database.ToolApprovalDecisionCancelled
			r.Reason = arg.Reason
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *memStore) CountFlowTrailingDenials(ctx context.Context, flowID int64) (int64, error) {
	m.mx.Lock()
	defer m.mx.Unlock()
	var lastGrant int64
	for id, r := range m.rows {
		if r.FlowID != flowID {
			continue
		}
		if r.Decision == database.ToolApprovalDecisionApproved || r.Decision == database.ToolApprovalDecisionEdited {
			if id > lastGrant {
				lastGrant = id
			}
		}
	}
	var n int64
	for id, r := range m.rows {
		if r.FlowID == flowID && r.Decision == database.ToolApprovalDecisionDenied && id > lastGrant {
			n++
		}
	}
	return n, nil
}

func (m *memStore) filter(keep func(*database.ToolApproval) bool) []database.ToolApproval {
	m.mx.Lock()
	defer m.mx.Unlock()
	var out []database.ToolApproval
	for _, r := range m.rows {
		if keep(r) {
			out = append(out, *r)
		}
	}
	return out
}

var errNoPending = errors.New("no pending approval")

func sqlNow() sql.NullTime { return sql.NullTime{Time: time.Now(), Valid: true} }

type capturePublisher struct {
	mx        sync.Mutex
	requested []database.ToolApproval
	updated   []database.ToolApproval
}

func (c *capturePublisher) ToolApprovalRequested(_ context.Context, a database.ToolApproval) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.requested = append(c.requested, a)
}

func (c *capturePublisher) ToolApprovalUpdated(_ context.Context, a database.ToolApproval) {
	c.mx.Lock()
	defer c.mx.Unlock()
	c.updated = append(c.updated, a)
}

type recordingPauser struct {
	mx     sync.Mutex
	paused []int64
}

func (p *recordingPauser) PauseFlow(_ context.Context, flowID int64, _ string) error {
	p.mx.Lock()
	defer p.mx.Unlock()
	p.paused = append(p.paused, flowID)
	return nil
}

const testFlowID = int64(7)

func newDispatcher(t *testing.T) (*Dispatcher, *memStore, *capturePublisher) {
	t.Helper()
	store := newMemStore()
	pub := &capturePublisher{}
	return NewDispatcher(store, pub), store, pub
}

func req(tool string, args string) *Request {
	return &Request{
		FlowID: testFlowID, Agent: database.MsgchainTypePentester,
		ToolCallID: "call-1", ToolName: tool, IsEnvironment: true, Args: json.RawMessage(args),
	}
}

func TestDispatcher_Evaluate_RunsAnUngatedCallWithoutAsking(t *testing.T) {
	d, store, pub := newDispatcher(t)
	gate := d.GateFor(testFlowID, Config{Mode: ModeRiskClassified, MinRisk: RiskHigh})

	res, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"ls"}`))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Decision != DecisionApproved {
		t.Fatalf("decision %s, want approved", res.Decision)
	}
	if len(store.rows) != 0 {
		t.Fatal("an ungated call must not create an approval row")
	}
	if len(pub.requested) != 0 {
		t.Fatal("an ungated call must not be announced")
	}
}

// decided waits for the one pending approval, then applies decide to it.
func decideSoon(t *testing.T, d *Dispatcher, store *memStore, decide func(id int64)) {
	t.Helper()
	go func() {
		deadline := time.After(2 * time.Second)
		for {
			select {
			case <-deadline:
				t.Error("no approval became pending")
				return
			default:
			}
			if pending, _ := store.GetFlowPendingToolApprovals(context.Background(), testFlowID); len(pending) == 1 {
				decide(pending[0].ID)
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
}

func TestDispatcher_Evaluate_BlocksUntilTheOperatorDecides(t *testing.T) {
	cases := []struct {
		name     string
		decision Decision
		edited   string
		wantDec  Decision
		wantArgs string
		wantErr  error
	}{
		{name: "approved", decision: DecisionApproved, wantDec: DecisionApproved, wantArgs: `{"input":"nmap t"}`},
		{name: "edited", decision: DecisionEdited, edited: `{"input":"nmap -T2 t"}`, wantDec: DecisionEdited, wantArgs: `{"input":"nmap -T2 t"}`},
		{name: "denied", decision: DecisionDenied, wantErr: ErrDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, store, pub := newDispatcher(t)
			gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools, AllowEdit: true})

			decideSoon(t, d, store, func(id int64) {
				var edited json.RawMessage
				if tc.edited != "" {
					edited = json.RawMessage(tc.edited)
				}
				if _, err := d.Decide(context.Background(), id, tc.decision, edited, "because", 99); err != nil {
					t.Errorf("decide: %v", err)
				}
			})

			res, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Decision != tc.wantDec || string(res.Args) != tc.wantArgs {
				t.Fatalf("got (%s, %s), want (%s, %s)", res.Decision, res.Args, tc.wantDec, tc.wantArgs)
			}
			if len(pub.requested) != 1 || len(pub.updated) != 1 {
				t.Fatalf("announced %d requested / %d updated, want 1 / 1", len(pub.requested), len(pub.updated))
			}
		})
	}
}

func TestDispatcher_Evaluate_AppliesTheTimeoutOutcome(t *testing.T) {
	t.Run("deny on timeout", func(t *testing.T) {
		d, _, _ := newDispatcher(t)
		gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools, TimeoutSec: 1, OnTimeout: OnTimeoutDeny})
		_, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
	})
	t.Run("approve on timeout", func(t *testing.T) {
		d, _, _ := newDispatcher(t)
		gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools, TimeoutSec: 1, OnTimeout: OnTimeoutApprove})
		res, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
		if err != nil || res.Decision != DecisionApproved {
			t.Fatalf("got (%v, %v), want approved", res, err)
		}
	})
}

func TestDispatcher_Evaluate_ReleasesABlockedCallWhenItsContextEnds(t *testing.T) {
	d, store, pub := newDispatcher(t)
	gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools})
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := gate.Evaluate(ctx, req("terminal", `{"input":"nmap t"}`))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled evaluate never returned")
	}

	if pending, _ := store.GetFlowPendingToolApprovals(context.Background(), testFlowID); len(pending) != 0 {
		t.Fatalf("%d request(s) still pending after the agent stopped waiting, want none", len(pending))
	}
	if len(pub.updated) != 1 || pub.updated[0].Decision != database.ToolApprovalDecisionCancelled {
		t.Fatalf("announced %+v, want the request reported cancelled", pub.updated)
	}
}

func TestDispatcher_Evaluate_PausesTheFlowOnceTheDenialBudgetIsSpent(t *testing.T) {
	d, store, _ := newDispatcher(t)
	pauser := &recordingPauser{}
	d.SetPauser(pauser)
	gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools, MaxDenials: 2})

	denyNext := func() error {
		decideSoon(t, d, store, func(id int64) {
			if _, err := d.Decide(context.Background(), id, DecisionDenied, nil, "no", 1); err != nil {
				t.Errorf("decide: %v", err)
			}
		})
		_, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
		return err
	}

	if err := denyNext(); !errors.Is(err, ErrDenied) {
		t.Fatalf("first denial err = %v, want ErrDenied", err)
	}
	if err := denyNext(); !errors.Is(err, ErrPaused) {
		t.Fatalf("second denial err = %v, want ErrPaused", err)
	}
	if len(pauser.paused) != 1 || pauser.paused[0] != testFlowID {
		t.Fatalf("paused %v, want [%d]", pauser.paused, testFlowID)
	}
}

func TestDispatcher_CancelFlow_RefusesAndWakesEveryPendingCall(t *testing.T) {
	d, store, pub := newDispatcher(t)
	gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools})

	done := make(chan error, 1)
	go func() {
		_, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
		done <- err
	}()

	// Wait for the request to be pending, then cancel the whole flow.
	deadline := time.After(2 * time.Second)
	for {
		if pending, _ := store.GetFlowPendingToolApprovals(context.Background(), testFlowID); len(pending) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no approval became pending")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := d.CancelFlow(context.Background(), testFlowID, "flow stopped"); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("a cancelled call returned %v, want ErrDenied", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelling the flow did not wake the blocked call")
	}
	if len(pub.updated) != 1 {
		t.Fatalf("announced %d updates, want 1", len(pub.updated))
	}
}

func TestDispatcher_CancelOrphaned_ClosesEveryPendingRowAndTellsTheOperator(t *testing.T) {
	store := newMemStore()
	pub := &capturePublisher{}
	d := NewDispatcher(store, pub)

	first, _ := store.CreateToolApproval(context.Background(), database.CreateToolApprovalParams{FlowID: testFlowID, Agent: database.MsgchainTypePentester, ToolCallID: "a", ToolName: "terminal", Args: json.RawMessage(`{}`), RiskClass: database.ToolRiskClassHigh})
	decided, _ := store.CreateToolApproval(context.Background(), database.CreateToolApprovalParams{FlowID: testFlowID, Agent: database.MsgchainTypePentester, ToolCallID: "b", ToolName: "terminal", Args: json.RawMessage(`{}`), RiskClass: database.ToolRiskClassHigh})
	if _, err := store.DecideToolApproval(context.Background(), database.DecideToolApprovalParams{ID: decided.ID, Decision: database.ToolApprovalDecisionApproved}); err != nil {
		t.Fatalf("decide: %v", err)
	}

	if err := d.CancelOrphaned(context.Background()); err != nil {
		t.Fatalf("cancel orphaned: %v", err)
	}

	if got, _ := store.GetToolApproval(context.Background(), first.ID); got.Decision != database.ToolApprovalDecisionCancelled {
		t.Fatalf("the orphan is %q, want cancelled", got.Decision)
	}
	if got, _ := store.GetToolApproval(context.Background(), decided.ID); got.Decision != database.ToolApprovalDecisionApproved {
		t.Fatalf("an already decided row became %q, want it left approved", got.Decision)
	}
	if len(pub.updated) != 1 || pub.updated[0].ID != first.ID {
		t.Fatalf("announced %+v, want exactly the cancelled orphan", pub.updated)
	}
}

func TestDispatcher_Decide_RefusesAnEditTheFlowsPolicyDoesNotAllow(t *testing.T) {
	d, store, _ := newDispatcher(t)
	gate := d.GateFor(testFlowID, Config{Mode: ModeAllTools, AllowEdit: false})

	waiting := make(chan error, 1)
	go func() {
		_, err := gate.Evaluate(context.Background(), req("terminal", `{"input":"nmap t"}`))
		waiting <- err
	}()

	var id int64
	deadline := time.After(2 * time.Second)
	for id == 0 {
		if pending, _ := store.GetFlowPendingToolApprovals(context.Background(), testFlowID); len(pending) == 1 {
			id = pending[0].ID
			break
		}
		select {
		case <-deadline:
			t.Fatal("no approval became pending")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	_, err := d.Decide(context.Background(), id, DecisionEdited, json.RawMessage(`{"input":"id"}`), "", 1)
	if err == nil || !strings.Contains(err.Error(), "does not allow edited arguments") {
		t.Fatalf("Decide(edited) = %v, want a refusal naming the policy", err)
	}
	if got, _ := store.GetToolApproval(context.Background(), id); got.Decision != database.ToolApprovalDecisionPending {
		t.Fatalf("the refused edit left the request %q, want it still pending", got.Decision)
	}

	// The operator can still settle it, and the agent is released.
	if _, err := d.Decide(context.Background(), id, DecisionDenied, nil, "no edits here", 1); err != nil {
		t.Fatalf("deny: %v", err)
	}
	select {
	case err := <-waiting:
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("agent got %v, want ErrDenied", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the agent was never released")
	}
}
