//go:build postgres

package database_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"pentagi/pkg/database"

	"github.com/sqlc-dev/pqtype"
)

func requestApproval(t *testing.T, q *database.Queries, flowID int64, callID string) database.ToolApproval {
	t.Helper()

	approval, err := q.CreateToolApproval(context.Background(), database.CreateToolApprovalParams{
		FlowID:     flowID,
		Agent:      database.MsgchainTypePentester,
		ToolCallID: callID,
		ToolName:   "terminal",
		Args:       json.RawMessage(`{"input":"id"}`),
		RiskClass:  database.ToolRiskClassMedium,
	})
	if err != nil {
		t.Fatalf("create approval %s: %v", callID, err)
	}
	if approval.Decision != database.ToolApprovalDecisionPending {
		t.Fatalf("a new approval is %q, want pending", approval.Decision)
	}
	return approval
}

func decide(t *testing.T, q *database.Queries, id int64, decision database.ToolApprovalDecision) {
	t.Helper()

	params := database.DecideToolApprovalParams{ID: id, Decision: decision}
	if decision == database.ToolApprovalDecisionEdited {
		params.EditedArgs = pqtype.NullRawMessage{RawMessage: json.RawMessage(`{"input":"whoami"}`), Valid: true}
	}
	if _, err := q.DecideToolApproval(context.Background(), params); err != nil {
		t.Fatalf("decide %d as %s: %v", id, decision, err)
	}
}

func TestToolApprovals_DecideToolApproval_DecidesOnlyOnce(t *testing.T) {
	db := openSchema(t)
	q := database.New(db)
	flowID := seedFlow(t, db, seedUser(t, db), time.Now().UTC())

	approval := requestApproval(t, q, flowID, "call-1")
	decide(t, q, approval.ID, database.ToolApprovalDecisionDenied)

	_, err := q.DecideToolApproval(context.Background(), database.DecideToolApprovalParams{
		ID:       approval.ID,
		Decision: database.ToolApprovalDecisionApproved,
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("a second decision returned %v, want sql.ErrNoRows", err)
	}

	stored, err := q.GetToolApproval(context.Background(), approval.ID)
	if err != nil {
		t.Fatalf("get approval: %v", err)
	}
	if stored.Decision != database.ToolApprovalDecisionDenied || !stored.DecidedAt.Valid {
		t.Fatalf("stored decision is %q (decided_at valid=%v), want the first decision kept", stored.Decision, stored.DecidedAt.Valid)
	}
}

func TestToolApprovals_DecideToolApproval_RejectsEditedArgsOutsideAnEdit(t *testing.T) {
	db := openSchema(t)
	q := database.New(db)
	flowID := seedFlow(t, db, seedUser(t, db), time.Now().UTC())

	tests := []struct {
		name   string
		params database.DecideToolApprovalParams
	}{
		{name: "an edit without arguments", params: database.DecideToolApprovalParams{
			Decision: database.ToolApprovalDecisionEdited,
		}},
		{name: "an approval with arguments", params: database.DecideToolApprovalParams{
			Decision:   database.ToolApprovalDecisionApproved,
			EditedArgs: pqtype.NullRawMessage{RawMessage: json.RawMessage(`{}`), Valid: true},
		}},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.params.ID = requestApproval(t, q, flowID, "call-"+string(rune('a'+i))).ID
			if _, err := q.DecideToolApproval(context.Background(), tc.params); err == nil {
				t.Fatal("the decision was stored, want the check constraint to refuse it")
			}
		})
	}
}

func TestToolApprovals_CountFlowTrailingDenials_CountsOnlySinceTheLastGrant(t *testing.T) {
	db := openSchema(t)
	q := database.New(db)
	uid := seedUser(t, db)
	flowID := seedFlow(t, db, uid, time.Now().UTC())
	otherFlowID := seedFlow(t, db, uid, time.Now().UTC())

	count := func() int64 {
		t.Helper()
		n, err := q.CountFlowTrailingDenials(context.Background(), flowID)
		if err != nil {
			t.Fatalf("count denials: %v", err)
		}
		return n
	}

	steps := []struct {
		decision database.ToolApprovalDecision
		want     int64
	}{
		{database.ToolApprovalDecisionDenied, 1},
		{database.ToolApprovalDecisionDenied, 2},
		{database.ToolApprovalDecisionTimeout, 2},
		{database.ToolApprovalDecisionApproved, 0},
		{database.ToolApprovalDecisionDenied, 1},
		{database.ToolApprovalDecisionEdited, 0},
		{database.ToolApprovalDecisionDenied, 1},
	}
	for i, step := range steps {
		approval := requestApproval(t, q, flowID, "call-"+string(rune('a'+i)))
		decide(t, q, approval.ID, step.decision)
		other := requestApproval(t, q, otherFlowID, "other-"+string(rune('a'+i)))
		decide(t, q, other.ID, database.ToolApprovalDecisionDenied)

		if got := count(); got != step.want {
			t.Fatalf("after step %d (%s) the streak is %d, want %d", i+1, step.decision, got, step.want)
		}
	}

	requestApproval(t, q, flowID, "still-pending")
	if got := count(); got != 1 {
		t.Fatalf("a pending request changed the streak to %d, want 1", got)
	}
}

func TestToolApprovals_CancelFlowPendingToolApprovals_LeavesOtherFlowsPending(t *testing.T) {
	db := openSchema(t)
	q := database.New(db)
	uid := seedUser(t, db)
	flowID := seedFlow(t, db, uid, time.Now().UTC())
	otherFlowID := seedFlow(t, db, uid, time.Now().UTC())

	pending := requestApproval(t, q, flowID, "call-1")
	decided := requestApproval(t, q, flowID, "call-2")
	decide(t, q, decided.ID, database.ToolApprovalDecisionApproved)
	other := requestApproval(t, q, otherFlowID, "call-3")

	cancelled, err := q.CancelFlowPendingToolApprovals(context.Background(), database.CancelFlowPendingToolApprovalsParams{
		FlowID: flowID,
		Reason: "flow stopped",
	})
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if len(cancelled) != 1 || cancelled[0].ID != pending.ID || cancelled[0].Reason != "flow stopped" {
		t.Fatalf("cancelled %+v, want only approval %d with the reason", cancelled, pending.ID)
	}

	left, err := q.GetFlowPendingToolApprovals(context.Background(), otherFlowID)
	if err != nil {
		t.Fatalf("pending of the other flow: %v", err)
	}
	if len(left) != 1 || left[0].ID != other.ID {
		t.Fatalf("the other flow has %+v pending, want approval %d", left, other.ID)
	}
}

func TestToolApprovals_Constraints_RefuseValuesOutsideTheirSets(t *testing.T) {
	db := openSchema(t)
	flowID := seedFlow(t, db, seedUser(t, db), time.Now().UTC())

	insert := func(risk, decision string) error {
		_, err := db.Exec(`
			INSERT INTO tool_approvals (flow_id, agent, tool_call_id, tool_name, args, risk_class, decision)
			VALUES ($1, 'pentester', 'c', 'terminal', '{}', $2, $3)`, flowID, risk, decision)
		return err
	}

	if err := insert("medium", "pending"); err != nil {
		t.Fatalf("a valid row was refused: %v", err)
	}
	if err := insert("severe", "pending"); err == nil {
		t.Fatal("an unknown risk class was stored, want the check constraint to refuse it")
	}
	if err := insert("medium", "maybe"); err == nil {
		t.Fatal("an unknown decision was stored, want the check constraint to refuse it")
	}
}
