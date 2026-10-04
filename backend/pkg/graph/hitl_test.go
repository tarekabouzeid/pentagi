package graph

import (
	"context"
	"encoding/json"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/graph/model"
	"pentagi/pkg/hitl"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hitlStore is a minimal hitl.Store: enough for the resolver authz tests, which
// never reach the blocking paths.
type hitlStore struct {
	hitl.Store

	approval database.ToolApproval
	rows     []database.ToolApproval
	decided  *database.DecideToolApprovalParams
}

func (s *hitlStore) GetToolApproval(context.Context, int64) (database.ToolApproval, error) {
	return s.approval, nil
}

func (s *hitlStore) GetFlowToolApprovals(context.Context, int64) ([]database.ToolApproval, error) {
	return s.rows, nil
}

func (s *hitlStore) DecideToolApproval(_ context.Context, arg database.DecideToolApprovalParams) (database.ToolApproval, error) {
	s.decided = &arg
	out := s.approval
	out.Decision = arg.Decision
	out.DecidedBy = arg.DecidedBy
	return out, nil
}

func hitlResolver(db *graphDB, store *hitlStore) *Resolver {
	r := graphResolver(db)
	r.HITL = hitl.NewDispatcher(store, noopHITLPublisher{})
	return r
}

type noopHITLPublisher struct{}

func (noopHITLPublisher) ToolApprovalRequested(context.Context, database.ToolApproval) {}
func (noopHITLPublisher) ToolApprovalUpdated(context.Context, database.ToolApproval)   {}

func TestHITLResolver_ToolApprovals_RefusesAFlowTheCallerDoesNotOwn(t *testing.T) {
	db := &graphDB{flowOwner: 2}
	r := hitlResolver(db, &hitlStore{rows: []database.ToolApproval{{ID: 1, FlowID: 5}}})

	_, err := r.Query().ToolApprovals(graphUserContext(1, "flows.view"), 5)

	require.Error(t, err, "a non-owner must not read another user's approvals")
}

func TestHITLResolver_ToolApprovals_ServesTheOwnersFlow(t *testing.T) {
	db := &graphDB{flowOwner: 1}
	r := hitlResolver(db, &hitlStore{rows: []database.ToolApproval{
		{ID: 1, FlowID: 5, Agent: database.MsgchainTypePentester, Args: json.RawMessage(`{}`)},
	}})

	out, err := r.Query().ToolApprovals(graphUserContext(1, "flows.view"), 5)

	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, int64(1), out[0].ID)
}

func TestHITLResolver_DecideToolApproval_RefusesAnApprovalOfAnotherFlow(t *testing.T) {
	db := &graphDB{flowOwner: 1}
	// The caller owns flow 5, but the approval belongs to flow 9.
	store := &hitlStore{approval: database.ToolApproval{ID: 7, FlowID: 9}}
	r := hitlResolver(db, store)

	_, err := r.Mutation().DecideToolApproval(graphUserContext(1, "flows.edit"), 5, 7, model.ApprovalDecisionApproved, nil, nil)

	require.ErrorIs(t, err, ErrForbidden)
	assert.Nil(t, store.decided, "a cross-flow approval must never be decided")
}

func TestHITLResolver_DecideToolApproval_RecordsTheDecidingUser(t *testing.T) {
	db := &graphDB{flowOwner: 1}
	store := &hitlStore{approval: database.ToolApproval{ID: 7, FlowID: 5, Args: json.RawMessage(`{}`), Agent: database.MsgchainTypePentester}}
	r := hitlResolver(db, store)

	_, err := r.Mutation().DecideToolApproval(graphUserContext(1, "flows.edit"), 5, 7, model.ApprovalDecisionDenied, nil, strPtr("no"))

	require.NoError(t, err)
	require.NotNil(t, store.decided)
	assert.Equal(t, int64(1), store.decided.DecidedBy.Int64, "the decision records the acting user")
	assert.Equal(t, database.ToolApprovalDecisionDenied, store.decided.Decision)
}
