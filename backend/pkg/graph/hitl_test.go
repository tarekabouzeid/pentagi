package graph

import (
	"context"
	"encoding/json"
	"testing"

	"pentagi/pkg/config"
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

func TestHITLResolver_flowFunctions_MergesTheHITLAndSandboxInputs(t *testing.T) {
	backend, profile := "openshell", "recon_only"
	minRisk := model.RiskClassMedium
	timeout := 45

	got, err := flowFunctions(
		&model.HitlConfigInput{Mode: model.HitlModeRiskClassified, MinRisk: &minRisk, TimeoutSeconds: &timeout},
		&model.SandboxConfigInput{Backend: &backend, Profile: &profile},
	)

	require.NoError(t, err)
	require.NotNil(t, got.HITL)
	assert.Equal(t, hitl.ModeRiskClassified, got.HITL.Mode)
	assert.Equal(t, hitl.RiskMedium, got.HITL.MinRisk)
	assert.Equal(t, 45, got.HITL.TimeoutSec)
	require.NotNil(t, got.Sandbox)
	assert.Equal(t, "openshell", string(got.Sandbox.Backend))
	assert.Equal(t, "recon_only", got.Sandbox.Profile)
}

func TestHITLResolver_flowFunctions_LeavesTheDefaultsWhenNothingIsAsked(t *testing.T) {
	got, err := flowFunctions(nil, nil)

	require.NoError(t, err)
	assert.Nil(t, got, "no input means no per-flow override at all")
}

func TestHITLResolver_flowFunctions_RefusesABrokenPolicy(t *testing.T) {
	bad := "allow"

	_, err := flowFunctions(&model.HitlConfigInput{Mode: model.HitlModeAllTools, OnTimeout: &bad}, nil)

	require.Error(t, err)
}

func TestHITLResolver_Settings_ListsTheEnabledSandboxBackends(t *testing.T) {
	tests := []struct {
		name         string
		cfg          *config.Config
		wantBackends []string
		wantDefault  string
		wantPresets  []string
	}{
		{"docker only", &config.Config{}, []string{"docker"}, "docker", []string{}},
		{"openshell enabled",
			&config.Config{OpenShellEnabled: true, ExecutorBackend: "openshell"},
			[]string{"docker", "openshell"}, "openshell", []string{"binary_analysis", "recon_only", "web_pentest"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sandboxSettings(tc.cfg)

			assert.Equal(t, tc.wantBackends, got.Backends)
			assert.Equal(t, tc.wantDefault, got.DefaultBackend)
			assert.Equal(t, tc.wantPresets, got.OpenshellPresets)
		})
	}
}
