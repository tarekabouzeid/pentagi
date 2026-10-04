package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/hitl"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hitlFlowDB struct {
	database.Querier

	owner int64
}

func (d hitlFlowDB) GetFlow(_ context.Context, id int64) (database.Flow, error) {
	if id == 404 {
		return database.Flow{}, sql.ErrNoRows
	}

	return database.Flow{ID: id, UserID: d.owner}, nil
}

type hitlRowStore struct {
	hitl.Store

	approval database.ToolApproval
	decided  *database.DecideToolApprovalParams
}

func (s *hitlRowStore) GetToolApproval(context.Context, int64) (database.ToolApproval, error) {
	return s.approval, nil
}

func (s *hitlRowStore) GetFlowToolApprovals(context.Context, int64) ([]database.ToolApproval, error) {
	return []database.ToolApproval{s.approval}, nil
}

func (s *hitlRowStore) DecideToolApproval(_ context.Context, arg database.DecideToolApprovalParams) (database.ToolApproval, error) {
	s.decided = &arg
	out := s.approval
	out.Decision = arg.Decision
	out.DecidedBy = arg.DecidedBy

	return out, nil
}

type hitlNoPublisher struct{}

func (hitlNoPublisher) ToolApprovalRequested(context.Context, database.ToolApproval) {}
func (hitlNoPublisher) ToolApprovalUpdated(context.Context, database.ToolApproval)   {}

// hitlEngine mounts the two handlers behind a stand-in for the auth middleware.
func hitlEngine(owner int64, store *hitlRowStore, uid uint64, prm ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)

	svc := NewHITLService(hitl.NewDispatcher(store, hitlNoPublisher{}), hitlFlowDB{owner: owner})
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("uid", uid)
		c.Set("prm", prm)
	})
	engine.GET("/flows/:flowID/approvals", svc.GetFlowApprovals)
	engine.POST("/flows/:flowID/approvals/:approvalID/decide", svc.DecideToolApproval)

	return engine
}

func hitlDecide(engine *gin.Engine, flowID, approvalID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/flows/"+flowID+"/approvals/"+approvalID+"/decide", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func TestHITL_DecideToolApproval_RefusesAFlowTheCallerDoesNotOwn(t *testing.T) {
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 5}}
	engine := hitlEngine(2, store, 1, "flows.edit")

	rec := hitlDecide(engine, "5", "7", `{"decision":"approved"}`)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.decided, "a non-owner must not decide another user's approval")
}

func TestHITL_DecideToolApproval_RefusesAnApprovalOfAnotherFlow(t *testing.T) {
	// The caller owns flow 5, but approval 7 belongs to flow 9.
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 9}}
	engine := hitlEngine(1, store, 1, "flows.edit")

	rec := hitlDecide(engine, "5", "7", `{"decision":"approved"}`)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Nil(t, store.decided, "an approval must only be decided through its own flow")
}

func TestHITL_DecideToolApproval_RecordsTheDecidingUser(t *testing.T) {
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 5, Args: json.RawMessage(`{}`)}}
	engine := hitlEngine(3, store, 3, "flows.edit")

	rec := hitlDecide(engine, "5", "7", `{"decision":"denied","reason":"out of scope"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, store.decided)
	assert.Equal(t, int64(3), store.decided.DecidedBy.Int64)
	assert.Equal(t, database.ToolApprovalDecisionDenied, store.decided.Decision)
	assert.Equal(t, "out of scope", store.decided.Reason)
}

func TestHITL_DecideToolApproval_LetsAnAdminDecideAnyFlow(t *testing.T) {
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 5, Args: json.RawMessage(`{}`)}}
	engine := hitlEngine(2, store, 1, "flows.edit", "flows.admin")

	rec := hitlDecide(engine, "5", "7", `{"decision":"approved"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, int64(1), store.decided.DecidedBy.Int64, "the admin, not the owner, is recorded")
}

func TestHITL_DecideToolApproval_ReportsAMissingFlowAndABadDecision(t *testing.T) {
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 5}}
	engine := hitlEngine(1, store, 1, "flows.edit")

	assert.Equal(t, http.StatusNotFound, hitlDecide(engine, "404", "7", `{"decision":"approved"}`).Code)
	assert.Equal(t, http.StatusBadRequest, hitlDecide(engine, "5", "7", `{"decision":"maybe"}`).Code)
	assert.Equal(t, http.StatusBadRequest, hitlDecide(engine, "5", "7", `{"decision":"edited"}`).Code,
		"an edit without replacement arguments is not a decision")
	assert.Nil(t, store.decided)
}

func TestHITL_GetFlowApprovals_ServesOnlyTheOwnersFlow(t *testing.T) {
	store := &hitlRowStore{approval: database.ToolApproval{ID: 7, FlowID: 5, Args: json.RawMessage(`{}`)}}

	own := httptest.NewRecorder()
	hitlEngine(1, store, 1, "flows.view").ServeHTTP(own, httptest.NewRequest(http.MethodGet, "/flows/5/approvals", nil))
	other := httptest.NewRecorder()
	hitlEngine(2, store, 1, "flows.view").ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/flows/5/approvals", nil))

	assert.Equal(t, http.StatusOK, own.Code)
	assert.Equal(t, http.StatusForbidden, other.Code)
}
