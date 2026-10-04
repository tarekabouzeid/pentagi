package services

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"pentagi/pkg/database"
	"pentagi/pkg/database/converter"
	"pentagi/pkg/hitl"
	"pentagi/pkg/server/logger"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
)

// HITLService serves the REST equivalents of the HITL GraphQL operations: it
// reuses the same dispatcher, so a decision made over REST and one made over
// GraphQL are indistinguishable downstream.
type HITLService struct {
	dispatcher *hitl.Dispatcher
	db         database.Querier
}

func NewHITLService(dispatcher *hitl.Dispatcher, db database.Querier) *HITLService {
	return &HITLService{dispatcher: dispatcher, db: db}
}

type decideToolApprovalRequest struct {
	Decision   string          `json:"decision" binding:"required"`
	EditedArgs json.RawMessage `json:"edited_args"`
	Reason     string          `json:"reason"`
}

// ownsFlow reports whether the caller may act on flowID: a flows.admin caller
// may act on any flow, anyone else only on their own.
func (s *HITLService) ownsFlow(c *gin.Context, flowID int64) (bool, error) {
	privs := c.GetStringSlice("prm")
	if slices.Contains(privs, "flows.admin") {
		_, err := s.db.GetFlow(c.Request.Context(), flowID)
		return err == nil, err
	}
	flow, err := s.db.GetFlow(c.Request.Context(), flowID)
	if err != nil {
		return false, err
	}
	return flow.UserID == int64(c.GetUint64("uid")), nil
}

// GetFlowApprovals handles GET /flows/:flowID/approvals
// @Summary List a flow's tool approvals
// @Tags HITL
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Success 200 {object} response.successResp
// @Failure 403 {object} response.errorResp
// @Failure 404 {object} response.errorResp
// @Router /flows/{flowID}/approvals [get]
func (s *HITLService) GetFlowApprovals(c *gin.Context) {
	flowID, ok := s.flowIDOwnedByCaller(c)
	if !ok {
		return
	}

	rows, err := s.dispatcher.ListFlow(c.Request.Context(), flowID)
	if err != nil {
		response.Error(c, response.ErrInternal, err)
		return
	}

	response.Success(c, http.StatusOK, converter.ConvertToolApprovals(rows))
}

// DecideToolApproval handles POST /flows/:flowID/approvals/:approvalID/decide
// @Summary Decide a pending tool approval
// @Tags HITL
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param flowID path int true "flow id" minimum(0)
// @Param approvalID path int true "approval id" minimum(0)
// @Param request body decideToolApprovalRequest true "decision"
// @Success 200 {object} response.successResp
// @Failure 400 {object} response.errorResp
// @Failure 403 {object} response.errorResp
// @Failure 404 {object} response.errorResp
// @Router /flows/{flowID}/approvals/{approvalID}/decide [post]
func (s *HITLService) DecideToolApproval(c *gin.Context) {
	flowID, ok := s.flowIDOwnedByCaller(c)
	if !ok {
		return
	}

	approvalID, err := strconv.ParseInt(c.Param("approvalID"), 10, 64)
	if err != nil {
		response.Error(c, response.ErrFlowsInvalidRequest, err)
		return
	}

	var req decideToolApprovalRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, response.ErrFlowsInvalidRequest, err)
		return
	}

	approval, err := s.dispatcher.Approval(c.Request.Context(), approvalID)
	if err != nil {
		response.Error(c, response.ErrFlowsNotFound, err)
		return
	}
	if approval.FlowID != flowID {
		// Not the caller's flow to decide for, though the approval exists.
		response.Error(c, response.ErrNotPermitted, errors.New("approval belongs to another flow"))
		return
	}

	updated, err := s.dispatcher.Decide(
		c.Request.Context(), approvalID, hitl.Decision(req.Decision), req.EditedArgs, req.Reason, int64(c.GetUint64("uid")),
	)
	if err != nil {
		response.Error(c, response.ErrFlowsInvalidRequest, err)
		return
	}

	response.Success(c, http.StatusOK, converter.ConvertToolApproval(updated))
}

// flowIDOwnedByCaller parses :flowID and confirms the caller may act on it,
// writing the error response itself when it may not.
func (s *HITLService) flowIDOwnedByCaller(c *gin.Context) (int64, bool) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, response.ErrFlowsInvalidRequest, err)
		return 0, false
	}

	owns, err := s.ownsFlow(c, flowID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.Error(c, response.ErrFlowsNotFound, err)
		} else {
			response.Error(c, response.ErrInternal, err)
		}
		return 0, false
	}
	if !owns {
		logger.FromContext(c).Warn("tool approval access denied: flow belongs to another user")
		response.Error(c, response.ErrNotPermitted, nil)
		return 0, false
	}

	return flowID, true
}
