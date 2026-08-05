package services

import (
	"fmt"
	"net/http"
	"strconv"

	"pentagi/pkg/controller"
	"pentagi/pkg/database"
	"pentagi/pkg/hitl"
	"pentagi/pkg/server/response"

	"github.com/gin-gonic/gin"
)

var (
	errBadRequest     = response.NewHttpError(http.StatusBadRequest, "bad_request", "invalid request")
	errInternalHITL   = response.NewHttpError(http.StatusInternalServerError, "internal_error", "internal error")
	errNotImplemented = response.NewHttpError(http.StatusNotImplemented, "not_implemented", "not implemented")
)

// HITLService handles REST endpoints for Human-In-The-Loop approval management.
type HITLService struct {
	dispatcher *hitl.Dispatcher
	controller controller.FlowController
}

// NewHITLService creates a new HITL service.
func NewHITLService(dispatcher *hitl.Dispatcher, fc controller.FlowController) *HITLService {
	return &HITLService{dispatcher: dispatcher, controller: fc}
}

type decideRequest struct {
	Decision   string `json:"decision" binding:"required,oneof=approved denied edited"`
	EditedArgs string `json:"edited_args,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// DecideToolApproval handles POST /flows/:flowID/approvals/:approvalID/decide
// @Summary Decide on a pending tool approval
// @Tags HITL
// @Accept json
// @Produce json
// @Param flowID path int true "Flow ID"
// @Param approvalID path int true "Approval ID"
// @Param body body decideRequest true "Decision"
// @Success 200 {object} response.successResp
// @Failure 400 {object} response.errorResp
// @Router /flows/{flowID}/approvals/{approvalID}/decide [post]
func (s *HITLService) DecideToolApproval(c *gin.Context) {
	approvalID, err := strconv.ParseInt(c.Param("approvalID"), 10, 64)
	if err != nil {
		response.Error(c, errBadRequest, fmt.Errorf("invalid approval ID: %w", err))
		return
	}

	var req decideRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, errBadRequest, err)
		return
	}

	resp := &hitl.ApprovalResponse{
		Decision: hitl.Decision(req.Decision),
		Reason:   req.Reason,
	}
	if req.EditedArgs != "" {
		resp.EditedArgs = []byte(req.EditedArgs)
	}

	if err := s.dispatcher.Submit(c.Request.Context(), approvalID, resp); err != nil {
		response.Error(c, errInternalHITL, err)
		return
	}

	response.Success(c, http.StatusOK, "approval decision submitted")
}

// PauseFlow handles POST /flows/:flowID/pause
// @Summary Pause a running flow (sets status to waiting)
// @Tags HITL
// @Produce json
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp
// @Router /flows/{flowID}/pause [post]
func (s *HITLService) PauseFlow(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errBadRequest, fmt.Errorf("invalid flow ID: %w", err))
		return
	}

	fw, err := s.controller.GetFlow(c.Request.Context(), flowID)
	if err != nil {
		response.Error(c, errBadRequest, fmt.Errorf("flow not found: %w", err))
		return
	}

	if err := fw.SetStatus(c.Request.Context(), database.FlowStatusWaiting); err != nil {
		response.Error(c, errInternalHITL, err)
		return
	}

	response.Success(c, http.StatusOK, "flow paused")
}

// ResumeFlow handles POST /flows/:flowID/resume
// @Summary Resume a paused flow
// @Tags HITL
// @Produce json
// @Param flowID path int true "Flow ID"
// @Success 200 {object} response.successResp
// @Router /flows/{flowID}/resume [post]
func (s *HITLService) ResumeFlow(c *gin.Context) {
	flowID, err := strconv.ParseInt(c.Param("flowID"), 10, 64)
	if err != nil {
		response.Error(c, errBadRequest, fmt.Errorf("invalid flow ID: %w", err))
		return
	}

	fw, err := s.controller.GetFlow(c.Request.Context(), flowID)
	if err != nil {
		response.Error(c, errBadRequest, fmt.Errorf("flow not found: %w", err))
		return
	}

	if err := fw.SetStatus(c.Request.Context(), database.FlowStatusRunning); err != nil {
		response.Error(c, errInternalHITL, err)
		return
	}

	response.Success(c, http.StatusOK, "flow resumed")
}

// InjectCommand handles POST /flows/:flowID/inject
// @Summary Inject a command into a running flow
// @Tags HITL
// @Accept json
// @Produce json
// @Param flowID path int true "Flow ID"
// @Param body body injectRequest true "Command to inject"
// @Success 501 {object} response.errorResp
// @Router /flows/{flowID}/inject [post]
func (s *HITLService) InjectCommand(c *gin.Context) {
	response.Error(c, errNotImplemented, fmt.Errorf("command injection is not yet implemented"))
}

type injectRequest struct {
	Command string `json:"command" binding:"required"`
}
