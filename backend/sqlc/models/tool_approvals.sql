-- name: CreateToolApproval :one
INSERT INTO tool_approvals (
  flow_id, task_id, tool_call_id, tool_name, args, risk_class, decision, requested_at
)
VALUES (
  $1, $2, $3, $4, $5, $6, 'pending', NOW()
)
RETURNING *;

-- name: UpdateToolApprovalDecision :one
UPDATE tool_approvals
SET decision = $1, edited_args = $2, reason = $3, decided_by = $4, decided_at = NOW()
WHERE id = $5 AND decision = 'pending'
RETURNING *;

-- name: GetToolApproval :one
SELECT * FROM tool_approvals
WHERE id = $1;

-- name: GetToolApprovalsByFlow :many
SELECT * FROM tool_approvals
WHERE flow_id = $1
ORDER BY requested_at DESC;

-- name: GetPendingToolApprovals :many
SELECT * FROM tool_approvals
WHERE flow_id = $1 AND decision = 'pending'
ORDER BY requested_at ASC;

-- name: GetAllPendingToolApprovals :many
SELECT * FROM tool_approvals
WHERE decision = 'pending'
ORDER BY requested_at ASC;

-- name: CountConsecutiveDenials :one
SELECT COUNT(*) FROM (
  SELECT decision FROM tool_approvals
  WHERE flow_id = $1
  ORDER BY requested_at DESC
) sub
WHERE sub.decision = 'denied';
