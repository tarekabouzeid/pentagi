-- name: CreateToolApproval :one
INSERT INTO tool_approvals (
  flow_id,
  task_id,
  subtask_id,
  assistant_id,
  agent,
  tool_call_id,
  tool_name,
  args,
  risk_class,
  risk_reason
) VALUES (
  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
RETURNING *;

-- name: DecideToolApproval :one
UPDATE tool_approvals
SET
  decision = $1,
  edited_args = $2,
  reason = $3,
  decided_by = $4,
  decided_at = CURRENT_TIMESTAMP
WHERE id = $5 AND decision = 'pending'
RETURNING *;

-- name: GetToolApproval :one
SELECT
  ta.*
FROM tool_approvals ta
WHERE ta.id = $1;

-- name: GetFlowToolApprovals :many
SELECT
  ta.*
FROM tool_approvals ta
WHERE ta.flow_id = $1
ORDER BY ta.created_at DESC, ta.id DESC;

-- name: GetFlowPendingToolApprovals :many
SELECT
  ta.*
FROM tool_approvals ta
WHERE ta.flow_id = $1 AND ta.decision = 'pending'
ORDER BY ta.id ASC;

-- name: CancelPendingToolApprovals :many
UPDATE tool_approvals
SET
  decision = 'cancelled',
  reason = $1,
  decided_at = CURRENT_TIMESTAMP
WHERE decision = 'pending'
RETURNING *;

-- name: CancelFlowPendingToolApprovals :many
UPDATE tool_approvals
SET
  decision = 'cancelled',
  reason = $1,
  decided_at = CURRENT_TIMESTAMP
WHERE flow_id = $2 AND decision = 'pending'
RETURNING *;

-- A denial streak is broken by an approval or an edit, not by a timeout or a cancellation.
-- name: CountFlowTrailingDenials :one
SELECT
  COUNT(*)::BIGINT
FROM tool_approvals ta
WHERE ta.flow_id = $1
  AND ta.decision = 'denied'
  AND ta.id > COALESCE((
    SELECT MAX(granted.id)
    FROM tool_approvals granted
    WHERE granted.flow_id = $1 AND granted.decision IN ('approved', 'edited')
  ), 0);

-- name: GetAllPendingToolApprovals :many
SELECT
  ta.*
FROM tool_approvals ta
WHERE ta.decision = 'pending'
ORDER BY ta.id ASC;
