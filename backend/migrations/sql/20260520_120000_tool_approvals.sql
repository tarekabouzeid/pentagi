-- +goose Up
-- +goose StatementBegin

CREATE TYPE TOOL_APPROVAL_DECISION AS ENUM (
  'pending',
  'approved',
  'denied',
  'edited',
  'timeout'
);

CREATE TYPE HITL_MODE AS ENUM (
  'per_tool',
  'risk_classified',
  'policy_only'
);

CREATE TYPE RISK_CLASS AS ENUM (
  'low',
  'medium',
  'high',
  'blocked'
);

CREATE TABLE tool_approvals (
  id BIGSERIAL PRIMARY KEY,
  flow_id BIGINT NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
  tool_call_id TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  args JSONB NOT NULL DEFAULT '{}',
  risk_class RISK_CLASS NOT NULL DEFAULT 'medium',
  decision TOOL_APPROVAL_DECISION NOT NULL DEFAULT 'pending',
  edited_args JSONB,
  reason TEXT,
  decided_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  requested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tool_approvals_flow_decision ON tool_approvals(flow_id, decision);
CREATE INDEX idx_tool_approvals_pending ON tool_approvals(decision) WHERE decision = 'pending';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS tool_approvals;
DROP TYPE IF EXISTS RISK_CLASS;
DROP TYPE IF EXISTS HITL_MODE;
DROP TYPE IF EXISTS TOOL_APPROVAL_DECISION;

-- +goose StatementEnd
