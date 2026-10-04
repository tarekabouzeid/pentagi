-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS tool_approvals (
  id            BIGINT        PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  flow_id       BIGINT        NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  task_id       BIGINT        NULL REFERENCES tasks(id) ON DELETE SET NULL,
  subtask_id    BIGINT        NULL REFERENCES subtasks(id) ON DELETE SET NULL,
  assistant_id  BIGINT        NULL REFERENCES assistants(id) ON DELETE SET NULL,
  agent         MSGCHAIN_TYPE NOT NULL,
  tool_call_id  TEXT          NOT NULL,
  tool_name     TEXT          NOT NULL,
  args          JSONB         NOT NULL,
  risk_class    TEXT          NOT NULL,
  risk_reason   TEXT          NOT NULL DEFAULT '',
  decision      TEXT          NOT NULL DEFAULT 'pending',
  edited_args   JSONB         NULL,
  reason        TEXT          NOT NULL DEFAULT '',
  decided_by    BIGINT        NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at    TIMESTAMPTZ   NULL,

  CONSTRAINT tool_approvals_risk_class_valid
    CHECK (risk_class IN ('low', 'medium', 'high', 'blocked')),
  CONSTRAINT tool_approvals_decision_valid
    CHECK (decision IN ('pending', 'approved', 'edited', 'denied', 'timeout', 'cancelled')),
  CONSTRAINT tool_approvals_edited_args_only_when_edited
    CHECK ((decision = 'edited') = (edited_args IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS tool_approvals_flow_id_created_at_idx ON tool_approvals(flow_id, created_at DESC);
CREATE INDEX IF NOT EXISTS tool_approvals_pending_idx ON tool_approvals(flow_id) WHERE decision = 'pending';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tool_approvals;
-- +goose StatementEnd
