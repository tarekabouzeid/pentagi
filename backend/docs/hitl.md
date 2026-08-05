# Human-In-The-Loop (HITL) Architecture

PentAGI's HITL system provides operator oversight of autonomous agent tool execution. It allows human operators to approve, deny, or edit tool calls before they are executed, with configurable risk-based policies.

## Overview

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Agent     │────▶│  HITL Gate   │────▶│  Dispatcher  │────▶│   Frontend   │
│ (performer) │     │ (classifier) │     │  (waiter)    │     │ (approval UI)│
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                │                      │
                                                ▼                      │
                                         ┌──────────────┐              │
                                         │  PostgreSQL  │◀─────────────┘
                                         │ tool_approvals│   (decide mutation)
                                         └──────────────┘
```

1. Agent calls a tool (e.g., `terminal_exec`, `file_write`).
2. The **HITL Gate** classifies the risk and checks the flow's HITL config.
3. If approval is required, the **Dispatcher** persists a pending request and publishes a `toolApprovalRequested` event.
4. The **Frontend** displays the request in the Approvals tab.
5. The operator approves/denies/edits via GraphQL mutation.
6. The Dispatcher unblocks the agent with the decision.

## Configuration

HITL is configured per-flow via the `Functions` JSON field on flow creation:

```json
{
  "hitl": {
    "mode": "risk_classified",
    "approval_timeout_seconds": 300,
    "on_timeout": "deny",
    "allow_edit": true,
    "max_denials": 3,
    "risk_tools": [],
    "executor_backend": "docker"
  }
}
```

### Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | enum | `risk_classified` | `per_tool` / `risk_classified` / `policy_only` |
| `approval_timeout_seconds` | int | 300 | Seconds before timeout (0 = no timeout) |
| `on_timeout` | enum | `deny` | `deny` or `approve` when timeout occurs |
| `allow_edit` | bool | true | Allow operator to edit args before approving |
| `max_denials` | int | 3 | Consecutive denials before auto-pausing the flow |
| `risk_tools` | []string | [] | Explicit list of tools requiring approval (overrides classifier) |
| `executor_backend` | string | `docker` | `docker` or `openshell` |

### Modes

- **`per_tool`**: Every tool call requires approval. Use for high-assurance scenarios.
- **`risk_classified`**: Only medium/high/blocked risk tools require approval. Default.
- **`policy_only`**: No manual approvals; relies solely on sandbox policy enforcement.

### Risk Classification

Tools are classified by file path patterns in their arguments:

| Risk | Examples |
|------|----------|
| Low | Read-only operations, `ls`, `cat`, info gathering |
| Medium | File writes to non-sensitive paths, network scans |
| High | System file modifications, credential access, kernel operations |
| Blocked | Operations that should never execute (e.g., `rm -rf /`) |

## REST API

### Decide an Approval

```bash
curl -X POST https://localhost:8443/api/v1/flows/{flowId}/approvals/{approvalId}/decide \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "decision": "approved",
    "edited_args": null,
    "reason": "Looks safe to proceed"
  }'
```

### Pause a Flow

```bash
curl -X POST https://localhost:8443/api/v1/flows/{flowId}/pause \
  -H "Authorization: Bearer <token>"
```

### Resume a Flow

```bash
curl -X POST https://localhost:8443/api/v1/flows/{flowId}/resume \
  -H "Authorization: Bearer <token>"
```

### Inject Command (501 — Not Implemented)

```bash
curl -X POST https://localhost:8443/api/v1/flows/{flowId}/inject \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"command": "whoami"}'
```

> **Note:** `InjectCommand` is deferred to a follow-up release. It requires injecting a synthetic tool-call response into a live LLM message chain.

## GraphQL API

### Mutation: Decide Approval

```graphql
mutation {
  decideToolApproval(
    approvalId: "42"
    decision: approved
    editedArgs: null
    reason: "Proceed"
  ) {
    id decision decidedAt
  }
}
```

### Query: List Approvals

```graphql
query {
  toolApprovals(flowId: "1") {
    id toolName riskClass decision args requestedAt decidedAt
  }
}
```

### Subscription: Real-Time Approval Events

```graphql
subscription {
  toolApprovalRequested(flowId: "1") {
    id toolName args riskClass
  }
}
```

## Executor Backends

### Docker (Default)

The default backend uses Docker containers for sandboxed execution. No additional configuration needed beyond the standard `DOCKER_*` environment variables.

### NVIDIA OpenShell

OpenShell provides policy-governed sandboxes with fine-grained filesystem, network, and process controls.

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSHELL_ENABLED` | `false` | Enable OpenShell backend |
| `OPENSHELL_HOST` | `localhost` | OpenShell daemon host |
| `OPENSHELL_SSH_PORT` | `22` | SSH port for data plane |
| `OPENSHELL_SSH_USER` | `agent` | SSH user for sandbox access |
| `OPENSHELL_SSH_KEY_PATH` | (required) | Path to SSH private key |
| `OPENSHELL_KNOWN_HOSTS_PATH` | (required) | Path to known_hosts file |
| `OPENSHELL_CLI_PATH` | `openshell` | Path to openshell CLI binary |
| `OPENSHELL_DEFAULT_PRESET` | `web_pentest` | Default sandbox policy preset |

> **Security:** `OPENSHELL_KNOWN_HOSTS_PATH` is required. The backend refuses to start without host-key verification configured.

**Policy Presets:**

- `web_pentest` — Full network, pentest tools, filesystem write in /tmp and /home
- `recon_only` — Reconnaissance only, limited writes, no mail ports
- `binary_analysis` — No network, isolated filesystem for malware analysis

### Adding a New Executor Backend

1. Create `backend/pkg/executor/<name>/backend.go` implementing `executor.Backend`.
2. The interface methods mirror Docker's exec/copy API surface:
   - `ContainerExecCreate` / `ContainerExecAttach` / `ContainerExecInspect` — command execution
   - `CopyToContainer` / `CopyFromContainer` — file transfer (tar format)
   - `IsContainerRunning` — health check
   - `GetDefaultImage` — default sandbox image/preset
3. Add config fields to `pkg/config/config.go`.
4. Wire the backend into `pkg/controller/flow.go` by conditionally constructing it based on the flow's `hitl.Config.ExecutorBackend` value.

## Denial-Loop Guard

If an operator denies `max_denials` consecutive tool calls for a flow, the system automatically:
1. Sets the flow status to `waiting` (paused).
2. Returns a special error to the agent indicating it should stop.
3. The operator must explicitly resume the flow via `/resume` or the GraphQL mutation.

## Recovery on Restart

On server startup, the dispatcher queries `tool_approvals` for any rows with `decision = 'pending'`. These are re-emitted as `toolApprovalRequested` events so the frontend immediately shows them.

## Database Schema

The `tool_approvals` table stores the audit trail:

```sql
CREATE TABLE tool_approvals (
    id            BIGSERIAL PRIMARY KEY,
    flow_id       BIGINT NOT NULL REFERENCES flows(id),
    task_id       BIGINT REFERENCES tasks(id),
    tool_call_id  TEXT NOT NULL,
    tool_name     TEXT NOT NULL,
    args          JSONB NOT NULL,
    risk_class    risk_class NOT NULL DEFAULT 'low',
    decision      tool_approval_decision NOT NULL DEFAULT 'pending',
    edited_args   JSONB,
    reason        TEXT,
    decided_by    BIGINT REFERENCES users(id),
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at    TIMESTAMPTZ
);
```
