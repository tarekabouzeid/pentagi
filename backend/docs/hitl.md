# Human-in-the-Loop Approvals and Sandbox Backends

This document describes two per-flow controls an operator can set when a flow is created: whether the agents' tool calls wait for a human decision, and which sandbox runtime the flow's tools run in.

## Overview

A flow's agents act through tools: the terminal runs commands in the sandbox, the file tool reads and writes files there, and the rest delegate, search and remember. Without an approval policy a flow runs unattended. With one, a tool call that matches the policy is stored, announced to the operator, and held until the operator approves, edits or denies it.

```text
agent chain ─► execToolCall ─► HITL gate ─► classify risk ─► policy asks? ─┬─ no ─► run the tool
                                                                           └─ yes ─► tool_approvals row (pending)
                                                                                      │ announce (subscription)
operator ─► Approvals tab / GraphQL / REST ─► decide ─────────────────────────────────┘ wake the agent
```

The gate sits in `flowProvider.execToolCall`, which every agent chain runs through, so the flow's agents and its assistant are covered by one policy. The code is in `backend/pkg/hitl`.

## Policy

The policy is stored under `hitl` in the flow's functions, so it is fixed when the flow is created and survives a restart. A flow stored without one runs unattended. The policy is validated when the flow is created: an unknown mode, risk or timeout action, or a negative number, rejects the request instead of silently running the flow unattended.

| Field | Values | Default | Meaning |
|---|---|---|---|
| `mode` | `off`, `risk_classified`, `all_tools` | `off` | `risk_classified` asks for calls at or above `min_risk`; `all_tools` asks for every sandbox call (terminal and file), and for any other tool named in `tools` |
| `min_risk` | `low`, `medium`, `high`, `blocked` | `high` | Threshold for `risk_classified` |
| `tools` | tool names | none | In `risk_classified` mode, gate only these tools whatever their risk; in `all_tools` mode, also gate these non-sandbox tools |
| `timeout_seconds` | integer | `0` | Seconds to wait for a decision; `0` waits indefinitely |
| `on_timeout` | `deny`, `approve` | `deny` | What a request that nobody decided becomes |
| `allow_edit` | boolean | `false` | Whether an operator may replace the agent's arguments; an edit on a flow that does not allow it is refused and the request stays pending |
| `max_denials` | integer | `0` | Consecutive denials after which the flow is paused; `0` disables the pause |

A call classified `blocked` is always gated, even in `off` mode, so an operator can see and refuse it. In `risk_classified` mode a call is gated only if the policy covers it; an unrecognised mode gates the call rather than letting it through.

The web UI offers three choices on a new automation flow: no approval, approve risky tools (`risk_classified`, `min_risk` medium, 300 second timeout that denies, edits allowed, pause after 3 denials) and approve every tool (`all_tools`, same timeout and budget).

## Risk classification

The classifier reads the arguments of sandbox tools (`terminal`, `file`); every other tool is an orchestration step and is `low`. The rules run in this order and the first match wins. The reason is stored on the approval and shown to the operator.

| Risk | Matches |
|---|---|
| `blocked` | Destructive or host-takeover commands: `rm -rf /`, `mkfs`, `dd if=`, writes to `/dev/sd*`, a fork bomb, `shutdown`/`reboot`/`halt`/`poweroff`, `chown -R`, reading `/etc/shadow` |
| `high` | Reverse shells and piping content into an interpreter, active exploitation or cracking tools (`sqlmap`, `hydra`, `john`, `hashcat`, `metasploit`, `msfconsole`, `crackmapexec`, `responder`, `mimikatz`), a state-changing HTTP request against an authentication endpoint, file writes under `/etc`, `/root`, `/usr`, `.ssh`, shell start-up files and similar, and any call whose arguments cannot be parsed |
| `medium` | Network scanners (`nmap`, `masscan`, `nikto`, `gobuster`, `ffuf`, `nuclei`, `wpscan`, ...), outbound network commands (`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, ...), detached background commands, other commands with side effects, other file writes |
| `low` | Read-only commands (`ls`, `cat`, `grep`, `find`, `id`, `ps`, ...) and file reads |

The classifier is a heuristic over the command text. It does not understand shell: a command that is assembled at run time, encoded, or hidden in a script the agent wrote earlier can be classified lower than it deserves. Treat it as a way to put a human in front of the obviously risky calls, not as a security boundary. The boundary is the sandbox, and the policy presets of the OpenShell backend below tighten it. For work where every action must be reviewed, use `all_tools`, which reviews every command and file change the agents make.

## Operator actions

An approval moves from `pending` to exactly one of `approved`, `edited`, `denied`, `timeout` or `cancelled`; a second decision on the same request is refused. An `edited` decision carries replacement arguments, which must be valid JSON, and is accepted only on a flow whose policy sets `allow_edit`.

What the agent sees:

- Approved or edited: the tool runs and returns its normal result.
- Denied, timed out (with `on_timeout: deny`) or cancelled: the tool does not run and the agent receives a `[BLOCKED BY OPERATOR]` result saying so, which it reads and re-plans around. The chain does not fail.
- Denial budget spent: after `max_denials` consecutive denials (a denial streak is broken by an approval or an edit, not by a timeout) the flow is set to `waiting` and the agent receives a `[PAUSED BY OPERATOR]` result telling it to make no further tool calls and report back. The running chain is not force-cancelled; use **Stop** on the flow for that. Send new input to continue the flow.

A request is held in memory by the agent that raised it, so a pending request does not survive a restart: on startup the requests the previous process left pending are marked `cancelled`, and a restored flow asks again if it still needs the call. Likewise a request is cancelled when its flow is finished or stopped, or its chain is cancelled, so the operator is never left deciding a request that no agent is waiting on.

### Web UI

The flow page has an **Approvals** tab listing the flow's requests newest first, each with the tool, its risk and the reason, and the arguments. A pending request offers **Approve**, **Edit** (change the JSON arguments, then **Approve edited**) and **Deny**. New requests and decisions arrive live.

### GraphQL

```graphql
query { toolApprovals(flowId: 5) { id toolName riskClass riskReason status args requestedAt } }
query { pendingToolApprovals(flowId: 5) { id toolName riskClass } }

mutation {
  decideToolApproval(flowId: 5, approvalId: 7, decision: approved, reason: "in scope") { id status decidedBy }
}

subscription { toolApprovalRequested(flowId: 5) { id toolName riskClass args } }
subscription { toolApprovalUpdated(flowId: 5) { id status } }
```

`createFlow` takes the policy and the sandbox choice:

```graphql
mutation {
  createFlow(
    modelProvider: "openai"
    input: "Test https://staging.example.com"
    hitl: { mode: risk_classified, minRisk: medium, timeoutSeconds: 300, onTimeout: "deny", allowEdit: true, maxDenials: 3 }
    sandbox: { backend: "openshell", profile: "recon_only" }
  ) { id }
}
```

### REST

```bash
curl -X POST https://localhost:8443/api/v1/flows \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"input":"Test staging","provider":"openai","functions":{"hitl":{"mode":"risk_classified","min_risk":"medium","allow_edit":true},"sandbox":{"backend":"openshell","profile":"recon_only"}}}'

curl https://localhost:8443/api/v1/flows/5/approvals/ -H "Authorization: Bearer <token>"

curl -X POST https://localhost:8443/api/v1/flows/5/approvals/7/decide \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"decision":"edited","edited_args":{"input":"nmap -T2 target"},"reason":"slower scan"}'
```

### Authorization

Reading approvals needs `flows.view` and deciding needs `flows.edit`, on the caller's own flow; a `flows.admin` caller can act on any flow. GraphQL checks ownership with the same helper as the other flow operations and REST applies the privilege middleware plus the same ownership rule. An approval can only be decided through the flow it belongs to. The deciding user is recorded in `decided_by`. A new privilege for a separate approver role is not part of this change.

## Audit trail

Every request is a row in `tool_approvals`: the flow, task, subtask or assistant and agent it came from, the tool call id and arguments, the risk class and reason, the decision, any edited arguments, the reason given, who decided and when. Rows are kept after the flow is finished, and are removed only if the flow row is physically deleted.

## Sandbox backends

Each flow runs its tools in one sandbox runtime, chosen when the flow is created and stored under `sandbox` in the flow's functions, so the terminal, the Files tab, flow finish and a restart all use the same runtime. A flow stored without a choice is a Docker flow. The runtimes live in `backend/pkg/sandbox`; a backend is anything that satisfies `docker.DockerClient`, so the tools do not change.

| Variable | Default | Meaning |
|---|---|---|
| `EXECUTOR_BACKEND` | `docker` | Runtime new flows use when they do not choose one |
| `OPENSHELL_ENABLED` | `false` | Connect to an OpenShell gateway at startup and offer it as a backend |
| `OPENSHELL_GATEWAY_ADDRESS` | `localhost:8080` | Gateway `host:port`; an `http://` prefix means plaintext |
| `OPENSHELL_WORKSPACE` | `default` | OpenShell workspace the sandboxes are created in |
| `OPENSHELL_TOKEN` | empty | Bearer token for the gateway; masked in logs and agent transcripts |
| `OPENSHELL_TLS_CA_CERT` | empty | CA file for a gateway with a private certificate |
| `OPENSHELL_TLS_INSECURE` | `false` | Skip certificate verification (testing only) |
| `OPENSHELL_DEFAULT_IMAGE` | `vxcontrol/kali-linux` | Image for sandboxes of flows that do not name one |
| `OPENSHELL_DEFAULT_PRESET` | `web_pentest` | Policy preset for flows that do not choose one |

A configured gateway that cannot be reached, or an unknown default preset, stops startup; PentAGI does not silently fall back to Docker. Requesting a backend that is not enabled rejects the flow.

### NVIDIA OpenShell

[OpenShell](https://github.com/NVIDIA/OpenShell) (Apache-2.0) runs each sandbox under a security policy enforced by the gateway. PentAGI talks to the gateway over gRPC with the official Go SDK, creates one sandbox per flow and deletes it when the flow ends. A flow can pick one of three built-in policy presets, offered by the UI when OpenShell is enabled:

| Preset | Posture |
|---|---|
| `web_pentest` | Outbound network, read-only root, writable `/tmp`, `/home`, `/var/tmp` and `/work` |
| `recon_only` | Read-only network access, writable `/tmp` and `/work` |
| `binary_analysis` | No network, writable `/tmp` and `/work` |

Differences from Docker to be aware of:

- Each command is one gateway call. A detached command lives as long as that call, bounded by the terminal timeout; start long-lived services with `nohup` or similar.
- **Stop** ends the commands PentAGI is waiting on, but there is no sweep of leftover processes as there is in Docker.
- Docker-specific container settings (published ports, host Docker access for workers) do not apply, and the image must be pullable by the gateway.
- The Files tab lists directories with `find` and `stat` run inside the sandbox, so the image needs them.

The OpenShell backend is covered by unit tests against fakes of the SDK. It has not been run against a live gateway in CI.

### Adding a backend

See "Adding a New Executor Backend" in `CLAUDE.md`.
