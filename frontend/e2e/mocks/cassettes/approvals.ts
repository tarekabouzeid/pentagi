import type { ResultOf } from '@graphql-typed-document-node/core';

import type { DecideToolApprovalDocument, ToolApprovalsDocument } from '@/graphql/types';

import { AgentType, RiskClass, ToolApprovalStatus } from '@/graphql/types';

import type { Cassette } from '../cassette.ts';

import { entity } from '../cassette.ts';
import { flowsCassette } from './flows.ts';

const T = '2026-01-15T11:30:00Z';

export const APPROVAL_ID = '7';
export const APPROVAL_TOOL = 'terminal';
export const APPROVAL_REASON = 'network scanning tool (nmap)';
export const APPROVED_FLAG = 'approval-approved';

const makeApproval = (status: ToolApprovalStatus) =>
    entity('ToolApproval', {
        agent: AgentType.Pentester,
        args: '{"input":"nmap -sV target.invalid"}',
        assistantId: null,
        decidedAt: status === ToolApprovalStatus.Pending ? null : T,
        decidedBy: status === ToolApprovalStatus.Pending ? null : '1',
        editedArgs: null,
        flowId: '5',
        id: APPROVAL_ID,
        reason: '',
        requestedAt: T,
        riskClass: RiskClass.Medium,
        riskReason: APPROVAL_REASON,
        status,
        subtaskId: null,
        taskId: null,
        toolCallId: 'call-e2e-1',
        toolName: APPROVAL_TOOL,
    });

const pending: ResultOf<typeof ToolApprovalsDocument> = { toolApprovals: [makeApproval(ToolApprovalStatus.Pending)] };
const decided: ResultOf<typeof DecideToolApprovalDocument> = {
    decideToolApproval: makeApproval(ToolApprovalStatus.Approved),
};

// A flow with one tool call waiting for approval. Approving it flips the
// server-side flag; the update frame that follows is what turns the card over,
// the way a decision made from another tab would arrive.
export const approvalsCassette = (): Cassette =>
    flowsCassette({
        mutations: {
            decideToolApproval: [
                {
                    data: decided,
                    setFlag: APPROVED_FLAG,
                    variables: { approvalId: APPROVAL_ID, decision: 'approved', flowId: '5' },
                },
            ],
        },
        queries: {
            toolApprovals: [{ data: pending, variables: { flowId: '5' } }],
        },
        subscriptions: {
            toolApprovalUpdated: [
                {
                    frames: [
                        {
                            payload: { data: { toolApprovalUpdated: makeApproval(ToolApprovalStatus.Approved) } },
                            whenFlag: APPROVED_FLAG,
                        },
                    ],
                    variables: { flowId: '5' },
                },
            ],
        },
    });
