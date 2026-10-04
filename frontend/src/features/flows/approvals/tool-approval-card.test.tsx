import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import type { ToolApprovalFragmentFragment } from '@/graphql/types';

import { AgentType, ApprovalDecision, RiskClass, ToolApprovalStatus } from '@/graphql/types';

import ToolApprovalCard from './tool-approval-card';

const base: ToolApprovalFragmentFragment = {
    agent: AgentType.Pentester,
    args: '{"input":"nmap target"}',
    assistantId: null,
    decidedAt: null,
    decidedBy: null,
    editedArgs: null,
    flowId: '1',
    id: '7',
    reason: '',
    requestedAt: '2026-01-01T00:00:00Z',
    riskClass: RiskClass.High,
    riskReason: 'network scanning tool (nmap)',
    status: ToolApprovalStatus.Pending,
    subtaskId: null,
    taskId: null,
    toolCallId: 'call-1',
    toolName: 'terminal',
};

describe('ToolApprovalCard', () => {
    it('submits the plain decision when the operator approves', async () => {
        const onDecide = vi.fn().mockResolvedValue(undefined);
        render(
            <ToolApprovalCard
                approval={base}
                onDecide={onDecide}
                pending
            />,
        );

        await userEvent.click(screen.getByRole('button', { name: 'Approve' }));

        expect(onDecide).toHaveBeenCalledWith(ApprovalDecision.Approved, undefined);
    });

    it('sends the edited arguments as an edited decision', async () => {
        const onDecide = vi.fn().mockResolvedValue(undefined);
        render(
            <ToolApprovalCard
                approval={base}
                onDecide={onDecide}
                pending
            />,
        );

        await userEvent.click(screen.getByRole('button', { name: 'Edit arguments' }));
        const box = screen.getByLabelText('Edited tool arguments');
        await userEvent.clear(box);
        await userEvent.type(box, '{{"input":"nmap -T2 target"}');
        await userEvent.click(screen.getByRole('button', { name: /approve edited/i }));

        expect(onDecide).toHaveBeenCalledWith(ApprovalDecision.Edited, '{"input":"nmap -T2 target"}');
    });

    it('refuses to submit invalid edited JSON', async () => {
        const onDecide = vi.fn().mockResolvedValue(undefined);
        render(
            <ToolApprovalCard
                approval={base}
                onDecide={onDecide}
                pending
            />,
        );

        await userEvent.click(screen.getByRole('button', { name: 'Edit arguments' }));
        const box = screen.getByLabelText('Edited tool arguments');
        await userEvent.clear(box);
        await userEvent.type(box, 'not json');
        await userEvent.click(screen.getByRole('button', { name: /approve edited/i }));

        expect(onDecide).not.toHaveBeenCalled();
        expect(screen.getByText('Edited arguments must be valid JSON')).toBeInTheDocument();
    });

    it('shows no decision controls once the request is no longer pending', () => {
        render(
            <ToolApprovalCard
                approval={{ ...base, status: ToolApprovalStatus.Denied }}
                onDecide={vi.fn()}
                pending={false}
            />,
        );

        expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
        expect(screen.getByText('denied')).toBeInTheDocument();
    });

    it('surfaces a decision failure without crashing', async () => {
        const onDecide = vi.fn().mockRejectedValue(new Error('flow is gone'));
        render(
            <ToolApprovalCard
                approval={base}
                onDecide={onDecide}
                pending
            />,
        );

        await userEvent.click(screen.getByRole('button', { name: 'Deny' }));

        await waitFor(() => expect(screen.getByText('flow is gone')).toBeInTheDocument());
    });
});
