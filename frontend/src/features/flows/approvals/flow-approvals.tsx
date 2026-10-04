import { useMutation, useQuery } from '@apollo/client/react';
import { ShieldCheck } from 'lucide-react';
import { useCallback, useMemo } from 'react';
import { toast } from 'sonner';

import type { ApprovalDecision } from '@/graphql/types';

import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty';
import { ScrollArea } from '@/components/ui/scroll-area';
import { DecideToolApprovalDocument, ToolApprovalsDocument, ToolApprovalStatus } from '@/graphql/types';
import { useFlow } from '@/providers/flow-provider';

import ToolApprovalCard from './tool-approval-card';

function FlowApprovals() {
    const { flowId } = useFlow();

    const { data } = useQuery(ToolApprovalsDocument, {
        fetchPolicy: 'cache-and-network',
        skip: !flowId,
        variables: { flowId: flowId ?? '' },
    });

    const [decideMutation] = useMutation(DecideToolApprovalDocument);

    const approvals = useMemo(() => data?.toolApprovals ?? [], [data?.toolApprovals]);

    const decide = useCallback(
        async (approvalId: string, decision: ApprovalDecision, editedArgs?: string) => {
            if (!flowId) {
                return;
            }

            await decideMutation({ variables: { approvalId, decision, editedArgs, flowId } });
            toast.success('Decision submitted');
        },
        [decideMutation, flowId],
    );

    if (approvals.length === 0) {
        return (
            <Empty className="h-full">
                <EmptyHeader>
                    <EmptyMedia variant="icon">
                        <ShieldCheck />
                    </EmptyMedia>
                    <EmptyTitle>No tool approvals</EmptyTitle>
                    <EmptyDescription>
                        When this flow asks for human approval before running a tool, the request appears here.
                    </EmptyDescription>
                </EmptyHeader>
            </Empty>
        );
    }

    return (
        <ScrollArea className="h-full">
            <div
                className="space-y-3 pr-4"
                data-testid="flow-approvals"
            >
                {approvals.map((approval) => (
                    <ToolApprovalCard
                        approval={approval}
                        key={approval.id}
                        onDecide={(decision, editedArgs) => decide(approval.id, decision, editedArgs)}
                        pending={approval.status === ToolApprovalStatus.Pending}
                    />
                ))}
            </div>
        </ScrollArea>
    );
}

export default FlowApprovals;
