import { ShieldAlert } from 'lucide-react';
import { useMemo } from 'react';

import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty';
import { useToolApprovalsQuery } from '@/graphql/types';
import { useAutoScroll } from '@/hooks/use-auto-scroll';
import { useFlow } from '@/providers/flow-provider';

import ToolApprovalCard from './tool-approval-card';

const FlowApprovals = () => {
    const { flowId } = useFlow();

    const { data } = useToolApprovalsQuery({
        fetchPolicy: 'cache-first',
        nextFetchPolicy: 'cache-first',
        skip: !flowId,
        variables: { flowId: flowId ?? '' },
    });

    const approvals = useMemo(() => data?.toolApprovals ?? [], [data?.toolApprovals]);

    const { containerRef, endRef } = useAutoScroll(approvals, flowId);

    if (approvals.length === 0) {
        return (
            <Empty>
                <EmptyMedia>
                    <ShieldAlert className="size-10" />
                </EmptyMedia>
                <EmptyContent>
                    <EmptyHeader>
                        <EmptyTitle>No Approvals</EmptyTitle>
                        <EmptyDescription>
                            No tool approval requests have been made for this flow yet.
                        </EmptyDescription>
                    </EmptyHeader>
                </EmptyContent>
            </Empty>
        );
    }

    return (
        <div className="flex h-full flex-col" ref={containerRef}>
            <div className="space-y-3 p-4">
                {approvals.map((approval) => (
                    <ToolApprovalCard approval={approval} key={approval.id} />
                ))}
                <div ref={endRef} />
            </div>
        </div>
    );
};

export default FlowApprovals;
