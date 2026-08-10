import { Check, Edit, ShieldAlert, ShieldCheck, ShieldX, X } from 'lucide-react';
import { useCallback, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import {
    ApprovalDecision,
    RiskClass,
    type ToolApprovalFragmentFragment,
    useDecideToolApprovalMutation,
} from '@/graphql/types';
import { cn } from '@/lib/utils';
import { formatDate } from '@/lib/utils/format';

interface ToolApprovalCardProps {
    approval: ToolApprovalFragmentFragment;
}

const riskClassConfig: Record<RiskClass, { color: string; icon: typeof ShieldAlert; label: string }> = {
    [RiskClass.Blocked]: {
        color: 'bg-red-900/10 text-red-400 border-red-900/20',
        icon: ShieldX,
        label: 'Blocked',
    },
    [RiskClass.High]: { color: 'bg-red-500/10 text-red-500 border-red-500/20', icon: ShieldX, label: 'High' },
    [RiskClass.Low]: { color: 'bg-green-500/10 text-green-500 border-green-500/20', icon: ShieldCheck, label: 'Low' },
    [RiskClass.Medium]: {
        color: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
        icon: ShieldAlert,
        label: 'Medium',
    },
};

const ToolApprovalCard = ({ approval }: ToolApprovalCardProps) => {
    const [isEditing, setIsEditing] = useState(false);
    const [editedArgs, setEditedArgs] = useState(approval.args);
    const [reason, setReason] = useState('');

    const [decideToolApproval, { loading }] = useDecideToolApprovalMutation();

    const isPending = approval.decision === 'pending';
    const riskConfig = riskClassConfig[approval.riskClass];
    const RiskIcon = riskConfig.icon;

    const handleDecision = useCallback(
        async (decision: ApprovalDecision) => {
            try {
                await decideToolApproval({
                    variables: {
                        approvalId: approval.id,
                        decision,
                        editedArgs: decision === ApprovalDecision.Edited ? editedArgs : undefined,
                        reason: reason || undefined,
                    },
                });
                toast.success(`Tool call ${decision}`);
            } catch (error) {
                toast.error(`Failed to submit decision: ${error instanceof Error ? error.message : 'Unknown error'}`);
            }
        },
        [approval.id, decideToolApproval, editedArgs, reason],
    );

    const formatArgs = (args: string) => {
        try {
            return JSON.stringify(JSON.parse(args), null, 2);
        } catch {
            return args;
        }
    };

    return (
        <div
            className={cn(
                'space-y-3 rounded-lg border p-4',
                isPending ? 'border-yellow-500/30 bg-yellow-500/5' : 'border-muted',
            )}
        >
            {/* Header */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <code className="text-sm font-semibold">{approval.toolName}</code>
                    <Badge
                        className={cn('text-xs', riskConfig.color)}
                        variant="outline"
                    >
                        <RiskIcon className="mr-1 size-3" />
                        {riskConfig.label}
                    </Badge>
                    <span className="text-muted-foreground text-xs">{formatDate(new Date(approval.requestedAt))}</span>
                </div>
                {!isPending && (
                    <Badge
                        className="text-xs"
                        variant={
                            approval.decision === 'approved' || approval.decision === 'edited'
                                ? 'default'
                                : 'destructive'
                        }
                    >
                        {approval.decision}
                    </Badge>
                )}
            </div>

            {/* Arguments */}
            <div className="space-y-1">
                <p className="text-muted-foreground text-xs font-medium">Arguments</p>
                {isEditing ? (
                    <Textarea
                        className="font-mono text-xs"
                        onChange={(e) => setEditedArgs(e.target.value)}
                        rows={6}
                        value={editedArgs}
                    />
                ) : (
                    <pre className="bg-muted max-h-48 overflow-auto rounded p-2 text-xs">
                        {formatArgs(approval.args)}
                    </pre>
                )}
            </div>

            {/* Decision actions */}
            {isPending && (
                <div className="space-y-2">
                    <div className="space-y-1">
                        <p className="text-muted-foreground text-xs font-medium">Reason (optional)</p>
                        <Textarea
                            className="text-xs"
                            onChange={(e) => setReason(e.target.value)}
                            placeholder="Add a reason for your decision..."
                            rows={2}
                            value={reason}
                        />
                    </div>
                    <div className="flex items-center gap-2">
                        <Button
                            disabled={loading}
                            onClick={() => handleDecision(ApprovalDecision.Approved)}
                            size="sm"
                            variant="default"
                        >
                            <Check className="mr-1 size-3" />
                            Approve
                        </Button>
                        {isEditing ? (
                            <Button
                                disabled={loading}
                                onClick={() => handleDecision(ApprovalDecision.Edited)}
                                size="sm"
                                variant="secondary"
                            >
                                <Check className="mr-1 size-3" />
                                Approve Edited
                            </Button>
                        ) : (
                            <Button
                                onClick={() => setIsEditing(true)}
                                size="sm"
                                variant="outline"
                            >
                                <Edit className="mr-1 size-3" />
                                Edit
                            </Button>
                        )}
                        <Button
                            disabled={loading}
                            onClick={() => handleDecision(ApprovalDecision.Denied)}
                            size="sm"
                            variant="destructive"
                        >
                            <X className="mr-1 size-3" />
                            Deny
                        </Button>
                        {isEditing && (
                            <Button
                                onClick={() => {
                                    setIsEditing(false);
                                    setEditedArgs(approval.args);
                                }}
                                size="sm"
                                variant="ghost"
                            >
                                Cancel Edit
                            </Button>
                        )}
                    </div>
                </div>
            )}

            {/* Decided info */}
            {!isPending && approval.decidedAt && (
                <p className="text-muted-foreground text-xs">
                    <span className="font-medium">Decided:</span> {formatDate(new Date(approval.decidedAt))}
                </p>
            )}
            {!isPending && approval.reason && (
                <p className="text-muted-foreground text-xs">
                    <span className="font-medium">Reason:</span> {approval.reason}
                </p>
            )}
            {!isPending && approval.editedArgs && (
                <div className="space-y-1">
                    <p className="text-muted-foreground text-xs font-medium">Edited Arguments</p>
                    <pre className="bg-muted max-h-32 overflow-auto rounded p-2 text-xs">
                        {formatArgs(approval.editedArgs)}
                    </pre>
                </div>
            )}
        </div>
    );
};

export default ToolApprovalCard;
