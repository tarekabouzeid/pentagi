import { Check, Pencil, X } from 'lucide-react';
import { useState } from 'react';

import type { ToolApprovalFragmentFragment } from '@/graphql/types';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { ApprovalDecision, RiskClass, ToolApprovalStatus } from '@/graphql/types';
import { cn } from '@/lib/utils';

interface ToolApprovalCardProps {
    approval: ToolApprovalFragmentFragment;
    onDecide: (decision: ApprovalDecision, editedArgs?: string) => Promise<void>;
    pending: boolean;
}

const riskVariant: Record<RiskClass, 'orange' | 'red' | 'secondary' | 'yellow'> = {
    [RiskClass.Blocked]: 'red',
    [RiskClass.High]: 'red',
    [RiskClass.Low]: 'secondary',
    [RiskClass.Medium]: 'yellow',
};

const statusVariant: Record<ToolApprovalStatus, 'blue' | 'green' | 'red' | 'secondary' | 'yellow'> = {
    [ToolApprovalStatus.Approved]: 'green',
    [ToolApprovalStatus.Cancelled]: 'secondary',
    [ToolApprovalStatus.Denied]: 'red',
    [ToolApprovalStatus.Edited]: 'blue',
    [ToolApprovalStatus.Pending]: 'yellow',
    [ToolApprovalStatus.Timeout]: 'secondary',
};

// prettyArgs renders the tool's JSON arguments indented, falling back to the
// raw string when it is not valid JSON.
function prettyArgs(args: string): string {
    try {
        return JSON.stringify(JSON.parse(args), null, 2);
    } catch {
        return args;
    }
}

function ToolApprovalCard({ approval, onDecide, pending }: ToolApprovalCardProps) {
    const [editing, setEditing] = useState(false);
    const [draft, setDraft] = useState(() => prettyArgs(approval.editedArgs ?? approval.args));
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<null | string>(null);

    const decide = async (decision: ApprovalDecision, editedArgs?: string) => {
        setBusy(true);
        setError(null);

        try {
            await onDecide(decision, editedArgs);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to submit the decision');
        } finally {
            setBusy(false);
        }
    };

    const submitEdit = () => {
        try {
            JSON.parse(draft);
        } catch {
            setError('Edited arguments must be valid JSON');

            return;
        }

        void decide(ApprovalDecision.Edited, draft);
    };

    const disabled = busy || !pending;

    return (
        <Card
            className={cn(!pending && 'opacity-70')}
            data-testid="tool-approval-card"
        >
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0">
                <CardTitle className="font-mono text-sm">{approval.toolName}</CardTitle>
                <div className="flex items-center gap-1.5">
                    <Badge variant={riskVariant[approval.riskClass]}>{approval.riskClass}</Badge>
                    <Badge variant={statusVariant[approval.status]}>{approval.status}</Badge>
                </div>
            </CardHeader>
            <CardContent className="space-y-2">
                <p className="text-muted-foreground text-xs">{approval.riskReason}</p>
                {editing ? (
                    <Textarea
                        aria-label="Edited tool arguments"
                        className="min-h-32 font-mono text-xs"
                        onChange={(event) => setDraft(event.target.value)}
                        value={draft}
                    />
                ) : (
                    <pre className="bg-muted max-h-48 overflow-auto rounded-md p-2 font-mono text-xs">
                        {prettyArgs(approval.editedArgs ?? approval.args)}
                    </pre>
                )}
                {approval.reason && <p className="text-muted-foreground text-xs">Reason: {approval.reason}</p>}
                {error && <p className="text-destructive text-xs">{error}</p>}
            </CardContent>
            {pending && (
                <CardFooter className="flex flex-wrap justify-end gap-2">
                    {editing ? (
                        <>
                            <Button
                                disabled={disabled}
                                onClick={() => setEditing(false)}
                                size="sm"
                                variant="ghost"
                            >
                                Cancel
                            </Button>
                            <Button
                                disabled={disabled}
                                onClick={submitEdit}
                                size="sm"
                            >
                                <Check className="mr-1 size-4" /> Approve edited
                            </Button>
                        </>
                    ) : (
                        <>
                            <Button
                                aria-label="Deny"
                                disabled={disabled}
                                onClick={() => void decide(ApprovalDecision.Denied)}
                                size="sm"
                                variant="destructive"
                            >
                                <X className="mr-1 size-4" /> Deny
                            </Button>
                            <Button
                                aria-label="Edit arguments"
                                disabled={disabled}
                                onClick={() => setEditing(true)}
                                size="sm"
                                variant="outline"
                            >
                                <Pencil className="mr-1 size-4" /> Edit
                            </Button>
                            <Button
                                aria-label="Approve"
                                disabled={disabled}
                                onClick={() => void decide(ApprovalDecision.Approved)}
                                size="sm"
                            >
                                <Check className="mr-1 size-4" /> Approve
                            </Button>
                        </>
                    )}
                </CardFooter>
            )}
        </Card>
    );
}

export default ToolApprovalCard;
