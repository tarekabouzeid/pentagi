import type { HitlConfigInput, SandboxConfigInput } from '@/graphql/types';

import { HitlMode, RiskClass } from '@/graphql/types';

export interface FlowRunOptionValues {
    hitlMode?: HitlMode;
    sandboxBackend?: string;
    sandboxProfile?: string;
}

// The approval policy a mode choice stands for. "Risky tools" asks from medium
// risk up, so a plain `ls` runs unattended but a scan or a write waits.
const hitlByMode: Record<HitlMode, HitlConfigInput | undefined> = {
    [HitlMode.AllTools]: {
        allowEdit: true,
        maxDenials: 3,
        mode: HitlMode.AllTools,
        onTimeout: 'deny',
        timeoutSeconds: 300,
    },
    [HitlMode.Off]: undefined,
    [HitlMode.RiskClassified]: {
        allowEdit: true,
        maxDenials: 3,
        minRisk: RiskClass.Medium,
        mode: HitlMode.RiskClassified,
        onTimeout: 'deny',
        timeoutSeconds: 300,
    },
};

// toRunOptionVariables maps the form's run options onto createFlow's `hitl`
// and `sandbox` arguments, leaving each undefined when the operator left it at
// the server default so the request carries no override at all.
export function toRunOptionVariables(values: FlowRunOptionValues): {
    hitl: HitlConfigInput | undefined;
    sandbox: SandboxConfigInput | undefined;
} {
    const hitl = values.hitlMode ? hitlByMode[values.hitlMode] : undefined;
    const backend = values.sandboxBackend || undefined;
    const profile = backend === 'openshell' ? values.sandboxProfile || undefined : undefined;

    return { hitl, sandbox: backend || profile ? { backend, profile } : undefined };
}
