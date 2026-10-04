import { describe, expect, it } from 'vitest';

import { HitlMode, RiskClass } from '@/graphql/types';

import { toRunOptionVariables } from './flow-run-options-variables';

describe('toRunOptionVariables', () => {
    it('sends no override when everything is left at the server default', () => {
        expect(toRunOptionVariables({})).toEqual({ hitl: undefined, sandbox: undefined });
        expect(toRunOptionVariables({ hitlMode: HitlMode.Off })).toEqual({ hitl: undefined, sandbox: undefined });
    });

    it('asks only from medium risk up for the risky-tools mode', () => {
        const { hitl } = toRunOptionVariables({ hitlMode: HitlMode.RiskClassified });

        expect(hitl).toMatchObject({
            allowEdit: true,
            maxDenials: 3,
            minRisk: RiskClass.Medium,
            mode: 'risk_classified',
        });
    });

    it('gates every tool in the all-tools mode without a risk threshold', () => {
        const { hitl } = toRunOptionVariables({ hitlMode: HitlMode.AllTools });

        expect(hitl?.mode).toBe('all_tools');
        expect(hitl?.minRisk).toBeUndefined();
    });

    it('carries the policy preset only for the OpenShell backend', () => {
        expect(toRunOptionVariables({ sandboxBackend: 'openshell', sandboxProfile: 'recon_only' }).sandbox).toEqual({
            backend: 'openshell',
            profile: 'recon_only',
        });
        expect(toRunOptionVariables({ sandboxBackend: 'docker', sandboxProfile: 'recon_only' }).sandbox).toEqual({
            backend: 'docker',
            profile: undefined,
        });
    });
});
