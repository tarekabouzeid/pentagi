import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useForm } from 'react-hook-form';
import { describe, expect, it, vi } from 'vitest';

import { HitlMode } from '@/graphql/types';

import type { FlowRunOptionValues } from './flow-run-options-variables';

import { FlowRunOptions } from './flow-run-options';

const settings = vi.hoisted(() => ({ current: null as null | Record<string, unknown> }));

vi.mock('@/providers/system-settings-provider', () => ({
    useOptionalSystemSettings: () => (settings.current ? { isLoading: false, settings: settings.current } : null),
}));

let latest: FlowRunOptionValues = {};

function Harness() {
    const form = useForm<FlowRunOptionValues>({ defaultValues: {} });
    latest = form.watch();

    return <FlowRunOptions control={form.control} />;
}

describe('FlowRunOptions', () => {
    it('offers only the approval choice when the server runs Docker alone', () => {
        settings.current = { sandbox: { backends: ['docker'], defaultBackend: 'docker', openshellPresets: [] } };
        render(<Harness />);

        expect(screen.getByRole('button', { name: 'Tool approval' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Sandbox backend' })).not.toBeInTheDocument();
    });

    it('offers the approval choice even without any server settings', () => {
        settings.current = null;
        render(<Harness />);

        expect(screen.getByRole('button', { name: 'Tool approval' })).toHaveTextContent('No approval');
    });

    it('records the chosen approval mode in the form', async () => {
        settings.current = null;
        render(<Harness />);

        await userEvent.click(screen.getByRole('button', { name: 'Tool approval' }));
        await userEvent.click(await screen.findByText('Approve risky tools'));

        expect(latest.hitlMode).toBe(HitlMode.RiskClassified);
    });

    it('shows the policy menu only once OpenShell is the chosen backend', async () => {
        settings.current = {
            sandbox: {
                backends: ['docker', 'openshell'],
                defaultBackend: 'docker',
                openshellPresets: ['recon_only', 'web_pentest'],
            },
        };
        render(<Harness />);

        expect(screen.getByRole('button', { name: 'Sandbox backend' })).toHaveTextContent('Docker');
        expect(screen.queryByRole('button', { name: 'Sandbox policy' })).not.toBeInTheDocument();

        await userEvent.click(screen.getByRole('button', { name: 'Sandbox backend' }));
        await userEvent.click(await screen.findByText('OpenShell'));

        expect(latest.sandboxBackend).toBe('openshell');
        expect(screen.getByRole('button', { name: 'Sandbox policy' })).toHaveTextContent('recon_only');
    });
});
