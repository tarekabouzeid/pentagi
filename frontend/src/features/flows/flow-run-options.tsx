import type { Control, FieldValues, Path } from 'react-hook-form';

import { Check, ChevronDown, Server, ShieldCheck } from 'lucide-react';
import { useController } from 'react-hook-form';

import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { InputGroupButton } from '@/components/ui/input-group';
import { HitlMode } from '@/graphql/types';
import { useOptionalSystemSettings } from '@/providers/system-settings-provider';

import type { FlowRunOptionValues } from './flow-run-options-variables';

const approvalLabels: Record<HitlMode, string> = {
    [HitlMode.AllTools]: 'Approve every tool',
    [HitlMode.Off]: 'No approval',
    [HitlMode.RiskClassified]: 'Approve risky tools',
};

const approvalHints: Record<HitlMode, string> = {
    [HitlMode.AllTools]: 'Every sandbox command and file change waits for you',
    [HitlMode.Off]: 'The agents run unattended',
    [HitlMode.RiskClassified]: 'Scans, network calls and writes wait for you; read-only commands run',
};

interface FlowRunOptionsProps<T extends FieldValues & FlowRunOptionValues> {
    control: Control<T>;
    disabled?: boolean;
}

interface OptionMenuProps {
    ariaLabel: string;
    disabled?: boolean;
    icon: React.ReactNode;
    items: Array<{ hint?: string; label: string; value: string }>;
    onChange: (value: string) => void;
    value: string;
}

// FlowRunOptions lets the operator choose, per flow, whether tool calls wait
// for approval and which sandbox backend (and OpenShell policy) the flow runs
// in. The sandbox menus appear only when the server runs more than Docker.
export function FlowRunOptions<T extends FieldValues & FlowRunOptionValues>({
    control,
    disabled,
}: FlowRunOptionsProps<T>) {
    const sandbox = useOptionalSystemSettings()?.settings?.sandbox;

    const { field: hitlField } = useController({ control, name: 'hitlMode' as Path<T> });
    const { field: backendField } = useController({ control, name: 'sandboxBackend' as Path<T> });
    const { field: profileField } = useController({ control, name: 'sandboxProfile' as Path<T> });

    const backends = sandbox?.backends ?? [];
    const backend = (backendField.value as string | undefined) || sandbox?.defaultBackend || 'docker';
    const showBackend = backends.length > 1;
    const showProfile = backend === 'openshell' && (sandbox?.openshellPresets.length ?? 0) > 0;

    return (
        <>
            <OptionMenu
                ariaLabel="Tool approval"
                disabled={disabled}
                icon={<ShieldCheck />}
                items={Object.values(HitlMode).map((mode) => ({
                    hint: approvalHints[mode],
                    label: approvalLabels[mode],
                    value: mode,
                }))}
                onChange={hitlField.onChange}
                value={(hitlField.value as HitlMode | undefined) ?? HitlMode.Off}
            />

            {showBackend && (
                <OptionMenu
                    ariaLabel="Sandbox backend"
                    disabled={disabled}
                    icon={<Server />}
                    items={backends.map((name) => ({
                        label: name === 'openshell' ? 'OpenShell' : 'Docker',
                        value: name,
                    }))}
                    onChange={(value) => {
                        backendField.onChange(value);
                        profileField.onChange(undefined);
                    }}
                    value={backend}
                />
            )}

            {showProfile && sandbox && (
                <OptionMenu
                    ariaLabel="Sandbox policy"
                    disabled={disabled}
                    icon={<ShieldCheck />}
                    items={sandbox.openshellPresets.map((name) => ({ label: name, value: name }))}
                    onChange={profileField.onChange}
                    value={(profileField.value as string | undefined) ?? sandbox.openshellPresets[0] ?? ''}
                />
            )}
        </>
    );
}

function OptionMenu({ ariaLabel, disabled, icon, items, onChange, value }: OptionMenuProps) {
    const current = items.find((item) => item.value === value) ?? items[0];

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <InputGroupButton
                    aria-label={ariaLabel}
                    disabled={disabled}
                    variant="ghost"
                >
                    {icon}
                    <span className="max-w-40 truncate">{current?.label}</span>
                    <ChevronDown />
                </InputGroupButton>
            </DropdownMenuTrigger>
            <DropdownMenuContent
                align="start"
                side="top"
            >
                {items.map((item) => (
                    <DropdownMenuItem
                        key={item.value}
                        onSelect={() => onChange(item.value)}
                    >
                        <div className="flex w-full min-w-0 flex-col">
                            <span className="flex items-center gap-2">
                                <span className="flex-1 truncate">{item.label}</span>
                                {item.value === current?.value && <Check className="size-4 shrink-0" />}
                            </span>
                            {item.hint && <span className="text-muted-foreground text-xs">{item.hint}</span>}
                        </div>
                    </DropdownMenuItem>
                ))}
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
