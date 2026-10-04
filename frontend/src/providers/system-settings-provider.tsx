import type { ReactNode } from 'react';

import { useQuery } from '@apollo/client/react';
import { createContext, use, useMemo } from 'react';

import type { SettingsFragmentFragment } from '@/graphql/types';

import { SettingsDocument } from '@/graphql/types';
import { useUser } from '@/providers/user-provider';

interface SettingsContextType {
    isLoading: boolean;
    settings: null | SettingsFragmentFragment;
}

const SystemSettingsContext = createContext<SettingsContextType | undefined>(undefined);

export function SystemSettingsProvider({ children }: { children: ReactNode }) {
    const { isAuthenticated } = useUser();

    const { data: settingsData, loading } = useQuery(SettingsDocument, {
        skip: !isAuthenticated(),
    });

    const value = useMemo<SettingsContextType>(
        () => ({
            isLoading: loading,
            settings: settingsData?.settings ?? null,
        }),
        [loading, settingsData?.settings],
    );

    return <SystemSettingsContext value={value}>{children}</SystemSettingsContext>;
}

// useOptionalSystemSettings is for UI that adapts to the server's settings but
// must still render, without them, where no provider is mounted.
export function useOptionalSystemSettings() {
    return use(SystemSettingsContext) ?? null;
}

export function useSystemSettings() {
    const context = use(SystemSettingsContext);

    if (context === undefined) {
        throw new Error('useSystemSettings must be used within a SystemSettingsProvider');
    }

    return context;
}
