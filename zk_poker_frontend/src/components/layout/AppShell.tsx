'use client';

import { TopBar } from '~/components/layout/TopBar';
import { ToastHost } from '~/components/common/ToastHost';
import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-primary-950">
      <TopBar />
      <main className="flex-1">
        {children}
      </main>
      <ToastHost />
    </div>
  );
}
