'use client';

import { LandingNav } from '~/components/landing/LandingNav';
import { ToastHost } from '~/components/common/ToastHost';
import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="min-h-screen bg-primary-950">
      <LandingNav />
      <main className="flex-1">
        {children}
      </main>
      <ToastHost />
    </div>
  );
}
