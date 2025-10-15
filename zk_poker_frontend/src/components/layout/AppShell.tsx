'use client';

import { TopBar } from '~/components/layout/TopBar';
import { ToastHost } from '~/components/common/ToastHost';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const isLandingPage = pathname === '/';

  return (
    <div className="min-h-screen bg-primary-950">
      {!isLandingPage && <TopBar />}
      <main className="flex-1">
        {children}
      </main>
      <ToastHost />
    </div>
  );
}
