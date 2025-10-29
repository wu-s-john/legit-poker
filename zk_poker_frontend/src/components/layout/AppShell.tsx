'use client';

import { usePathname } from 'next/navigation';
import { LandingNav } from '~/components/landing/LandingNav';
import { TopBar } from '~/components/layout/TopBar';
import { ToastHost } from '~/components/common/ToastHost';
import type { ReactNode } from 'react';

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const pathname = usePathname();
  const isLandingPage = pathname === '/';
  const isInvestorPage = pathname === '/investor';
  const isDebugPage = pathname?.startsWith('/debug');

  // Show LandingNav on landing page, investor page, and debug pages
  // Show TopBar on app pages (lobby, room, etc.) but not on debug pages
  const showLandingNav = isLandingPage || isInvestorPage || isDebugPage;
  const showTopBar = !isLandingPage && !isInvestorPage && !isDebugPage;

  return (
    <div className="min-h-screen bg-primary-950">
      {showLandingNav && <LandingNav />}
      {showTopBar && <TopBar />}
      <main className="flex-1">
        {children}
      </main>
      <ToastHost />
    </div>
  );
}
