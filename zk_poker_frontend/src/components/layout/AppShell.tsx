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
  const isDebugPage = pathname?.startsWith('/debug');

  // Show LandingNav only on landing page
  // Show TopBar on app pages (lobby, room, etc.) but not on debug pages
  // Show LandingNav on debug pages for consistent navigation
  const showLandingNav = isLandingPage || isDebugPage;
  const showTopBar = !isLandingPage && !isDebugPage;

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
