'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Menu } from 'lucide-react';
import { MobileMenu } from './MobileMenu';

export function LandingNav() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <>
      <header className="sticky top-0 z-50 border-b border-primary-800 bg-primary-950/95 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
        {/* Left: Logo + Brand */}
        <Link href="/" className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-felt">
            <span className="text-xl font-bold text-white">LP</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-xl font-bold text-white">Legit Poker</span>
            <span className="hidden text-sm text-primary-300 sm:inline">
              by BASIS LABS
            </span>
          </div>
        </Link>

        {/* Center: Nav Links (hidden on mobile) */}
        <nav className="hidden items-center gap-8 md:flex">
          <Link
            href="#play"
            className="text-sm font-medium text-white underline underline-offset-4 transition-colors hover:text-primary-400"
          >
            Play
          </Link>
          <Link
            href="#why-different"
            className="text-sm font-medium text-white underline underline-offset-4 transition-colors hover:text-primary-400"
          >
            Why different
          </Link>
          <Link
            href="#why-now"
            className="text-sm font-medium text-white underline underline-offset-4 transition-colors hover:text-primary-400"
          >
            Why now
          </Link>
          <Link
            href="#whitepaper"
            className="text-sm font-medium text-white underline underline-offset-4 transition-colors hover:text-primary-400"
          >
            Whitepaper
          </Link>
          <Link
            href="#investors"
            className="text-sm font-medium text-white underline underline-offset-4 transition-colors hover:text-primary-400"
          >
            Investors
          </Link>
        </nav>

        {/* Right: Auth + CTA */}
        <div className="flex items-center gap-3">
          <Link
            href="/login"
            className="hidden px-4 py-2 text-sm font-medium text-white transition-colors hover:text-primary-400 sm:inline-flex"
          >
            Login
          </Link>

          <Link
            href="/signup"
            className="hidden items-center rounded-lg border-2 border-primary-400 px-4 py-2 text-sm font-semibold text-primary-400 transition-colors hover:bg-primary-400/10 sm:inline-flex"
          >
            Sign up
          </Link>

          <Link
            href="/demo"
            className="hidden items-center rounded-lg bg-danger px-6 py-2 text-sm font-semibold text-white transition-colors hover:bg-danger/90 sm:inline-flex"
          >
            Play Demo
          </Link>

          <button
            onClick={() => setIsMobileMenuOpen(true)}
            className="p-2 text-white md:hidden"
            aria-label="Open menu"
          >
            <Menu className="h-6 w-6" />
          </button>
        </div>
      </div>
    </header>

      <MobileMenu
        isOpen={isMobileMenuOpen}
        onClose={() => setIsMobileMenuOpen(false)}
      />
    </>
  );
}
