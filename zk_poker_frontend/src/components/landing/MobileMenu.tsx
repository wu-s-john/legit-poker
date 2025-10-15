'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { X } from 'lucide-react';

interface MobileMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function MobileMenu({ isOpen, onClose }: MobileMenuProps) {
  // Prevent body scroll when menu is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden"
        onClick={onClose}
      />

      {/* Menu Panel */}
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-sm bg-primary-900 shadow-2xl md:hidden">
        <div className="flex h-full flex-col">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-primary-800 p-6">
            <span className="text-xl font-bold text-white">Menu</span>
            <button
              onClick={onClose}
              className="rounded-lg p-2 text-primary-300 transition-colors hover:bg-primary-800 hover:text-white"
            >
              <X className="h-6 w-6" />
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="flex-1 overflow-y-auto p-6">
            <div className="space-y-1">
              <Link
                href="#play"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Play
              </Link>
              <Link
                href="#why-different"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Why different
              </Link>
              <Link
                href="#why-now"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Why now
              </Link>
              <Link
                href="#whitepaper"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Whitepaper
              </Link>
              <Link
                href="#investors"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Investors
              </Link>
            </div>

            {/* Divider */}
            <div className="my-6 border-t border-primary-800" />

            {/* Auth Links */}
            <div className="space-y-3">
              <Link
                href="/login"
                onClick={onClose}
                className="block rounded-lg px-4 py-3 text-center text-base font-medium text-white transition-colors hover:bg-primary-800"
              >
                Login
              </Link>
              <Link
                href="/signup"
                onClick={onClose}
                className="block rounded-lg border-2 border-primary-400 px-4 py-3 text-center text-base font-semibold text-primary-400 transition-colors hover:bg-primary-400/10"
              >
                Sign up
              </Link>
              <Link
                href="/demo"
                onClick={onClose}
                className="block rounded-lg bg-danger px-4 py-3 text-center text-base font-semibold text-white transition-colors hover:bg-danger/90"
              >
                Play Demo
              </Link>
            </div>
          </nav>
        </div>
      </div>
    </>
  );
}
