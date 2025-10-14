'use client';

import Link from 'next/link';
import { ArrowUpRight } from 'lucide-react';
import { announcementRibbon } from '~/lib/ctaConfig';
import { trackEvent } from '~/lib/analytics';

export function LaunchUpdatesButton() {
  const { page } = announcementRibbon;

  const handleClick = () => {
    trackEvent(page.analyticsEvent, { href: page.typeformUrl });
  };

  return (
    <Link
      href={page.typeformUrl}
      target="_blank"
      rel="noopener noreferrer"
      onClick={handleClick}
      className="mt-10 inline-flex items-center gap-2 rounded-full bg-primary-400 px-8 py-3 font-semibold text-primary-950 transition-colors hover:bg-primary-300 focus:outline-none focus-visible:ring-4 focus-visible:ring-[#55D6A988] focus-visible:ring-offset-2 focus-visible:ring-offset-primary-900"
    >
      {page.ctaLabel}
      <ArrowUpRight className="h-5 w-5" aria-hidden="true" />
    </Link>
  );
}
