'use client';

import Link from 'next/link';
import { trackEvent } from '~/lib/analytics';
import { announcementRibbon } from '~/lib/ctaConfig';

interface AnnouncementRibbonProps {
  readonly className?: string;
}

export function AnnouncementRibbon({ className }: AnnouncementRibbonProps) {
  const { id, badge, teaser, href, analyticsEvent } = announcementRibbon;

  const handleClick = () => {
    trackEvent(analyticsEvent, { id, href });
  };

  return (
    <Link
      href={href}
      onClick={handleClick}
      aria-labelledby={`${id}-label`}
      className={`group block border-b border-[#F3E6C4] bg-[#FFF4D6] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#55D6A988] focus-visible:ring-offset-0 ${className ?? ''}`}
    >
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-start gap-2 px-4 py-1 text-[#614400] transition-colors duration-150 sm:flex-nowrap sm:px-6">
        <span
          className="rounded-full border border-[#E8D48F] bg-[#FFE8A3] px-2 py-px text-xs font-semibold"
          aria-hidden="true"
        >
          {badge}
        </span>
        <span
          id={`${id}-label`}
          className="text-left text-xs font-semibold sm:text-sm group-hover:underline"
        >
          {teaser}
        </span>
      </div>
    </Link>
  );
}
