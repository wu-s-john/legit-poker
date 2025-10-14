import type { Metadata } from 'next';
import { announcementRibbon } from '~/lib/ctaConfig';
import { LaunchUpdatesButton } from '~/components/landing/LaunchUpdatesButton';

export const metadata: Metadata = {
  title: 'Launch announcements | ProofPlay',
};

const { page: launchUpdates } = announcementRibbon;

export default function LaunchUpdatesPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-950 via-primary-900 to-primary-800">
      <div className="mx-auto flex max-w-3xl flex-col items-center px-6 pb-24 pt-16 text-center text-primary-100">
        <span className="text-sm font-semibold uppercase tracking-wide text-primary-400">
          Launch updates
        </span>
        <h1 className="mt-4 text-4xl font-bold text-white md:text-5xl">
          {launchUpdates.title}
        </h1>
        <p className="mt-6 text-lg text-primary-200 md:text-xl">
          {launchUpdates.description}
        </p>
        <ul className="mt-8 space-y-2 text-left text-primary-200">
          <li className="flex items-start gap-3">
            <span className="mt-1 h-2 w-2 rounded-full bg-primary-400" aria-hidden="true" />
            <span>Private beta table invites as soon as ProofPlay shuffles its first deck.</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="mt-1 h-2 w-2 rounded-full bg-primary-400" aria-hidden="true" />
            <span>Investor brief with performance metrics, compliance roadmap, and technical milestones.</span>
          </li>
          <li className="flex items-start gap-3">
            <span className="mt-1 h-2 w-2 rounded-full bg-primary-400" aria-hidden="true" />
            <span>Early reads on protocol upgrades, tournaments, and community events.</span>
          </li>
        </ul>
        <LaunchUpdatesButton />
      </div>
    </div>
  );
}
