import Link from 'next/link';
import { Play, Trophy, User, Shield } from 'lucide-react';
import { AnnouncementRibbon } from '~/components/landing/AnnouncementRibbon';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-950 via-primary-900 to-primary-800">
      <div className="pb-24">
        <AnnouncementRibbon />

        <div className="mx-auto max-w-5xl px-6">
          <section className="mt-8 space-y-6 text-center">
            <div className="flex flex-col items-center justify-center gap-3 md:flex-row">
              <Shield className="h-12 w-12 text-primary-400" />
              <h1 className="text-5xl font-bold text-white md:text-6xl">
                Proof<span className="text-primary-400">Play</span>
              </h1>
            </div>

            <p className="mx-auto max-w-2xl text-lg text-primary-200 md:text-xl">
              Experience the future of online poker with zero-knowledge proof technology.
              Play with complete privacy and mathematical guarantees.
            </p>
          </section>

          <section className="mt-12 grid gap-6 md:grid-cols-3">
            <div className="rounded-lg border border-primary-700 bg-primary-800/50 p-6 backdrop-blur-sm">
              <Shield className="mb-4 h-8 w-8 text-primary-400" />
              <h3 className="mb-2 text-lg font-semibold text-white">Zero-Knowledge Proofs</h3>
              <p className="text-sm text-primary-300">
                Mathematical guarantees that your actions are valid without revealing your strategy.
              </p>
            </div>

            <div className="rounded-lg border border-primary-700 bg-primary-800/50 p-6 backdrop-blur-sm">
              <Play className="mb-4 h-8 w-8 text-primary-400" />
              <h3 className="mb-2 text-lg font-semibold text-white">Real-Time Gaming</h3>
              <p className="text-sm text-primary-300">
                Lightning-fast gameplay with instant verification and seamless user experience.
              </p>
            </div>

            <div className="rounded-lg border border-primary-700 bg-primary-800/50 p-6 backdrop-blur-sm">
              <Trophy className="mb-4 h-8 w-8 text-primary-400" />
              <h3 className="mb-2 text-lg font-semibold text-white">Fair Play</h3>
              <p className="text-sm text-primary-300">
                Provably fair games with transparent verification and no possibility of cheating.
              </p>
            </div>
          </section>

          <div className="mt-12 flex flex-col gap-4 sm:flex-row sm:justify-center">
            <Link
              href="/lobby"
              className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-8 py-3 font-semibold text-white transition-colors hover:bg-primary-500"
            >
              <Play className="h-5 w-5" />
              Play Now
            </Link>

            <Link
              href="/profile"
              className="inline-flex items-center gap-2 rounded-lg bg-primary-800 px-8 py-3 font-semibold text-primary-200 transition-colors hover:bg-primary-700"
            >
              <User className="h-5 w-5" />
              View Profile
            </Link>
          </div>

          <div className="mt-16 grid gap-8 text-center sm:grid-cols-3">
            <div>
              <div className="text-3xl font-bold text-primary-400">1000+</div>
              <div className="text-sm text-primary-300">Active Players</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-primary-400">50+</div>
              <div className="text-sm text-primary-300">Tables Running</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-primary-400">99.9%</div>
              <div className="text-sm text-primary-300">Uptime</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
