"use client";

interface ThreePillarsSectionProps {
  isVisible: boolean;
}

export function ThreePillarsSection({ isVisible }: ThreePillarsSectionProps) {
  return (
    <section className="bg-primary-950 py-16 md:py-24">
      <div
        className={`mx-auto max-w-7xl px-4 sm:px-6 transition-all duration-1000 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <h2 className="mb-12 text-center text-3xl font-bold text-white md:text-4xl lg:text-5xl">
          What Makes LegitPoker Different
        </h2>

        <div className="grid grid-cols-1 gap-8 md:grid-cols-2 lg:grid-cols-3">
          {/* Provably Fair Shuffles */}
          <div className="flex flex-col items-center rounded-xl border border-primary-700 bg-primary-800/50 p-8 text-center backdrop-blur-sm transition-all duration-300 hover:border-primary-500 hover:bg-primary-800/70">
            <div className="mb-4 text-6xl">🛡️</div>
            <h3 className="mb-4 text-xl font-bold text-white">
              Provably Fair Shuffles
            </h3>
            <p className="text-primary-300 leading-relaxed">
              Every deal verified on-chain using Multi-Party Computation and
              Zero-Knowledge Proofs— cards no one can peek, even us.
            </p>
          </div>

          {/* One Person, One Account */}
          <div className="flex flex-col items-center rounded-xl border border-primary-700 bg-primary-800/50 p-8 text-center backdrop-blur-sm transition-all duration-300 hover:border-primary-500 hover:bg-primary-800/70">
            <div className="mb-4 text-6xl">🤖❌</div>
            <h3 className="mb-4 text-xl font-bold text-white">
              One Person, One Account
            </h3>
            <p className="text-primary-300 leading-relaxed">
              Proof-of-Unique-Humanity onboarding + biometric login stops bots
              and collusion.
            </p>
          </div>

          {/* 2.5% Rake */}
          <div className="flex flex-col items-center rounded-xl border border-primary-700 bg-primary-800/50 p-8 text-center backdrop-blur-sm transition-all duration-300 hover:border-primary-500 hover:bg-primary-800/70">
            <div className="mb-4 text-6xl">💰</div>
            <h3 className="mb-4 text-xl font-bold text-white">
              2.5% Rake
            </h3>
            <p className="text-primary-300 leading-relaxed">
              Half the industry standard. Keep more of what you win. Doubles
              the number of profitable players.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
