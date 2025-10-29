"use client";

import { ShieldCheck, Coins, Users } from "lucide-react";

interface BuiltDifferentSectionProps {
  isVisible: boolean;
}

export function BuiltDifferentSection({
  isVisible,
}: BuiltDifferentSectionProps) {
  return (
    <section
      id="why-different"
      className="bg-primary-950 py-12 md:py-20 lg:py-32"
    >
      <div
        className={`mx-auto max-w-6xl px-4 transition-all duration-1000 sm:px-6 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
          BUILT DIFFERENT
        </h2>

        <div className="grid gap-4 sm:grid-cols-2 md:gap-6 lg:grid-cols-4">
          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border p-4 backdrop-blur-sm transition-all duration-300 hover:-translate-y-2 hover:shadow-xl active:scale-95 sm:p-6">
            <ShieldCheck className="text-primary-400 group-hover:text-primary-300 mb-3 h-8 w-8 transition-all duration-300 group-hover:scale-110 sm:mb-4" />
            <h3 className="mb-2 text-base font-semibold text-white sm:text-lg">
              Fairness you can verify
            </h3>
            <p className="text-primary-300 text-sm leading-relaxed">
              1.5s shuffle for 7 players. Every shuffle generates a SNARK. No
              trust required—just math.
            </p>
          </div>

          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border p-4 backdrop-blur-sm transition-all duration-300 hover:-translate-y-2 hover:shadow-xl active:scale-95 sm:p-6">
            <Coins className="text-primary-400 group-hover:text-primary-300 mb-3 h-8 w-8 transition-all duration-300 group-hover:scale-110 sm:mb-4" />
            <h3 className="mb-2 text-base font-semibold text-white sm:text-lg">
              2.5% rake changes everything
            </h3>
            <p className="text-primary-300 text-sm leading-relaxed">
              Half the industry standard means 2x more profitable players.
              From 15% winners to 30% winners.
            </p>
          </div>

          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border p-4 backdrop-blur-sm transition-all duration-300 hover:-translate-y-2 hover:shadow-xl active:scale-95 sm:p-6">
            <Users className="text-primary-400 group-hover:text-primary-300 mb-3 h-8 w-8 transition-all duration-300 group-hover:scale-110 sm:mb-4" />
            <h3 className="mb-2 text-base font-semibold text-white sm:text-lg">
              Real people, real poker
            </h3>
            <p className="text-primary-300 text-sm leading-relaxed">
              Proof-of-unique-humanity onboarding. Biometric login. Periodic
              BeCAPTCHA challenges. Device attestation.
            </p>
          </div>

          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border p-4 backdrop-blur-sm transition-all duration-300 hover:-translate-y-2 hover:shadow-xl active:scale-95 sm:p-6">
            <Coins className="text-primary-400 group-hover:text-primary-300 mb-3 h-8 w-8 transition-all duration-300 group-hover:scale-110 sm:mb-4" />
            <h3 className="mb-2 text-base font-semibold text-white sm:text-lg">
              Instant settlements
            </h3>
            <p className="text-primary-300 text-sm leading-relaxed">
              Stablecoin cash-ins and payouts settle in minutes, not weeks.
              Publicly verifiable escrow reserves.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
