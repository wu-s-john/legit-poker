"use client";

import Link from "next/link";

interface InvestorCTASectionProps {
  isVisible: boolean;
}

export function InvestorCTASection({ isVisible }: InvestorCTASectionProps) {
  return (
    <section className="bg-primary-900 py-12 md:py-20 lg:py-32">
      <div
        className={`mx-auto max-w-5xl px-4 text-center sm:px-6 transition-all duration-1000 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <h2 className="mb-6 text-2xl font-bold text-white sm:text-3xl md:mb-8 md:text-4xl">
          Ready to experience cryptographic fairness?
        </h2>

        <div className="flex flex-col justify-center gap-3 sm:flex-row sm:gap-4">
          <Link
            href="/demo"
            className="bg-primary-600 hover:bg-primary-500 flex items-center justify-center gap-2 rounded-lg px-8 py-4 text-base font-semibold text-white transition-colors sm:inline-flex sm:py-3"
          >
            Play Demo
          </Link>
          <Link
            href="/docs/LegitPoker_Shuffle_and_Deal_Whitepaper.pdf"
            className="text-primary-300 hover:text-primary-100 inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors"
          >
            Get Whitepaper
          </Link>
        </div>
      </div>
    </section>
  );
}
