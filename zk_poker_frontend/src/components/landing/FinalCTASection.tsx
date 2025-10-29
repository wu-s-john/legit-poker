"use client";

import Link from "next/link";
import { Play, FileText } from "lucide-react";

interface FinalCTASectionProps {
  isVisible: boolean;
}

export function FinalCTASection({ isVisible }: FinalCTASectionProps) {
  return (
    <section className="from-primary-800 via-primary-900 to-primary-950 bg-gradient-to-br py-16 md:py-24">
      <div
        className={`mx-auto max-w-4xl px-4 text-center sm:px-6 transition-all duration-1000 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <h2 className="mb-6 text-3xl font-bold text-white md:text-4xl lg:text-5xl">
          Ready to Play Poker You Can Trust?
        </h2>

        <p className="text-primary-200 mx-auto mb-8 max-w-2xl text-lg md:mb-12 md:text-xl">
          See the difference for yourself. Try our live demo or dive deep into
          the cryptography.
        </p>

        <div className="flex flex-col justify-center gap-4 sm:flex-row">
          <Link
            href="#demo"
            className="group bg-primary-600 shadow-primary-600/50 hover:bg-primary-500 hover:shadow-primary-500/50 flex items-center justify-center gap-2 rounded-lg px-8 py-4 text-lg font-semibold text-white shadow-lg transition-all duration-300 hover:scale-105 hover:shadow-xl sm:inline-flex"
          >
            <Play className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
            Try Demo
          </Link>

          <Link
            href="/docs/LegitPoker_Shuffle_and_Deal_Whitepaper.pdf"
            className="group border-primary-400 text-primary-100 hover:bg-primary-800/50 flex items-center justify-center gap-2 rounded-lg border-2 px-8 py-4 text-lg font-semibold transition-all duration-300 hover:scale-105 sm:inline-flex"
          >
            <FileText className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
            Read the Whitepaper
          </Link>
        </div>
      </div>
    </section>
  );
}
