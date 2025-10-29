"use client";

import Link from "next/link";
import { Shield, Play } from "lucide-react";

interface InvestorHeroSectionProps {
  isVisible: boolean;
}

export function InvestorHeroSection({ isVisible }: InvestorHeroSectionProps) {
  return (
    <section className="from-primary-950 via-primary-900 to-primary-800 bg-gradient-to-br pt-12 pb-16 md:pt-16 md:pb-24 lg:pt-24">
      <div
        className={`mx-auto max-w-5xl px-4 text-center transition-all duration-1000 sm:px-6 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <Shield className="text-primary-400 mx-auto mb-6 h-10 w-10 md:h-12 md:w-12" />

        <h1 className="mb-6 text-3xl leading-tight font-bold text-white sm:text-4xl md:text-5xl lg:text-6xl">
          Bringing cryptographic integrity
          <br className="hidden sm:inline" />
          to a $100B market.
        </h1>

        <p className="text-primary-200 mx-auto mb-8 max-w-2xl text-base leading-relaxed md:mb-12 md:text-lg lg:text-xl">
          The first high-performance, trustless poker platform. 2.5% rake
          (half the industry), 1.5s cryptographically fair shuffles, instant
          stablecoin settlements.
        </p>

        <div className="flex flex-col justify-center gap-3 sm:flex-row sm:gap-4">
          <Link
            href="/demo"
            className="group bg-primary-600 shadow-primary-600/50 hover:bg-primary-500 hover:shadow-primary-500/50 flex items-center justify-center gap-2 rounded-lg px-6 py-4 text-base font-semibold text-white shadow-lg transition-all duration-300 hover:scale-105 hover:shadow-xl sm:inline-flex sm:px-8 sm:py-3"
          >
            <Play className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
            Play Demo
          </Link>
          <Link
            href="/docs/LegitPoker_Shuffle_and_Deal_Whitepaper.pdf"
            className="group text-primary-300 hover:text-primary-100 inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-all duration-300 hover:translate-x-1"
          >
            Get the whitepaper
            <span className="transition-transform duration-300 group-hover:translate-x-1">
              →
            </span>
          </Link>
        </div>
      </div>
    </section>
  );
}
