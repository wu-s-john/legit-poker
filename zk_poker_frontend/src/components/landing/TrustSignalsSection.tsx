"use client";

import { TrendingUp, Shield, GraduationCap } from "lucide-react";

interface TrustSignalsSectionProps {
  isVisible: boolean;
}

export function TrustSignalsSection({ isVisible }: TrustSignalsSectionProps) {
  const signals = [
    {
      icon: TrendingUp,
      value: "10,000+",
      label: "Hands Dealt in Beta",
      description: "Real players, real games",
    },
    {
      icon: Shield,
      value: "0",
      label: "Undetected Bots",
      description: "Proof-of-Unique-Humanity works",
    },
    {
      icon: GraduationCap,
      value: "MIT",
      label: "Cryptography Research",
      description: "Built on peer-reviewed science",
    },
  ];

  return (
    <section className="bg-primary-900 py-16 md:py-24">
      <div
        className={`mx-auto max-w-7xl px-4 sm:px-6 transition-all duration-1000 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <div className="grid grid-cols-1 gap-8 md:grid-cols-3">
          {signals.map((signal, index) => (
            <div key={index} className="flex flex-col items-center text-center">
              <signal.icon className="text-primary-400 mb-4 h-12 w-12" />
              <div className="mb-2 text-4xl font-bold text-white md:text-5xl">
                {signal.value}
              </div>
              <div className="mb-2 text-lg font-semibold text-white">
                {signal.label}
              </div>
              <p className="text-primary-300">{signal.description}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
