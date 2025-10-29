"use client";

import { Globe, Zap, Shield, Server, Link2, Handshake } from "lucide-react";

interface FeaturesGridSectionProps {
  isVisible: boolean;
}

export function FeaturesGridSection({ isVisible }: FeaturesGridSectionProps) {
  const features = [
    {
      icon: Globe,
      emoji: "🌍",
      title: "Play Globally for Real Money",
      description:
        "Play anywhere. No geo-restrictions. No centralized entity to freeze accounts.",
    },
    {
      icon: Zap,
      emoji: "⚡",
      title: "Instant Buy-In and Cash-Out",
      description:
        "Deposit. Play. Withdraw. All on-chain. No waiting, no middlemen.",
    },
    {
      icon: Shield,
      emoji: "🛡️",
      title: "Verify Every Hand",
      description:
        "Check shuffle proofs yourself. Every deal is verifiable on-chain. Trust math, not operators.",
    },
    {
      icon: Server,
      emoji: "🎰",
      title: "Earn by Running the Network",
      description:
        "Run a shuffle or keyper node. Earn fees. No minimum stake required.",
    },
    {
      icon: Link2,
      emoji: "🔗",
      title: "Play from Any Chain",
      description:
        "Buy in with ETH, SOL, USDC from any chain. One poker app, any blockchain you prefer.",
    },
    {
      icon: Handshake,
      emoji: "🤝",
      title: "Stake Good Players",
      description:
        "Sponsor skilled players. Share their winnings. Create a new poker economy.",
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
        <h2 className="mb-4 text-center text-3xl font-bold text-white md:text-4xl lg:text-5xl">
          What You Get
        </h2>
        <p className="text-primary-200 mx-auto mb-12 max-w-3xl text-center text-lg md:text-xl">
          More than just poker. A new way to play.
        </p>

        <div className="grid grid-cols-1 gap-8 md:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => (
            <div
              key={index}
              className="group flex flex-col rounded-xl border border-primary-700 bg-primary-800/50 p-8 backdrop-blur-sm transition-all duration-300 hover:border-primary-500 hover:bg-primary-800/70"
            >
              <div className="mb-4 text-5xl">{feature.emoji}</div>
              <h3 className="mb-3 text-xl font-bold text-white">
                {feature.title}
              </h3>
              <p className="text-primary-300 leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
