"use client";

import Link from "next/link";
import { Spade, Lock, GitMerge, Link2, Users } from "lucide-react";
import { InvestorHeroSection } from "~/components/investor/InvestorHeroSection";
import { MarketOpportunitySection } from "~/components/investor/MarketOpportunitySection";
import { BuiltDifferentSection } from "~/components/investor/BuiltDifferentSection";
import { CompetitiveMoatSection } from "~/components/investor/CompetitiveMoatSection";
import { TeamSection } from "~/components/investor/TeamSection";
import { InvestorCTASection } from "~/components/investor/InvestorCTASection";
import { TechnicalAccordion } from "~/components/landing/TechnicalAccordion";
import { DemoSection } from "~/components/landing/DemoSection";
import { useSmoothScroll } from "~/hooks/useSmoothScroll";
import { useScrollAnimation } from "~/hooks/useScrollAnimation";

export default function InvestorPage() {
  // Enable smooth scrolling for anchor links
  useSmoothScroll();

  // Scroll animations for sections
  const heroAnimation = useScrollAnimation();
  const demoAnimation = useScrollAnimation();
  const marketAnimation = useScrollAnimation();
  const technicalAnimation = useScrollAnimation();
  const builtDifferentAnimation = useScrollAnimation();
  const competitiveAnimation = useScrollAnimation();
  const teamAnimation = useScrollAnimation();
  const ctaAnimation = useScrollAnimation();

  // Technical accordion content
  const technicalItems = [
    {
      icon: Spade,
      title: "Fast Collaborative Shuffling",
      subtitle: "1.5s for 7 players—25x faster than existing ZK poker.",
      content: (
        <p>
          Players jointly shuffle the deck using multi-party computation. Each
          shuffle generates a zero-knowledge proof (SNARK) that the shuffle was
          both random and honest—no player can predict or manipulate the deck
          order. Our optimized cryptography completes shuffles in 1.5s for 7
          players, 25x faster than existing ZK poker implementations.
        </p>
      ),
    },
    {
      icon: Lock,
      title: "Private Card Secrecy",
      subtitle: "End-to-end encryption. Only you see your cards.",
      content: (
        <p>
          Players&apos; hole cards remain encrypted end-to-end using ElGamal
          encryption on the BN254 curve. Only you can decrypt your own cards—no
          central server, no other players, not even our operators can see your
          hand until showdown. Unlike private blockchains (which sacrifice
          performance for privacy), our cryptographic approach achieves both:
          true secrecy with 1.5s shuffle times.
        </p>
      ),
    },
    {
      icon: GitMerge,
      title: "IVC Nova-Style Folding",
      subtitle: "Compress entire hand into one succinct proof.",
      content: (
        <p>
          We use Incrementally Verifiable Computation (IVC) with Nova-style
          folding schemes to aggregate proofs across every action in a
          hand—bets, raises, reveals. Instead of verifying hundreds of
          individual proofs, our folding scheme compresses the entire hand
          history into a single succinct proof. This enables real-time gameplay
          with cryptographic guarantees and minimal gas costs for on-chain
          settlement.
        </p>
      ),
    },
    {
      icon: Link2,
      title: "Multi-Chain Interoperability",
      subtitle: "Play from any chain—Ethereum, Solana, Base, Arbitrum.",
      content: (
        <p>
          Buy in with stablecoins or tokens from any major chain—Ethereum,
          Solana, Base, Arbitrum, or any EVM-compatible network. Our ZK bridge
          architecture settles to your chain of choice with minimal fees. No
          manual bridging, no locked liquidity. Play from any ecosystem, cash
          out to any wallet.
        </p>
      ),
    },
    {
      icon: Users,
      title: "Decentralized Roles: Earn as Operator",
      subtitle: "Run nodes, earn rewards. Bootstrapped from EigenLayer.",
      content: (
        <>
          <p className="mb-4">
            Legit Poker launches as an EigenLayer AVS (Actively Validated
            Service), bootstrapping from existing EigenLayer operators for
            robust decentralization from day one.
          </p>
          <div className="space-y-2">
            <p>
              <strong className="text-white">Operator roles:</strong>
            </p>
            <ul className="ml-4 list-disc space-y-1">
              <li>
                <strong>Shufflers:</strong> Run shuffle committee nodes to
                coordinate fair deck randomization. Earn rewards for uptime and
                correct execution.
              </li>
              <li>
                <strong>Ledger Operators:</strong> Maintain offchain game state
                and generate validity proofs for hand outcomes. Earn fees from
                rake distribution.
              </li>
            </ul>
            <p className="mt-2">
              All roles are permissionless (after proof-of-unique-humanity
              verification) and governed by smart contracts.
            </p>
          </div>
        </>
      ),
    },
  ];

  return (
    <div className="bg-primary-950 min-h-screen">
      {/* Investor Hero Section */}
      <div ref={heroAnimation.ref}>
        <InvestorHeroSection isVisible={heroAnimation.isVisible} />
      </div>

      {/* Interactive Poker Demo Section */}
      <section id="demo" className="bg-primary-900 py-12 md:py-20 lg:py-32">
        <div ref={demoAnimation.ref}>
          <DemoSection isVisible={demoAnimation.isVisible} />
        </div>
      </section>

      {/* Market Opportunity Section */}
      <div ref={marketAnimation.ref}>
        <MarketOpportunitySection isVisible={marketAnimation.isVisible} />
      </div>

      {/* How It Works Section - Interactive Accordions */}
      <section
        id="whitepaper"
        className="bg-primary-900 py-12 md:py-20 lg:py-32"
      >
        <div
          ref={technicalAnimation.ref}
          className={`mx-auto max-w-4xl px-4 transition-all duration-1000 sm:px-6 ${
            technicalAnimation.isVisible
              ? "translate-y-0 opacity-100"
              : "translate-y-10 opacity-0"
          }`}
        >
          <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
            HOW IT WORKS (Technical)
          </h2>

          <TechnicalAccordion items={technicalItems} />

          <div className="mt-6 text-center md:mt-8">
            <Link
              href="/docs/LegitPoker_Shuffle_and_Deal_Whitepaper.pdf"
              className="text-primary-300 hover:text-primary-100 inline-flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors"
            >
              Read the Technical Whitepaper →
            </Link>
          </div>
        </div>
      </section>

      {/* Built Different Section */}
      <div ref={builtDifferentAnimation.ref}>
        <BuiltDifferentSection isVisible={builtDifferentAnimation.isVisible} />
      </div>

      {/* Competitive Moat Section */}
      <div ref={competitiveAnimation.ref}>
        <CompetitiveMoatSection isVisible={competitiveAnimation.isVisible} />
      </div>

      {/* Team Section */}
      <div ref={teamAnimation.ref}>
        <TeamSection isVisible={teamAnimation.isVisible} />
      </div>

      {/* Investor CTA Section */}
      <div ref={ctaAnimation.ref}>
        <InvestorCTASection isVisible={ctaAnimation.isVisible} />
      </div>

      {/* Footer */}
      <footer className="border-primary-800 bg-primary-950 border-t py-8 sm:py-12">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <div className="text-primary-300 mb-4 flex flex-wrap justify-center gap-4 text-sm sm:gap-6">
            <Link href="/about" className="hover:text-primary-100 py-1">
              About
            </Link>
            <Link href="/docs/LegitPoker_Shuffle_and_Deal_Whitepaper.pdf" className="hover:text-primary-100 py-1">
              Whitepaper
            </Link>
            <Link href="/terms" className="hover:text-primary-100 py-1">
              Terms
            </Link>
            <Link href="/privacy" className="hover:text-primary-100 py-1">
              Privacy
            </Link>
          </div>

          <p className="text-primary-400 mt-4 text-center text-xs sm:text-sm">
            © 2025 Legit Poker by BASIS LABS. Open-source protocol.
          </p>

          <div className="text-primary-400 mt-3 flex justify-center gap-4 text-sm sm:mt-4 sm:gap-6">
            <Link
              href="https://twitter.com"
              className="hover:text-primary-300 py-1"
            >
              Twitter
            </Link>
            <Link
              href="https://github.com"
              className="hover:text-primary-300 py-1"
            >
              GitHub
            </Link>
            <Link
              href="https://discord.com"
              className="hover:text-primary-300 py-1"
            >
              Discord
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
