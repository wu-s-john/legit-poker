"use client";

import Link from "next/link";
import {
  Shield,
  ShieldCheck,
  Coins,
  Spade,
  Lock,
  GitMerge,
  Link2,
  Users,
  Play,
  UserPlus,
} from "lucide-react";
import { AnnouncementRibbon } from "~/components/landing/AnnouncementRibbon";
import { TechnicalAccordion } from "~/components/landing/TechnicalAccordion";
import { DemoSection } from "~/components/landing/DemoSection";
import { useSmoothScroll } from "~/hooks/useSmoothScroll";
import { useScrollAnimation } from "~/hooks/useScrollAnimation";

export default function LandingPage() {
  // Enable smooth scrolling for anchor links
  useSmoothScroll();

  // Scroll animations for sections
  const heroAnimation = useScrollAnimation();
  const demoAnimation = useScrollAnimation();
  const marketAnimation = useScrollAnimation();
  const technicalAnimation = useScrollAnimation();
  const featuresAnimation = useScrollAnimation();
  const competitiveAnimation = useScrollAnimation();
  const teamAnimation = useScrollAnimation();

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
      <AnnouncementRibbon />

      {/* Hero Section */}
      <section className="from-primary-950 via-primary-900 to-primary-800 bg-gradient-to-br pt-12 pb-16 md:pt-16 md:pb-24 lg:pt-24">
        <div
          ref={heroAnimation.ref}
          className={`mx-auto max-w-5xl px-4 text-center transition-all duration-1000 sm:px-6 ${
            heroAnimation.isVisible
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
              href="/private-table"
              className="group border-primary-400 text-primary-400 hover:border-primary-300 hover:bg-primary-400/10 hover:shadow-primary-400/20 flex items-center justify-center gap-2 rounded-lg border-2 px-6 py-4 text-base font-semibold transition-all duration-300 hover:scale-105 hover:shadow-lg sm:inline-flex sm:px-8 sm:py-3"
            >
              <UserPlus className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
              Create Private Table
            </Link>
            <Link
              href="/whitepaper"
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

      {/* Interactive Poker Demo Section */}
      <section id="play" className="bg-primary-950 py-12 md:py-20 lg:py-32">
        <div ref={demoAnimation.ref}>
          <DemoSection isVisible={demoAnimation.isVisible} />
        </div>
      </section>

      {/* Market Opportunity Section */}
      <section id="why-now" className="bg-primary-900 py-12 md:py-20 lg:py-32">
        <div
          ref={marketAnimation.ref}
          className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
            marketAnimation.isVisible
              ? "translate-y-0 opacity-100"
              : "translate-y-10 opacity-0"
          }`}
        >
          <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
            WHY THE MARKET IS READY NOW
          </h2>

          <div className="grid gap-4 md:grid-cols-3 md:gap-6">
            <div className="group border-primary-700 bg-primary-900/50 hover:border-primary-500 hover:bg-primary-900/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
              <div className="text-primary-400 group-hover:text-primary-300 mb-2 text-5xl font-bold transition-all duration-300 group-hover:scale-110 md:text-4xl">
                $100B+
              </div>
              <div className="text-primary-300 group-hover:text-primary-200 text-base transition-colors duration-300 md:text-sm">
                Value locked in market
              </div>
            </div>

            <div className="group border-primary-700 bg-primary-900/50 hover:border-primary-500 hover:bg-primary-900/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
              <div className="text-primary-400 group-hover:text-primary-300 mb-2 text-5xl font-bold transition-all duration-300 group-hover:scale-110 md:text-4xl">
                73%
              </div>
              <div className="text-primary-300 group-hover:text-primary-200 text-base transition-colors duration-300 md:text-sm">
                Players who distrust operators
              </div>
            </div>

            <div className="group border-primary-700 bg-primary-900/50 hover:border-primary-500 hover:bg-primary-900/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
              <div className="text-primary-400 group-hover:text-primary-300 mb-2 text-5xl font-bold transition-all duration-300 group-hover:scale-110 md:text-4xl">
                2.5%
              </div>
              <div className="text-primary-300 group-hover:text-primary-200 text-base transition-colors duration-300 md:text-sm">
                Our rake vs 5% standard
              </div>
            </div>
          </div>

          <p className="text-primary-200 mx-auto mt-6 max-w-3xl text-center text-sm leading-relaxed sm:text-base md:mt-8">
            Every year, millions of players abandon online poker due to opaque
            dealing, 2+ week withdrawal delays, and bot/collusion concerns.
            After &quot;gambling&quot; and &quot;poker&quot;, the most common word in player reviews
            is &quot;rigged&quot;. Zero-knowledge proofs solve this—finally.
          </p>
        </div>
      </section>

      {/* Built Different - Feature Cards */}
      <section
        id="why-different"
        className="bg-primary-900 py-12 md:py-20 lg:py-32"
      >
        <div
          ref={featuresAnimation.ref}
          className={`mx-auto max-w-6xl px-4 transition-all duration-1000 sm:px-6 ${
            featuresAnimation.isVisible
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

      {/* Competitive Moat - Table */}
      <section
        id="investors"
        className="bg-primary-950 py-12 md:py-20 lg:py-32"
      >
        <div
          ref={competitiveAnimation.ref}
          className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
            competitiveAnimation.isVisible
              ? "translate-y-0 opacity-100"
              : "translate-y-10 opacity-0"
          }`}
        >
          <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
            THE COMPETITIVE MOAT
          </h2>

          <div className="overflow-x-auto">
            <table className="border-primary-700 bg-primary-800/30 w-full rounded-lg border backdrop-blur-sm">
              <thead className="bg-primary-900">
                <tr>
                  <th className="text-primary-200 px-3 py-2 text-left text-xs font-semibold sm:px-4 sm:py-3 sm:text-sm">
                    Feature
                  </th>
                  <th className="text-primary-200 px-3 py-2 text-center text-xs font-semibold sm:px-4 sm:py-3 sm:text-sm">
                    Us
                  </th>
                  <th className="text-primary-200 px-3 py-2 text-center text-xs font-semibold sm:px-4 sm:py-3 sm:text-sm">
                    Trad Sites
                  </th>
                  <th className="text-primary-200 px-3 py-2 text-center text-xs font-semibold sm:px-4 sm:py-3 sm:text-sm">
                    Blockchain Poker
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Rake
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    2.5%
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    5%
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    4-5%
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Shuffle Speed
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    1.5s
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    N/A
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    38s (zkH)
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Provably Fair
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ✗
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ⚠️ Post-hoc
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Instant Withdraw
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ✗ 2+ weeks
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Bot Prevention
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ⚠️ Weak
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ✗
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Consumer UX
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    ✓
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ✗ Wallet
                  </td>
                </tr>
                <tr className="border-primary-800 hover:bg-primary-800/40 border-t">
                  <td className="text-primary-300 px-3 py-2 text-xs sm:px-4 sm:py-3 sm:text-sm">
                    Operational Expenses
                    <br />
                    <span className="text-[10px] sm:text-xs">
                      (% of revenue)
                    </span>
                  </td>
                  <td className="px-3 py-2 text-center text-xs text-white sm:px-4 sm:py-3 sm:text-sm">
                    &lt;10%
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    27-40%
                  </td>
                  <td className="text-primary-300 px-3 py-2 text-center text-xs sm:px-4 sm:py-3 sm:text-sm">
                    ?
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <p className="text-primary-200 mx-auto mt-6 max-w-3xl text-center text-sm sm:text-base md:mt-8">
            We&apos;re the only platform that combines cryptographic fairness with
            consumer-grade UX and economics that benefit players.
          </p>
        </div>
      </section>

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
              href="/whitepaper"
              className="text-primary-300 hover:text-primary-100 inline-flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors"
            >
              Read the Technical Whitepaper →
            </Link>
          </div>
        </div>
      </section>

      {/* Team Section */}
      <section className="bg-primary-950 py-12 md:py-20 lg:py-32">
        <div
          ref={teamAnimation.ref}
          className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
            teamAnimation.isVisible
              ? "translate-y-0 opacity-100"
              : "translate-y-10 opacity-0"
          }`}
        >
          <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
            BUILT BY EXPERTS
          </h2>

          <div className="mx-auto grid max-w-4xl gap-6 md:grid-cols-2 md:gap-8">
            {/* Daniel Rubin */}
            <div className="border-primary-700 bg-primary-800/50 rounded-lg border p-6 text-center sm:p-8">
              <div className="bg-primary-700 mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-full sm:h-24 sm:w-24">
                <span className="text-2xl font-bold text-white sm:text-3xl">
                  DR
                </span>
              </div>
              <h3 className="mb-1 text-lg font-bold text-white sm:text-xl">
                Daniel Rubin
              </h3>
              <p className="text-primary-400 mb-3 text-sm font-semibold sm:mb-4">
                CEO/CSO
              </p>
              <ul className="text-primary-200 space-y-1 text-left text-xs sm:text-sm">
                <li>• Math PhD Columbia</li>
                <li>• NSF SBIR Award Winner (FHE)</li>
                <li>• 19K YouTube subscribers</li>
              </ul>
            </div>

            {/* John S. Wu */}
            <div className="border-primary-700 bg-primary-800/50 rounded-lg border p-6 text-center sm:p-8">
              <div className="bg-primary-700 mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-full sm:h-24 sm:w-24">
                <span className="text-2xl font-bold text-white sm:text-3xl">
                  JW
                </span>
              </div>
              <h3 className="mb-1 text-lg font-bold text-white sm:text-xl">
                John S. Wu
              </h3>
              <p className="text-primary-400 mb-3 text-sm font-semibold sm:mb-4">
                CTO
              </p>
              <ul className="text-primary-200 space-y-1 text-left text-xs sm:text-sm">
                <li>• Math UCLA, CS NYU</li>
                <li>• Ex-Mina Protocol (networking lead)</li>
                <li>• Ex-Apple (Kubernetes security)</li>
                <li>• SameDay Health ($200M+ revenue)</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="bg-primary-950 py-12 md:py-20 lg:py-32">
        <div className="mx-auto max-w-5xl px-4 text-center sm:px-6">
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
              href="/private-table"
              className="border-primary-400 text-primary-400 hover:bg-primary-400/10 flex items-center justify-center gap-2 rounded-lg border-2 px-8 py-4 text-base font-semibold transition-colors sm:inline-flex sm:py-3"
            >
              Create Private Table
            </Link>
            <Link
              href="/whitepaper"
              className="text-primary-300 hover:text-primary-100 inline-flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium transition-colors"
            >
              Get Whitepaper
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-primary-800 bg-primary-950 border-t py-8 sm:py-12">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <div className="text-primary-300 mb-4 flex flex-wrap justify-center gap-4 text-sm sm:gap-6">
            <Link href="/about" className="hover:text-primary-100 py-1">
              About
            </Link>
            <Link href="/whitepaper" className="hover:text-primary-100 py-1">
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
