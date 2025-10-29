"use client";

interface MarketOpportunitySectionProps {
  isVisible: boolean;
}

export function MarketOpportunitySection({
  isVisible,
}: MarketOpportunitySectionProps) {
  return (
    <section
      id="why-now"
      className="bg-primary-950 py-12 md:py-20 lg:py-32"
    >
      <div
        className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
          isVisible
            ? "translate-y-0 opacity-100"
            : "translate-y-10 opacity-0"
        }`}
      >
        <h2 className="mb-8 text-center text-2xl font-bold text-white sm:text-3xl md:mb-12 md:text-4xl">
          WHY THE MARKET IS READY NOW
        </h2>

        <div className="grid gap-4 md:grid-cols-3 md:gap-6">
          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
            <div className="text-primary-400 group-hover:text-primary-300 mb-2 text-5xl font-bold transition-all duration-300 group-hover:scale-110 md:text-4xl">
              $100B+
            </div>
            <div className="text-primary-300 group-hover:text-primary-200 text-base transition-colors duration-300 md:text-sm">
              Value locked in market
            </div>
          </div>

          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
            <div className="text-primary-400 group-hover:text-primary-300 mb-2 text-5xl font-bold transition-all duration-300 group-hover:scale-110 md:text-4xl">
              73%
            </div>
            <div className="text-primary-300 group-hover:text-primary-200 text-base transition-colors duration-300 md:text-sm">
              Players who distrust operators
            </div>
          </div>

          <div className="group border-primary-700 bg-primary-800/50 hover:border-primary-500 hover:bg-primary-800/70 hover:shadow-primary-600/20 rounded-lg border-2 p-6 text-center transition-all duration-300 hover:scale-105 hover:shadow-xl active:scale-95">
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
  );
}
