"use client";

interface CompetitiveMoatSectionProps {
  isVisible: boolean;
}

export function CompetitiveMoatSection({
  isVisible,
}: CompetitiveMoatSectionProps) {
  return (
    <section
      id="investors"
      className="bg-primary-900 py-12 md:py-20 lg:py-32"
    >
      <div
        className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
          isVisible
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
  );
}
