"use client";

interface TeamSectionProps {
  isVisible: boolean;
}

export function TeamSection({ isVisible }: TeamSectionProps) {
  return (
    <section className="bg-primary-950 py-12 md:py-20 lg:py-32">
      <div
        className={`mx-auto max-w-5xl px-4 transition-all duration-1000 sm:px-6 ${
          isVisible
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
  );
}
