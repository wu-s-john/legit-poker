/**
 * PreparationOverlay Component
 *
 * Displays between demo creation and shuffle start.
 * Shows "Ready to shuffle?" with a button to begin the shuffle phase.
 */

export interface PreparationOverlayProps {
  onStartShuffle: () => void;
}

export function PreparationOverlay({ onStartShuffle }: PreparationOverlayProps) {
  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="flex flex-col items-center gap-6 rounded-lg bg-gradient-to-br from-slate-900/95 to-slate-800/95 p-8 shadow-2xl ring-1 ring-white/10">
        {/* Title */}
        <h2 className="text-2xl font-bold text-white">Ready to Shuffle?</h2>

        {/* Description */}
        <p className="max-w-md text-center text-sm text-slate-300">
          The poker table is set up with 7 players and 5 shufflers. When you&apos;re ready, click
          the button below to watch the zero-knowledge shuffle protocol in action.
        </p>

        {/* Start Button */}
        <button
          onClick={onStartShuffle}
          className="bg-gradient-to-r from-blue-600 to-cyan-600 px-8 py-3 rounded-lg text-base font-semibold text-white shadow-lg transition-all hover:from-blue-700 hover:to-cyan-700 hover:shadow-xl active:scale-95"
        >
          Start Shuffling
        </button>

        {/* Additional Context */}
        <div className="mt-2 text-xs text-slate-400">
          <p className="text-center">
            <span className="font-semibold">5 shufflers</span> will sequentially shuffle the deck
            using <span className="font-semibold">ElGamal encryption</span>
          </p>
        </div>
      </div>
    </div>
  );
}
