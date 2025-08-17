import Link from 'next/link';
import { Play, Trophy, User, Shield } from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-950 via-primary-900 to-primary-800 flex items-center justify-center">
      <div className="text-center space-y-8 max-w-4xl mx-auto px-6">
        {/* Hero Section */}
        <div className="space-y-6">
          <div className="flex items-center justify-center gap-3 mb-8">
            <Shield className="w-12 h-12 text-primary-400" />
            <h1 className="text-6xl font-bold text-white">
              Proof<span className="text-primary-400">Play</span>
            </h1>
          </div>
          
          <p className="text-xl text-primary-200 max-w-2xl mx-auto">
            Experience the future of online poker with zero-knowledge proof technology. 
            Play with complete privacy and mathematical guarantees.
          </p>
        </div>

        {/* Feature Cards */}
        <div className="grid md:grid-cols-3 gap-6 mt-12">
          <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
            <Shield className="w-8 h-8 text-primary-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Zero-Knowledge Proofs</h3>
            <p className="text-primary-300 text-sm">
              Mathematical guarantees that your actions are valid without revealing your strategy.
            </p>
          </div>
          
          <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
            <Play className="w-8 h-8 text-primary-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Real-Time Gaming</h3>
            <p className="text-primary-300 text-sm">
              Lightning-fast gameplay with instant verification and seamless user experience.
            </p>
          </div>
          
          <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
            <Trophy className="w-8 h-8 text-primary-400 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">Fair Play</h3>
            <p className="text-primary-300 text-sm">
              Provably fair games with transparent verification and no possibility of cheating.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center mt-12">
          <Link
            href="/lobby"
            className="inline-flex items-center gap-2 bg-primary-600 hover:bg-primary-500 text-white px-8 py-3 rounded-lg font-semibold transition-colors"
          >
            <Play className="w-5 h-5" />
            Play Now
          </Link>
          
          <Link
            href="/profile"
            className="inline-flex items-center gap-2 bg-primary-800 hover:bg-primary-700 text-primary-200 px-8 py-3 rounded-lg font-semibold transition-colors"
          >
            <User className="w-5 h-5" />
            View Profile
          </Link>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-8 mt-16 text-center">
          <div>
            <div className="text-3xl font-bold text-primary-400">1000+</div>
            <div className="text-primary-300 text-sm">Active Players</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-primary-400">50+</div>
            <div className="text-primary-300 text-sm">Tables Running</div>
          </div>
          <div>
            <div className="text-3xl font-bold text-primary-400">99.9%</div>
            <div className="text-primary-300 text-sm">Uptime</div>
          </div>
        </div>
      </div>
    </div>
  );
}
