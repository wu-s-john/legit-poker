'use client';

import { useState } from 'react';
import { Search } from 'lucide-react';

export function FilterBar() {
  const [searchTerm, setSearchTerm] = useState('');
  const [stakeFilter, setStakeFilter] = useState('all');
  const [gameFilter, setGameFilter] = useState('all');
  const [hideFull, setHideFull] = useState(false);

  const stakeBuckets = [
    { value: 'all', label: 'All Stakes' },
    { value: 'micro', label: 'Micro ($0.01/$0.02)' },
    { value: 'low', label: 'Low ($0.25/$0.50)' },
    { value: 'mid', label: 'Mid ($1/$2)' },
    { value: 'high', label: 'High ($5/$10+)' },
  ];

  const gameTypes = [
    { value: 'all', label: 'All Games' },
    { value: 'NLHE', label: 'No Limit Hold\'em' },
    { value: 'PLO', label: 'Pot Limit Omaha' },
  ];

  return (
    <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
      <div className="flex flex-col lg:flex-row gap-4 items-start lg:items-center">
        {/* Search */}
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-primary-400" />
          <input
            type="text"
            placeholder="Search tables..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-primary-700 border border-primary-600 rounded-lg text-white placeholder-primary-400 focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3">
          {/* Stake Filter */}
          <select
            value={stakeFilter}
            onChange={(e) => setStakeFilter(e.target.value)}
            className="px-3 py-2 bg-primary-700 border border-primary-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            {stakeBuckets.map((bucket) => (
              <option key={bucket.value} value={bucket.value}>
                {bucket.label}
              </option>
            ))}
          </select>

          {/* Game Type Filter */}
          <select
            value={gameFilter}
            onChange={(e) => setGameFilter(e.target.value)}
            className="px-3 py-2 bg-primary-700 border border-primary-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            {gameTypes.map((game) => (
              <option key={game.value} value={game.value}>
                {game.label}
              </option>
            ))}
          </select>

          {/* Hide Full Tables */}
          <label className="flex items-center gap-2 text-primary-300 cursor-pointer">
            <input
              type="checkbox"
              checked={hideFull}
              onChange={(e) => setHideFull(e.target.checked)}
              className="w-4 h-4 text-primary-600 bg-primary-700 border-primary-600 rounded focus:ring-primary-500"
            />
            <span className="text-sm">Hide Full</span>
          </label>
        </div>
      </div>
    </div>
  );
}
