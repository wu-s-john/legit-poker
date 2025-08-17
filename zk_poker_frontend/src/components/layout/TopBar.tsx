'use client';

import { Suspense } from 'react';
import { BalancePill } from '~/components/layout/BalancePill';
import { useBalances } from '~/lib/balances';
import { Plus } from 'lucide-react';
import Link from 'next/link';
import { usePathname, useSearchParams } from 'next/navigation';

function TopBarContent() {
  const { addCoins } = useBalances();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const currentTab = searchParams.get('tab') ?? 'ring';

  const isLobby = pathname === '/lobby' || pathname === '/room';

  const handleAddCoins = (type: 'GC' | 'SC') => {
    const amount = type === 'GC' ? 1000 : 100;
    addCoins(type, amount);
  };

  return (
    <header className="bg-primary-900 border-b border-primary-800 px-6 py-4">
      <div className="flex items-center justify-between max-w-7xl mx-auto">
        {/* Brand */}
        <div className="flex items-center gap-4">
          <Link href="/" className="text-2xl font-bold text-primary-100">
            ProofPlay
          </Link>
        </div>

        {/* Centered Tabs */}
        {isLobby && (
          <div className="flex items-center gap-1 bg-primary-800 rounded-lg p-1">
            <Link
              href="/lobby?tab=ring"
              className={`
                px-4 py-2 rounded-md text-sm font-medium transition-colors
                ${currentTab === 'ring' 
                  ? 'bg-primary-600 text-white' 
                  : 'text-primary-300 hover:text-white'
                }
              `}
            >
              Ring Games
            </Link>
            <Link
              href="/lobby?tab=tourney"
              className={`
                px-4 py-2 rounded-md text-sm font-medium transition-colors
                ${currentTab === 'tourney' 
                  ? 'bg-primary-600 text-white' 
                  : 'text-primary-300 hover:text-white'
                }
              `}
            >
              Tournaments
            </Link>
          </div>
        )}

        {/* Balance Pills */}
        <div className="flex items-center gap-3">
          <BalancePill type="GC" onClick={() => handleAddCoins('GC')} />
          <BalancePill type="SC" onClick={() => handleAddCoins('SC')} />
          
          {/* Add Coins Button */}
          <button
            onClick={() => handleAddCoins('SC')}
            className="flex items-center gap-2 px-3 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-lg transition-colors"
            title="Add Coins"
          >
            <Plus className="w-4 h-4" />
            <span className="text-sm font-medium">Add Coins</span>
          </button>
        </div>
      </div>
    </header>
  );
}

export function TopBar() {
  return (
    <Suspense fallback={<div className="bg-primary-900 border-b border-primary-800 px-6 py-4"><div className="flex items-center justify-between max-w-7xl mx-auto"><div className="text-2xl font-bold text-primary-100">ProofPlay</div></div></div>}>
      <TopBarContent />
    </Suspense>
  );
}
