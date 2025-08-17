'use client';

import { useBalances } from '~/lib/balances';
import { Coins } from 'lucide-react';

interface BalancePillProps {
  type: 'GC' | 'SC';
  onClick?: () => void;
}

export function BalancePill({ type, onClick }: BalancePillProps) {
  const { balances } = useBalances();
  const amount = balances[type];

  const formatAmount = (value: number) => {
    if (value >= 1000000) {
      return `${(value / 1000000).toFixed(1)}M`;
    }
    if (value >= 1000) {
      return `${(value / 1000).toFixed(1)}K`;
    }
    return value.toLocaleString();
  };

  const colors = {
    GC: 'bg-gradient-to-r from-yellow-500 to-yellow-600 text-yellow-900',
    SC: 'bg-gradient-to-r from-purple-500 to-purple-600 text-white',
  };

  return (
    <button
      onClick={onClick}
      className={`
        flex items-center gap-2 px-3 py-2 rounded-full font-semibold text-sm
        ${colors[type]}
        hover:shadow-lg transition-all duration-200
        ${onClick ? 'cursor-pointer' : 'cursor-default'}
      `}
      disabled={!onClick}
    >
      <Coins className="w-4 h-4" />
      <span className="font-mono">{formatAmount(amount)}</span>
      <span className="text-xs opacity-75">{type}</span>
    </button>
  );
}
