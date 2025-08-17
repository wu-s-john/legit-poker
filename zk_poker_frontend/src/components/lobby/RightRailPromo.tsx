'use client';

import { Trophy, Star, Gift } from 'lucide-react';

export function RightRailPromo() {
  const promos = [
    {
      id: '1',
      title: 'New Player Bonus',
      description: 'Get 100% bonus up to $1000 on your first deposit',
      icon: Gift,
      color: 'bg-gradient-to-br from-green-500 to-green-600',
    },
    {
      id: '2',
      title: 'Weekly Tournament',
      description: 'Join the Sunday Million for a chance to win big',
      icon: Trophy,
      color: 'bg-gradient-to-br from-yellow-500 to-yellow-600',
    },
    {
      id: '3',
      title: 'VIP Program',
      description: 'Earn points and unlock exclusive rewards',
      icon: Star,
      color: 'bg-gradient-to-br from-purple-500 to-purple-600',
    },
  ];

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold text-white mb-4">Promotions</h3>
      
      {promos.map((promo) => {
        const Icon = promo.icon;
        
        return (
          <div
            key={promo.id}
            className={`${promo.color} rounded-lg p-4 text-white hover:scale-105 transition-transform cursor-pointer`}
          >
            <div className="flex items-start gap-3">
              <Icon className="w-6 h-6 flex-shrink-0 mt-1" />
              <div>
                <h4 className="font-semibold text-sm mb-1">{promo.title}</h4>
                <p className="text-xs opacity-90">{promo.description}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
