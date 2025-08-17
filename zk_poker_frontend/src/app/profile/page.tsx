'use client';

import { useBalances } from '~/lib/balances';
import { BalancePill } from '~/components/layout/BalancePill';
import { User, Trophy, Clock, TrendingUp } from 'lucide-react';

export default function ProfilePage() {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { balances: _balances } = useBalances();

  const stats = [
    {
      label: 'Games Played',
      value: '127',
      icon: Trophy,
      color: 'text-yellow-400',
    },
    {
      label: 'Total Winnings',
      value: '$2,450',
      icon: TrendingUp,
      color: 'text-green-400',
    },
    {
      label: 'Time Played',
      value: '24h 32m',
      icon: Clock,
      color: 'text-blue-400',
    },
  ];

  return (
    <div className="max-w-4xl mx-auto px-6 py-8">
      <div className="space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="w-24 h-24 bg-primary-700 rounded-full mx-auto mb-4 flex items-center justify-center">
            <User className="w-12 h-12 text-primary-300" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Player Profile</h1>
          <p className="text-primary-300">Welcome to ProofPlay</p>
        </div>

        {/* Balances */}
        <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
          <h2 className="text-xl font-semibold text-white mb-4">Your Balances</h2>
          <div className="flex flex-col sm:flex-row gap-4">
            <BalancePill type="GC" />
            <BalancePill type="SC" />
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {stats.map((stat) => {
            const Icon = stat.icon;
            
            return (
              <div
                key={stat.label}
                className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700 text-center"
              >
                <Icon className={`w-8 h-8 mx-auto mb-3 ${stat.color}`} />
                <div className="text-2xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-primary-300 text-sm">{stat.label}</div>
              </div>
            );
          })}
        </div>

        {/* Recent Activity */}
        <div className="bg-primary-800/50 backdrop-blur-sm rounded-lg p-6 border border-primary-700">
          <h2 className="text-xl font-semibold text-white mb-4">Recent Activity</h2>
          <div className="space-y-3">
            <div className="flex items-center justify-between py-2 border-b border-primary-700">
              <div>
                <div className="text-white font-medium">Won $150 at High Stakes NLHE</div>
                <div className="text-primary-300 text-sm">2 hours ago</div>
              </div>
              <div className="text-green-400 font-semibold">+$150</div>
            </div>
            <div className="flex items-center justify-between py-2 border-b border-primary-700">
              <div>
                <div className="text-white font-medium">Lost $75 at Micro Stakes PLO</div>
                <div className="text-primary-300 text-sm">5 hours ago</div>
              </div>
              <div className="text-red-400 font-semibold">-$75</div>
            </div>
            <div className="flex items-center justify-between py-2">
              <div>
                <div className="text-white font-medium">Joined Sunday Million Tournament</div>
                <div className="text-primary-300 text-sm">1 day ago</div>
              </div>
              <div className="text-primary-400 font-semibold">-$1000</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
