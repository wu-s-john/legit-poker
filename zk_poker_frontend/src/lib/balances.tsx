'use client';

import { createContext, useContext, useState } from 'react';
import type { ReactNode } from 'react';
import type { Balance } from '~/types/poker';

interface BalancesContextType {
  balances: Balance;
  addCoins: (kind: 'GC' | 'SC', amount: number) => void;
  deductCoins: (kind: 'GC' | 'SC', amount: number) => void;
  setBalances: (balances: Balance) => void;
}

const BalancesContext = createContext<BalancesContextType | undefined>(undefined);

const initialBalances: Balance = {
  GC: 10000, // Starting game coins
  SC: 1000,  // Starting stake coins
};

export function BalancesProvider({ children }: { children: ReactNode }) {
  const [balances, setBalancesState] = useState<Balance>(initialBalances);

  const addCoins = (kind: 'GC' | 'SC', amount: number) => {
    setBalancesState(prev => ({
      ...prev,
      [kind]: prev[kind] + amount,
    }));
  };

  const deductCoins = (kind: 'GC' | 'SC', amount: number) => {
    setBalancesState(prev => ({
      ...prev,
      [kind]: Math.max(0, prev[kind] - amount),
    }));
  };

  const setBalances = (newBalances: Balance) => {
    setBalancesState(newBalances);
  };

  return (
    <BalancesContext.Provider value={{
      balances,
      addCoins,
      deductCoins,
      setBalances,
    }}>
      {children}
    </BalancesContext.Provider>
  );
}

export function useBalances() {
  const context = useContext(BalancesContext);
  if (context === undefined) {
    throw new Error('useBalances must be used within a BalancesProvider');
  }
  return context;
}
