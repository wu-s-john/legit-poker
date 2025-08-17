'use client';

import { useState, useEffect } from 'react';
import { Clock } from 'lucide-react';

interface CountdownBadgeProps {
  status: string;
  startsAt: string;
  endsAt?: string;
}

export function CountdownBadge({ status, startsAt, endsAt }: CountdownBadgeProps) {
  const [timeLeft, setTimeLeft] = useState<string>('');

  useEffect(() => {
    const updateCountdown = () => {
      const now = new Date().getTime();
      let targetTime: number;

      if (status === 'registering') {
        targetTime = new Date(startsAt).getTime();
      } else if (status === 'late_reg' && endsAt) {
        targetTime = new Date(endsAt).getTime();
      } else {
        setTimeLeft('');
        return;
      }

      const difference = targetTime - now;

      if (difference > 0) {
        const hours = Math.floor(difference / (1000 * 60 * 60));
        const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((difference % (1000 * 60)) / 1000);

        if (hours > 0) {
          setTimeLeft(`${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`);
        } else {
          setTimeLeft(`${minutes}:${seconds.toString().padStart(2, '0')}`);
        }
      } else {
        setTimeLeft('00:00');
      }
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);

    return () => clearInterval(interval);
  }, [status, startsAt, endsAt]);

  if (!timeLeft) return null;

  return (
    <div className="flex items-center gap-2 px-3 py-1 bg-primary-700 rounded-full text-sm">
      <Clock className="w-4 h-4 text-primary-400" />
      <span className="font-mono text-primary-200">{timeLeft}</span>
    </div>
  );
}
