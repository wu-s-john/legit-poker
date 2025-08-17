'use client';

interface SeatMapDotsProps {
  playerCount: number;
  maxPlayers: number;
}

export function SeatMapDots({ playerCount, maxPlayers }: SeatMapDotsProps) {
  const dots = Array.from({ length: maxPlayers }, (_, i) => ({
    id: i,
    occupied: i < playerCount,
  }));

  return (
    <div className="flex items-center gap-1">
      {dots.map((dot) => (
        <div
          key={dot.id}
          className={`
            w-2 h-2 rounded-full transition-colors
            ${dot.occupied 
              ? 'bg-green-400' 
              : 'bg-primary-600 border border-primary-500'
            }
          `}
          title={dot.occupied ? 'Occupied' : 'Empty'}
        />
      ))}
    </div>
  );
}
