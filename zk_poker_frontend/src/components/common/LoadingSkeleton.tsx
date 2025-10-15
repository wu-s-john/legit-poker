interface LoadingSkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular';
  width?: string;
  height?: string;
}

export function LoadingSkeleton({
  className = '',
  variant = 'rectangular',
  width = '100%',
  height = '20px',
}: LoadingSkeletonProps) {
  const variantClasses = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
  };

  return (
    <div
      className={`animate-pulse bg-primary-800/50 ${variantClasses[variant]} ${className}`}
      style={{ width, height }}
      aria-label="Loading..."
    />
  );
}

// Preset skeleton components for common use cases
export function SkeletonCard() {
  return (
    <div className="rounded-lg border border-primary-700 bg-primary-800/30 p-6">
      <LoadingSkeleton variant="circular" width="48px" height="48px" />
      <LoadingSkeleton className="mt-4" width="60%" height="24px" />
      <LoadingSkeleton className="mt-2" width="100%" height="16px" />
      <LoadingSkeleton className="mt-1" width="90%" height="16px" />
    </div>
  );
}

export function SkeletonText({ lines = 3 }: { lines?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: lines }).map((_, i) => (
        <LoadingSkeleton
          key={i}
          width={i === lines - 1 ? '75%' : '100%'}
          height="16px"
        />
      ))}
    </div>
  );
}
