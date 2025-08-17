'use client';

import { useToastStore } from '~/lib/toasts';
import { CheckCircle, XCircle, AlertCircle, Info, X } from 'lucide-react';
import { useEffect } from 'react';

const toastIcons = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertCircle,
  info: Info,
};

const toastColors = {
  success: 'bg-green-600 border-green-500',
  error: 'bg-red-600 border-red-500',
  warning: 'bg-yellow-600 border-yellow-500',
  info: 'bg-blue-600 border-blue-500',
};

export function ToastHost() {
  const { toasts, removeToast } = useToastStore();

  // Handle escape key to close toasts
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && toasts.length > 0) {
        const lastToast = toasts[toasts.length - 1];
        if (lastToast) {
          removeToast(lastToast.id);
        }
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [toasts, removeToast]);

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed top-4 right-4 z-50 space-y-2"
      aria-live="polite"
      aria-atomic="true"
    >
      {toasts.map((toast) => {
        const Icon = toastIcons[toast.type];
        
        return (
          <div
            key={toast.id}
            className={`
              flex items-center gap-3 p-4 rounded-lg border-l-4 shadow-lg
              text-white min-w-[300px] max-w-[400px]
              ${toastColors[toast.type]}
              toast-enter
            `}
            role="alert"
            aria-describedby={`toast-${toast.id}`}
          >
            <Icon className="w-5 h-5 flex-shrink-0" />
            <div className="flex-1">
              <p id={`toast-${toast.id}`} className="text-sm font-medium">
                {toast.message}
              </p>
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="flex-shrink-0 p-1 hover:bg-white/20 rounded transition-colors"
              aria-label="Close notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
