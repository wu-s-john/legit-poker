import { create } from 'zustand';
import type { Toast } from '~/types/poker';

interface ToastStore {
  toasts: Toast[];
  showToast: (toast: Omit<Toast, 'id'>) => void;
  showProving: (actionId: string) => void;
  markVerified: (actionId: string, ms: number) => void;
  showError: (message: string) => void;
  removeToast: (id: string) => void;
  clearToasts: () => void;
}

export const useToastStore = create<ToastStore>((set, get) => ({
  toasts: [],
  
  showToast: (toast) => {
    const id = Math.random().toString(36).substr(2, 9);
    const newToast: Toast = {
      ...toast,
      id,
      duration: toast.duration ?? 5000,
    };
    
    set((state) => ({
      toasts: [...state.toasts, newToast],
    }));
    
    // Auto-remove after duration
    setTimeout(() => {
      get().removeToast(id);
    }, newToast.duration);
  },
  
  showProving: (actionId: string) => {
    get().showToast({
      type: 'info',
      message: 'Proving...',
      actionId,
      duration: 0, // Don't auto-remove
    });
  },
  
  markVerified: (actionId: string, ms: number) => {
    const { toasts } = get();
    const provingToast = toasts.find(t => t.actionId === actionId && t.message === 'Proving...');
    
    if (provingToast) {
      // Update the existing proving toast
      set((state) => ({
        toasts: state.toasts.map(t => 
          t.id === provingToast.id 
            ? { ...t, type: 'success', message: `Verified in ${ms}ms`, duration: 3000 }
            : t
        ),
      }));
      
      // Remove after 3 seconds
      setTimeout(() => {
        get().removeToast(provingToast.id);
      }, 3000);
    } else {
      // Show a new verified toast if no proving toast found
      get().showToast({
        type: 'success',
        message: `Action verified in ${ms}ms`,
        actionId,
        duration: 3000,
      });
    }
  },
  
  showError: (message: string) => {
    get().showToast({
      type: 'error',
      message,
      duration: 5000,
    });
  },
  
  removeToast: (id: string) => {
    set((state) => ({
      toasts: state.toasts.filter(t => t.id !== id),
    }));
  },
  
  clearToasts: () => {
    set({ toasts: [] });
  },
}));
