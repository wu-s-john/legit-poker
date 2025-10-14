'use client';

type AnalyticsPayload = Record<string, unknown>;

/**
 * Lightweight analytics shim. Replace with real analytics integration as needed.
 */
export function trackEvent(name: string, payload: AnalyticsPayload = {}): void {
  if (process.env.NODE_ENV !== 'production') {
    console.debug('[analytics]', name, payload);
  }

  if (typeof window !== 'undefined') {
    const event = new CustomEvent('proofplay-analytics', {
      detail: { name, payload },
    });
    window.dispatchEvent(event);
  }
}
