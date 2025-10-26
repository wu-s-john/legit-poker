/**
 * Demo stream event types matching Rust backend DemoStreamEvent
 */

import {
  demoStreamEventSchema,
  type DemoStreamEvent,
} from "~/lib/schemas/demoStreamEventSchema";

/**
 * SSE message wrapper
 */
export interface SSEMessage {
  event: string;
  data: string;
}

// Re-export for backward compatibility
export type { DemoStreamEvent };

/**
 * Parse SSE event data to DemoStreamEvent using zod validation
 */
export function parseDemoEvent(message: SSEMessage): DemoStreamEvent | null {
  try {
    const json: unknown = JSON.parse(message.data);
    const result = demoStreamEventSchema.safeParse(json);
    if (!result.success) {
      console.error("Failed to validate demo event:", result.error);
      return null;
    }
    return result.data;
  } catch (error) {
    console.error("Failed to parse demo event JSON:", error);
    return null;
  }
}
