// hooks/useDemoStream.ts

"use client";

import { useState, useEffect, useRef } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/schemas/finalizedEnvelopeSchema";
import { demoStreamEventSchema } from "~/lib/schemas/demoStreamEventSchema";

const API_BASE =
  process.env.NEXT_PUBLIC_BACKEND_SERVER_API_URL ?? "http://localhost:4000";

interface DemoStreamState {
  messages: FinalizedAnyMessageEnvelope[];
  gameId: number | null;
  handId: number | null;
  status: "idle" | "connecting" | "connected" | "error" | "completed";
  error: string | null;
  playerMapping: Map<string, { seat: number; player_key: string }>;
}

/**
 * Hook to connect to SSE demo stream and maintain reverse chronological message list
 * Messages are prepended (newest first)
 *
 * @param enabled - If false, no connection is made. When true, connects to SSE stream.
 */
export function useDemoStream(enabled = true) {
  const [state, setState] = useState<DemoStreamState>({
    messages: [],
    gameId: null,
    handId: null,
    status: "idle",
    error: null,
    playerMapping: new Map(),
  });

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttempts = useRef(0);

  useEffect(() => {
    console.log("[SSE] useEffect triggered - enabled:", enabled);

    // ONLY connect if enabled is true
    if (!enabled) {
      console.log("[SSE] Hook disabled, staying idle");
      // Reset to idle state when disabled
      setState((prev) => ({
        ...prev,
        status: "idle",
        error: null,
      }));
      return;
    }

    console.log("[SSE] Hook enabled, preparing to connect");

    // Connect to SSE endpoint
    const connect = () => {
      console.log("[SSE] connect() called - setting status to 'connecting'");
      setState((prev) => ({ ...prev, status: "connecting", error: null }));

      const url = `${API_BASE}/games/demo/stream`;
      console.log("[SSE] Creating EventSource with URL:", url);
      const eventSource = new EventSource(url);
      eventSourceRef.current = eventSource;

      console.log(
        "[SSE] EventSource created, readyState:",
        eventSource.readyState,
      );
      console.log("[SSE] EventSource.CONNECTING =", EventSource.CONNECTING);
      console.log("[SSE] EventSource.OPEN =", EventSource.OPEN);
      console.log("[SSE] EventSource.CLOSED =", EventSource.CLOSED);

      // Connection opened
      eventSource.onopen = () => {
        console.log(
          "[SSE] Connection opened to",
          `${API_BASE}/games/demo/stream`,
        );
        console.log("[SSE] ReadyState after open:", eventSource.readyState);
        setState((prev) => ({ ...prev, status: "connected" }));
        reconnectAttempts.current = 0; // Reset reconnect attempts on successful connection
      };

      // Listen for specific event types from the backend
      eventSource.addEventListener("player_created", (event: Event) => {
        const messageEvent = event as MessageEvent<string>;
        console.log("[SSE] Received 'player_created' event:", messageEvent);
        console.log("[SSE] Event data:", messageEvent.data);
        // Player created events are informational, no state update needed
      });

      eventSource.addEventListener("hand_created", (event: Event) => {
        const messageEvent = event as MessageEvent<string>;
        console.log("[SSE] Received 'hand_created' event:", messageEvent);
        console.log("[SSE] Event data:", messageEvent.data);

        try {
          const json: unknown = JSON.parse(messageEvent.data);
          const parsed = demoStreamEventSchema.parse(json);
          console.log("[SSE] Validated hand_created event:", parsed);

          if (parsed.type === "hand_created") {
            setState((prev) => {
              const mapping = new Map<
                string,
                { seat: number; player_key: string }
              >();

              // Extract player mapping from snapshot
              if (parsed.snapshot?.players) {
                Object.values(parsed.snapshot.players).forEach((player) => {
                  mapping.set(player.player_key, {
                    seat: player.seat,
                    player_key: player.player_key,
                  });
                });
              }

              console.log("[SSE] Player mapping extracted:", mapping);

              return {
                ...prev,
                gameId: parsed.game_id,
                handId: parsed.hand_id,
                playerMapping: mapping,
              };
            });
          }
        } catch (error) {
          console.error(
            "[SSE] Failed to parse hand_created event:",
            event.data,
            error,
          );
        }
      });

      eventSource.addEventListener("game_event", (event: Event) => {
        const messageEvent = event as MessageEvent<string>;
        console.log("[SSE] Received 'game_event' event:", messageEvent);
        console.log("[SSE] Event data:", messageEvent.data);

        try {
          const json: unknown = JSON.parse(messageEvent.data);
          const parsed = demoStreamEventSchema.parse(json);

          console.log("[SSE] Validated game_event:", parsed);

          if (parsed.type === "game_event") {
            setState((prev) => {
              console.log(
                "[SSE] Adding message to list. Current count:",
                prev.messages.length,
              );
              return {
                ...prev,
                messages: [
                  parsed.envelope,
                  ...prev.messages,
                ],
              };
            });
          }
        } catch (error) {
          console.error("[SSE] Failed to parse game_event:", error);
          console.error("[SSE] Problem payload was:", event.data);
        }
      });

      eventSource.addEventListener(
        "community_decrypted",
        (event: Event) => {
          const messageEvent = event as MessageEvent<string>;
          console.log("[SSE] Received 'community_decrypted' event:", messageEvent);
          console.log("[SSE] Event data:", messageEvent.data);
          // Community cards events are informational for now
        },
      );

      eventSource.addEventListener(
        "hole_cards_decrypted",
        (event: Event) => {
          const messageEvent = event as MessageEvent<string>;
          console.log("[SSE] Received 'hole_cards_decrypted' event:", messageEvent);
          console.log("[SSE] Event data:", messageEvent.data);
          // Hole cards events are informational for now
        },
      );

      eventSource.addEventListener("hand_completed", (event: Event) => {
        const messageEvent = event as MessageEvent<string>;
        console.log("[SSE] Received 'hand_completed' event:", messageEvent);
        console.log("[SSE] Event data:", messageEvent.data);

        setState((prev) => ({ ...prev, status: "completed" }));
      });

      // Generic message handler (parses all event types)
      eventSource.onmessage = (event: MessageEvent<string>) => {
        console.log("[SSE] Raw event received:", event);
        console.log("[SSE] Event data:", event.data);

        try {
          const json: unknown = JSON.parse(event.data);
          console.log("[SSE] Parsed JSON:", json);

          const parsed = demoStreamEventSchema.parse(json);
          console.log("[SSE] Validated event:", parsed);

          // Handle hand_created event - extract player mapping
          if (parsed.type === "hand_created") {
            console.log(
              "[SSE] hand_created event - game_id:",
              parsed.game_id,
              "hand_id:",
              parsed.hand_id,
            );
            setState((prev) => {
              const mapping = new Map<
                string,
                { seat: number; player_key: string }
              >();

              // Extract player mapping from snapshot
              if (parsed.snapshot?.players) {
                Object.values(parsed.snapshot.players).forEach((player) => {
                  mapping.set(player.player_key, {
                    seat: player.seat,
                    player_key: player.player_key,
                  });
                });
              }

              console.log("[SSE] Player mapping extracted:", mapping);

              return {
                ...prev,
                gameId: parsed.game_id,
                handId: parsed.hand_id,
                playerMapping: mapping,
              };
            });
          }

          // Handle game_event - add to messages list (prepend for reverse chronological)
          if (parsed.type === "game_event") {
            setState((prev) => {
              console.log(
                "[SSE] game_event - Adding message to list. Current count:",
                prev.messages.length,
              );
              return {
                ...prev,
                messages: [
                  parsed.envelope,
                  ...prev.messages,
                ],
              };
            });
          }

          // Handle hand_completed - mark as completed but keep connection open
          if (parsed.type === "hand_completed") {
            console.log("[SSE] hand_completed event received");
            setState((prev) => ({ ...prev, status: "completed" }));
          }
        } catch (error) {
          console.error("[SSE] Failed to parse SSE event:", error);
          console.error("[SSE] Raw event data:", event.data);
        }
      };

      // Error handler
      eventSource.onerror = (err) => {
        console.error("[SSE] Connection error:", err);
        console.log("[SSE] ReadyState:", eventSource.readyState);
        eventSource.close();

        // Exponential backoff for reconnection (start: 1s, max: 30s)
        const backoffDelay = Math.min(
          1000 * Math.pow(2, reconnectAttempts.current),
          30000,
        );

        reconnectAttempts.current += 1;

        console.log(
          `[SSE] Reconnect attempt ${reconnectAttempts.current}, waiting ${Math.round(backoffDelay / 1000)}s...`,
        );

        setState((prev) => ({
          ...prev,
          status: "error",
          error: `Connection lost. Reconnecting in ${Math.round(backoffDelay / 1000)}s...`,
        }));

        // Schedule reconnection
        reconnectTimeoutRef.current = setTimeout(() => {
          console.log("[SSE] Attempting to reconnect...");
          connect();
        }, backoffDelay);
      };
    };

    console.log("[SSE] Starting initial connection...");
    // Start connection
    connect();

    // Cleanup on unmount or when enabled changes to false
    return () => {
      console.log("[SSE] Cleanup function called");
      if (eventSourceRef.current) {
        console.log("[SSE] Closing existing EventSource connection");
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (reconnectTimeoutRef.current) {
        console.log("[SSE] Clearing reconnect timeout");
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
    };
  }, [enabled]); // Re-run when enabled changes

  return state;
}
