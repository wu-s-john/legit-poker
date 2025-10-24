// app/debug/games/[gameId]/hands/[handId]/page.tsx

"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { useHandSnapshot } from "~/lib/api";
import { TopNavigation } from "~/components/console/TopNavigation";
import { LogsTableContainer } from "~/components/console/LogsTableContainer";

interface PageProps {
  params: Promise<{
    gameId: string;
    handId: string;
  }>;
}

export default function HandConsoleLogsPage({ params }: PageProps) {
  const { gameId, handId } = use(params);

  // TODO: Get viewer public key from auth context
  // For now, using a placeholder
  const viewerPublicKey = "placeholder_viewer_key";

  const { data, isLoading, error } = useQuery(useHandSnapshot(gameId, handId));

  if (isLoading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: "var(--color-bg-page)" }}
      >
        <div
          className="text-center space-y-4"
          style={{ color: "var(--color-text-primary)" }}
        >
          <div
            className="w-12 h-12 border-4 border-t-transparent rounded-full animate-spin mx-auto"
            style={{ borderColor: "var(--color-accent-teal)" }}
          />
          <p className="text-lg">Loading console logs...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: "var(--color-bg-page)" }}
      >
        <div
          className="text-center space-y-4 max-w-md p-8 rounded-xl border"
          style={{
            backgroundColor: "var(--color-bg-card)",
            borderColor: "var(--color-border-primary)",
            color: "var(--color-text-primary)",
          }}
        >
          <div
            className="text-5xl"
            style={{ color: "var(--color-accent-red)" }}
          >
            ⚠️
          </div>
          <h2
            className="text-xl font-bold"
            style={{ color: "var(--color-accent-red)" }}
          >
            Error Loading Logs
          </h2>
          <p style={{ color: "var(--color-text-secondary)" }}>
            {error instanceof Error ? error.message : "Unknown error occurred"}
          </p>
          <button
            onClick={() => window.location.reload()}
            className="mt-4 px-4 py-2 rounded-lg font-medium border transition-colors"
            style={{
              color: "var(--color-text-primary)",
              backgroundColor: "var(--color-bg-card-header)",
              borderColor: "var(--color-border-primary)",
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  // Compute total and hand status from messages
  const totalMessages = data.messages.length;
  const lastMessage = data.messages[data.messages.length - 1];
  const handStatus = lastMessage?.applied_phase ?? "Pending";

  return (
    <div
      className="min-h-screen"
      style={{ backgroundColor: "var(--color-bg-page)" }}
    >
      {/* Top Navigation */}
      <TopNavigation
        gameId={gameId}
        handId={handId}
        handStatus={handStatus}
        totalMessages={totalMessages}
      />

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        <LogsTableContainer
          messages={data.messages}
          viewerPublicKey={viewerPublicKey}
          playerMapping={data.playerMapping}
          itemsPerPage={50}
        />
      </main>
    </div>
  );
}
