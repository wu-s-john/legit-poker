// components/console/LogsTableContainer.tsx

"use client";

import { useState } from "react";
import type { FinalizedAnyMessageEnvelope } from "~/lib/schemas/finalizedEnvelopeSchema";
import { calculatePagination, paginateItems } from "~/lib/console/pagination";
import { MessageRow } from "./MessageRow";
import { Pagination } from "./Pagination";

interface LogsTableContainerProps {
  messages: FinalizedAnyMessageEnvelope[];
  viewerPublicKey: string;
  playerMapping: Map<string, { seat: number; player_key: string }>;
  itemsPerPage?: number;
}

export function LogsTableContainer({
  messages,
  viewerPublicKey,
  playerMapping,
  itemsPerPage = 50,
}: LogsTableContainerProps) {
  const [currentPage, setCurrentPage] = useState(1);

  const pagination = calculatePagination({
    currentPage,
    totalItems: messages.length,
    itemsPerPage,
  });

  const paginatedMessages = paginateItems(messages, currentPage, itemsPerPage);

  return (
    <div
      className="overflow-hidden rounded-xl border backdrop-blur-md"
      style={{
        backgroundColor: "var(--color-bg-card)",
        borderColor: "var(--color-border-primary)",
        boxShadow: "var(--shadow-card)",
      }}
    >
      {/* Table Header */}
      <div
        className="border-b px-6 py-4"
        style={{
          backgroundColor: "var(--color-bg-card-header)",
          borderColor: "var(--color-border-primary)",
        }}
      >
        <div className="grid grid-cols-[24px_60px_180px_200px_1fr] gap-4">
          {/* Empty space for chevron column */}
          <div></div>
          <div
            className="text-xs font-semibold tracking-wider uppercase"
            style={{ color: "var(--color-text-muted)" }}
          >
            Seq
          </div>
          <div
            className="text-xs font-semibold tracking-wider uppercase"
            style={{ color: "var(--color-text-muted)" }}
          >
            Timestamp
          </div>
          <div
            className="text-xs font-semibold tracking-wider uppercase"
            style={{ color: "var(--color-text-muted)" }}
          >
            Type
          </div>
          <div
            className="text-xs font-semibold tracking-wider uppercase"
            style={{ color: "var(--color-text-muted)" }}
          >
            Message
          </div>
        </div>
      </div>

      {/* Table Body */}
      <div>
        {paginatedMessages.length === 0 ? (
          <div
            className="px-6 py-12 text-center text-sm"
            style={{ color: "var(--color-text-muted)" }}
          >
            No messages found
          </div>
        ) : (
          paginatedMessages.map((message) => (
            <MessageRow
              key={message.snapshot_sequence_id}
              message={message}
              sequenceNumber={message.snapshot_sequence_id}
              viewerPublicKey={viewerPublicKey}
              playerMapping={playerMapping}
            />
          ))
        )}
      </div>

      {/* Pagination Footer */}
      {messages.length > 0 && (
        <div
          className="border-t"
          style={{
            backgroundColor: "var(--color-bg-table-header)",
            borderColor: "var(--color-border-primary)",
          }}
        >
          <Pagination pagination={pagination} onPageChange={setCurrentPage} />
        </div>
      )}
    </div>
  );
}
