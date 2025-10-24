// components/console/Pagination.tsx

"use client";

import type { PaginationResult } from "~/lib/console/pagination";
import { generatePageNumbers, formatPaginationInfo } from "~/lib/console/pagination";

interface PaginationProps {
  pagination: PaginationResult;
  onPageChange: (page: number) => void;
}

export function Pagination({ pagination, onPageChange }: PaginationProps) {
  const pageNumbers = generatePageNumbers(
    pagination.currentPage,
    pagination.totalPages,
  );

  const handlePrevious = () => {
    if (pagination.hasPreviousPage) {
      onPageChange(pagination.currentPage - 1);
    }
  };

  const handleNext = () => {
    if (pagination.hasNextPage) {
      onPageChange(pagination.currentPage + 1);
    }
  };

  return (
    <div className="flex items-center justify-between px-6 py-4">
      {/* Info text */}
      <div
        className="text-sm"
        style={{ color: "var(--color-text-secondary)" }}
      >
        {formatPaginationInfo(pagination)}
      </div>

      {/* Page controls */}
      <div className="flex items-center gap-2">
        {/* Previous button */}
        <button
          onClick={handlePrevious}
          disabled={!pagination.hasPreviousPage}
          className="px-3 py-1.5 text-sm font-medium rounded transition-colors border disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            color: "var(--color-text-primary)",
            backgroundColor: "oklch(from var(--color-bg-card) l c h / 0.6)",
            borderColor: "var(--color-border-subtle)",
          }}
        >
          Previous
        </button>

        {/* Page numbers */}
        <div className="flex items-center gap-1">
          {pageNumbers.map((pageNum, idx) =>
            pageNum === "ellipsis" ? (
              <span
                key={`ellipsis-${idx}`}
                className="px-2 text-sm"
                style={{ color: "var(--color-text-muted)" }}
              >
                ...
              </span>
            ) : (
              <button
                key={pageNum}
                onClick={() => onPageChange(pageNum)}
                className="min-w-[36px] px-2 py-1.5 text-sm font-medium rounded transition-colors border"
                style={{
                  color:
                    pageNum === pagination.currentPage
                      ? "var(--color-accent-teal)"
                      : "var(--color-text-primary)",
                  backgroundColor:
                    pageNum === pagination.currentPage
                      ? "oklch(from var(--color-accent-teal) l c h / 0.1)"
                      : "transparent",
                  borderColor:
                    pageNum === pagination.currentPage
                      ? "var(--color-accent-teal)"
                      : "var(--color-border-subtle)",
                }}
              >
                {pageNum}
              </button>
            ),
          )}
        </div>

        {/* Next button */}
        <button
          onClick={handleNext}
          disabled={!pagination.hasNextPage}
          className="px-3 py-1.5 text-sm font-medium rounded transition-colors border disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            color: "var(--color-text-primary)",
            backgroundColor: "oklch(from var(--color-bg-card) l c h / 0.6)",
            borderColor: "var(--color-border-subtle)",
          }}
        >
          Next
        </button>
      </div>
    </div>
  );
}
