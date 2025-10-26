// lib/console/pagination.ts

export interface PaginationConfig {
  currentPage: number;
  totalItems: number;
  itemsPerPage: number;
}

export interface PaginationResult {
  currentPage: number;
  totalPages: number;
  itemsPerPage: number;
  startIndex: number;
  endIndex: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  totalItems: number;
}

/**
 * Calculate pagination metadata
 */
export function calculatePagination(
  config: PaginationConfig,
): PaginationResult {
  const { currentPage, totalItems, itemsPerPage } = config;

  const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));
  const safePage = Math.min(Math.max(1, currentPage), totalPages);

  const startIndex = (safePage - 1) * itemsPerPage;
  const endIndex = Math.min(startIndex + itemsPerPage, totalItems);

  return {
    currentPage: safePage,
    totalPages,
    itemsPerPage,
    startIndex,
    endIndex,
    hasNextPage: safePage < totalPages,
    hasPreviousPage: safePage > 1,
    totalItems,
  };
}

/**
 * Paginate an array of items
 */
export function paginateItems<T>(
  items: T[],
  currentPage: number,
  itemsPerPage: number,
): T[] {
  const pagination = calculatePagination({
    currentPage,
    totalItems: items.length,
    itemsPerPage,
  });

  return items.slice(pagination.startIndex, pagination.endIndex);
}

/**
 * Generate page numbers for pagination UI
 * Shows: [1] ... [current-1] [current] [current+1] ... [last]
 */
export function generatePageNumbers(
  currentPage: number,
  totalPages: number,
  maxVisible = 7,
): (number | "ellipsis")[] {
  if (totalPages <= maxVisible) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }

  const pages: (number | "ellipsis")[] = [];
  const sidePages = Math.floor((maxVisible - 3) / 2); // Reserve 3 for first, last, and current

  // Always show first page
  pages.push(1);

  if (currentPage <= sidePages + 2) {
    // Near the start
    for (let i = 2; i <= Math.min(maxVisible - 2, totalPages - 1); i++) {
      pages.push(i);
    }
    if (totalPages > maxVisible - 1) {
      pages.push("ellipsis");
    }
  } else if (currentPage >= totalPages - sidePages - 1) {
    // Near the end
    pages.push("ellipsis");
    for (let i = Math.max(2, totalPages - maxVisible + 3); i < totalPages; i++) {
      pages.push(i);
    }
  } else {
    // In the middle
    pages.push("ellipsis");
    for (
      let i = currentPage - sidePages;
      i <= currentPage + sidePages;
      i++
    ) {
      pages.push(i);
    }
    pages.push("ellipsis");
  }

  // Always show last page
  if (totalPages > 1) {
    pages.push(totalPages);
  }

  return pages;
}

/**
 * Format pagination info string
 * Example: "Showing 1-50 of 142 messages"
 */
export function formatPaginationInfo(pagination: PaginationResult): string {
  if (pagination.totalItems === 0) {
    return "No messages";
  }

  const start = pagination.startIndex + 1;
  const end = pagination.endIndex;
  const total = pagination.totalItems;

  return `Showing ${start}-${end} of ${total} ${total === 1 ? "message" : "messages"}`;
}
