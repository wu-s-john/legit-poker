// components/console/CopyButton.tsx

"use client";

import { useState } from "react";

interface CopyButtonProps {
  text: string;
  label?: string;
}

export function CopyButton({ text, label = "Copy" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className="px-2 py-1 text-xs font-medium rounded transition-colors border"
      style={{
        color: copied ? "var(--color-accent-green)" : "var(--color-text-secondary)",
        backgroundColor: copied
          ? "oklch(from var(--color-accent-green) l c h / 0.1)"
          : "oklch(from var(--color-text-secondary) l c h / 0.1)",
        borderColor: copied
          ? "oklch(from var(--color-accent-green) l c h / 0.3)"
          : "oklch(from var(--color-text-secondary) l c h / 0.2)",
      }}
    >
      {copied ? "✓ Copied" : label}
    </button>
  );
}
