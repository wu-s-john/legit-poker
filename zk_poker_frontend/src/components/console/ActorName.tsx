// components/console/ActorName.tsx

"use client";

import { useState } from "react";
import type { AnyActor } from "~/lib/console/schemas";
import { formatActor } from "~/lib/console/formatting";

interface ActorNameProps {
  actor: AnyActor;
  viewerPublicKey: string;
}

export function ActorName({ actor, viewerPublicKey }: ActorNameProps) {
  const [showCopyIcon, setShowCopyIcon] = useState(false);
  const [showToast, setShowToast] = useState(false);

  const actorName = formatActor(actor, viewerPublicKey);

  // Get the public key/address for this actor
  const getActorAddress = (): string | null => {
    if ("Player" in actor) {
      return actor.Player.player_key;
    }
    if ("Shuffler" in actor) {
      return actor.Shuffler.shuffler_key;
    }
    return null;
  };

  const address = getActorAddress();

  const handleClick = async () => {
    if (!address) return;

    try {
      await navigator.clipboard.writeText(address);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 2000);
    } catch (err) {
      console.error("Failed to copy address:", err);
    }
  };

  // If there's no address (e.g., System), just show plain text
  if (!address) {
    return (
      <span
        className="font-semibold"
        style={{ color: "var(--color-text-primary)" }}
      >
        {actorName}
      </span>
    );
  }

  return (
    <>
      <span
        className="relative inline-flex items-center gap-1 font-semibold cursor-pointer transition-colors"
        style={{
          color: "var(--color-text-primary)",
          textDecoration: "underline dotted 1px",
          textUnderlineOffset: "3px",
        }}
        onMouseEnter={() => setShowCopyIcon(true)}
        onMouseLeave={() => setShowCopyIcon(false)}
        onClick={handleClick}
        aria-label={`${actorName} (${address})`}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handleClick();
          }
        }}
      >
        {actorName}
        {showCopyIcon && (
          <span
            className="inline-block text-xs transition-opacity"
            style={{
              color: "var(--color-text-muted)",
              opacity: showCopyIcon ? 1 : 0,
            }}
            aria-hidden="true"
          >
            📋
          </span>
        )}
      </span>

      {/* Toast notification */}
      {showToast && (
        <div
          className="fixed bottom-4 right-4 px-4 py-2 rounded-lg text-sm font-medium shadow-lg z-50 animate-in fade-in slide-in-from-bottom-2"
          style={{
            backgroundColor: "var(--color-bg-card)",
            color: "var(--color-accent-green)",
            border: "1px solid var(--color-accent-green)",
          }}
        >
          ✓ Address copied!
        </div>
      )}
    </>
  );
}
