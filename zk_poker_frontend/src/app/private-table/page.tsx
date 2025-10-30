"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useMutation } from "@tanstack/react-query";
import { rooms } from "~/lib/api";
import { Loader2, Users, DollarSign, Shield } from "lucide-react";
import Link from "next/link";

export default function PrivateTablePage() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    name: "",
    gameType: "NLHE" as "NLHE" | "PLO",
    smallBlind: "",
    bigBlind: "",
  });

  const createRoomMutation = useMutation({
    mutationFn: async () => {
      const sb = parseFloat(formData.smallBlind);
      const bb = parseFloat(formData.bigBlind);

      if (isNaN(sb) || isNaN(bb) || sb <= 0 || bb <= 0) {
        throw new Error("Invalid blind amounts");
      }

      if (bb <= sb) {
        throw new Error("Big blind must be greater than small blind");
      }

      return rooms.create({
        name: formData.name || `${formData.gameType} ${sb}/${bb}`,
        stakes: { sb, bb },
        gameType: formData.gameType,
      });
    },
    onSuccess: (data) => {
      router.push(`/room/${data.id}`);
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    createRoomMutation.mutate();
  };

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  // Preset configurations
  const presets = [
    { label: "Micro ($0.01/$0.02)", sb: "0.01", bb: "0.02" },
    { label: "Low ($0.25/$0.50)", sb: "0.25", bb: "0.50" },
    { label: "Mid ($1/$2)", sb: "1", bb: "2" },
    { label: "High ($5/$10)", sb: "5", bb: "10" },
    { label: "Nosebleed ($50/$100)", sb: "50", bb: "100" },
  ];

  const applyPreset = (sb: string, bb: string) => {
    setFormData({ ...formData, smallBlind: sb, bigBlind: bb });
  };

  return (
    <div className="min-h-screen bg-primary-950 py-12">
      <div className="mx-auto max-w-4xl px-4 sm:px-6">
        {/* Header */}
        <div className="mb-8 text-center">
          <h1 className="mb-4 text-3xl font-bold text-white sm:text-4xl md:text-5xl">
            Create Private Table
          </h1>
          <p className="text-primary-200 mx-auto max-w-2xl text-lg">
            Set up a custom poker table with your own stakes and invite friends
            to play.
          </p>
        </div>

        {/* Features */}
        <div className="mb-8 grid gap-4 sm:grid-cols-3">
          <div className="flex items-center gap-3 rounded-lg border border-primary-700 bg-primary-800/50 p-4">
            <Shield className="h-8 w-8 text-primary-400" />
            <div>
              <h3 className="font-semibold text-white">Cryptographically Fair</h3>
              <p className="text-sm text-primary-300">Verifiable shuffles</p>
            </div>
          </div>
          <div className="flex items-center gap-3 rounded-lg border border-primary-700 bg-primary-800/50 p-4">
            <Users className="h-8 w-8 text-primary-400" />
            <div>
              <h3 className="font-semibold text-white">Up to 9 Players</h3>
              <p className="text-sm text-primary-300">Full table support</p>
            </div>
          </div>
          <div className="flex items-center gap-3 rounded-lg border border-primary-700 bg-primary-800/50 p-4">
            <DollarSign className="h-8 w-8 text-primary-400" />
            <div>
              <h3 className="font-semibold text-white">Custom Stakes</h3>
              <p className="text-sm text-primary-300">Any blind level</p>
            </div>
          </div>
        </div>

        {/* Form */}
        <div className="rounded-xl border border-primary-700 bg-primary-900/50 p-6 backdrop-blur-sm sm:p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Table Name */}
            <div>
              <label htmlFor="name" className="mb-2 block text-sm font-medium text-white">
                Table Name (Optional)
              </label>
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="e.g., Friday Night Game"
                className="w-full rounded-lg border border-primary-700 bg-primary-800 px-4 py-3 text-white placeholder-primary-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
              />
              <p className="mt-1 text-sm text-primary-400">
                Leave blank to auto-generate from stakes
              </p>
            </div>

            {/* Game Type */}
            <div>
              <label htmlFor="gameType" className="mb-2 block text-sm font-medium text-white">
                Game Type
              </label>
              <select
                id="gameType"
                name="gameType"
                value={formData.gameType}
                onChange={handleChange}
                className="w-full rounded-lg border border-primary-700 bg-primary-800 px-4 py-3 text-white focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
              >
                <option value="NLHE">No-Limit Hold&apos;em (NLHE)</option>
                <option value="PLO">Pot-Limit Omaha (PLO)</option>
              </select>
            </div>

            {/* Stake Presets */}
            <div>
              <label className="mb-2 block text-sm font-medium text-white">
                Quick Stakes (Optional)
              </label>
              <div className="flex flex-wrap gap-2">
                {presets.map((preset) => (
                  <button
                    key={preset.label}
                    type="button"
                    onClick={() => applyPreset(preset.sb, preset.bb)}
                    className="rounded-lg border border-primary-700 bg-primary-800/50 px-4 py-2 text-sm font-medium text-primary-300 transition-colors hover:border-primary-500 hover:bg-primary-800 hover:text-white"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Blinds */}
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="smallBlind" className="mb-2 block text-sm font-medium text-white">
                  Small Blind <span className="text-danger">*</span>
                </label>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-primary-400">
                    $
                  </span>
                  <input
                    type="number"
                    id="smallBlind"
                    name="smallBlind"
                    value={formData.smallBlind}
                    onChange={handleChange}
                    step="0.01"
                    min="0.01"
                    required
                    placeholder="0.50"
                    className="w-full rounded-lg border border-primary-700 bg-primary-800 py-3 pl-8 pr-4 text-white placeholder-primary-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="bigBlind" className="mb-2 block text-sm font-medium text-white">
                  Big Blind <span className="text-danger">*</span>
                </label>
                <div className="relative">
                  <span className="absolute left-4 top-1/2 -translate-y-1/2 text-primary-400">
                    $
                  </span>
                  <input
                    type="number"
                    id="bigBlind"
                    name="bigBlind"
                    value={formData.bigBlind}
                    onChange={handleChange}
                    step="0.01"
                    min="0.01"
                    required
                    placeholder="1.00"
                    className="w-full rounded-lg border border-primary-700 bg-primary-800 py-3 pl-8 pr-4 text-white placeholder-primary-400 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/50"
                  />
                </div>
              </div>
            </div>

            {/* Error Message */}
            {createRoomMutation.isError && (
              <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-4">
                <p className="text-sm text-red-400">
                  {createRoomMutation.error instanceof Error
                    ? createRoomMutation.error.message
                    : "Failed to create table. Please try again."}
                </p>
              </div>
            )}

            {/* Submit Buttons */}
            <div className="flex flex-col gap-3 sm:flex-row">
              <button
                type="submit"
                disabled={createRoomMutation.isPending}
                className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-primary-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-primary-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {createRoomMutation.isPending ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" />
                    Creating Table...
                  </>
                ) : (
                  "Create Table"
                )}
              </button>

              <Link
                href="/lobby"
                className="flex flex-1 items-center justify-center gap-2 rounded-lg border-2 border-primary-400 px-6 py-3 font-semibold text-primary-400 transition-colors hover:bg-primary-400/10"
              >
                Cancel
              </Link>
            </div>
          </form>
        </div>

        {/* Info Box */}
        <div className="mt-8 rounded-lg border border-primary-700 bg-primary-800/30 p-6">
          <h3 className="mb-3 font-semibold text-white">What happens next?</h3>
          <ul className="space-y-2 text-sm text-primary-300">
            <li className="flex items-start gap-2">
              <span className="text-primary-400">1.</span>
              <span>Your private table will be created with the specified stakes</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-primary-400">2.</span>
              <span>You&apos;ll be redirected to the table lobby</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-primary-400">3.</span>
              <span>Share the table URL with friends to invite them</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-primary-400">4.</span>
              <span>Once 2+ players join, you can start the game</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
