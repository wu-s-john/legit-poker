import "~/styles/globals.css";

import { type Metadata } from "next";
import { Geist } from "next/font/google";
import { BalancesProvider } from '~/lib/balances';
import { AppShell } from '~/components/layout/AppShell';
import { Providers } from '~/components/Providers';

export const metadata: Metadata = {
  title: "ProofPlay - ZK Poker",
  description: "Real-time zero-knowledge poker client",
  icons: [{ rel: "icon", url: "/favicon.ico" }],
};

const geist = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
});

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${geist.variable}`}>
      <body>
        <Providers>
          <BalancesProvider>
            <AppShell>
              {children}
            </AppShell>
          </BalancesProvider>
        </Providers>
      </body>
    </html>
  );
}
