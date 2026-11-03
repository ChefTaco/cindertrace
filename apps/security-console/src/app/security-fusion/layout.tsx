import { ArrowUpRight, LogOut, ShieldHalf } from "lucide-react";
import Link from "next/link";
import { FusionNav } from "@/components/security-fusion/fusion-nav";

const chip =
  "inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1.5 text-[10px] uppercase tracking-wider transition-colors";

export default async function SecurityLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const fleetUrl = process.env["MAGNUS_CONSOLE_URL"];
  const fleetLink = fleetUrl && /^https:\/\//.test(fleetUrl) ? fleetUrl : null;
  return (
    <>
      <header className="sticky top-0 z-(--z-shell) border-b border-border bg-bg/85 backdrop-blur-sm">
        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-accent/70 via-primary/30 to-transparent" />
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-6 pt-4">
          <Link href="/security-fusion" className="group flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-panel border border-accent/40 bg-bg text-accent shadow-[0_0_14px_var(--color-glow-accent)] animate-flicker">
              <ShieldHalf className="h-5 w-5" />
            </span>
            <span className="leading-tight">
              <span className="block text-sm font-bold tracking-[0.3em] text-accent glow-text-accent">CINDERTRACE</span>
              <span className="block text-[10px] uppercase tracking-[0.25em] text-text-muted group-hover:text-text">
                Security Fusion
              </span>
            </span>
          </Link>
          <div className="flex flex-wrap items-center gap-2">
            {fleetLink && <a
              href={fleetLink}
              className={`${chip} border-primary/30 text-primary hover:border-primary hover:shadow-[0_0_10px_var(--color-glow)]`}
            >
              Magnus fleet <ArrowUpRight className="h-3 w-3" />
            </a>}
            <form action="/api/auth/logout" method="post">
              <button
                className={`${chip} border-border text-text-muted hover:border-border-strong hover:text-text`}
              >
                <LogOut className="h-3 w-3" /> Sign out
              </button>
            </form>
            <form action="/api/auth/logout?all=true" method="post">
              <button
                className={`${chip} border-danger/30 text-danger/80 hover:border-danger hover:text-danger hover:shadow-[0_0_10px_var(--color-glow-danger)]`}
              >
                Sign out all local sessions
              </button>
            </form>
          </div>
        </div>
        <div className="mx-auto mt-2 max-w-7xl px-4">
          <FusionNav />
        </div>
      </header>
      <div className="app-backdrop min-h-[calc(100vh-7rem)]">
        <div className="mx-auto max-w-7xl p-6">{children}</div>
      </div>
    </>
  );
}
