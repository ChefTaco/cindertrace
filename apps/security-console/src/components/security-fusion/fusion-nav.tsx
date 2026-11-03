"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/cn";

const TABS = [
  "Overview",
  "Cases",
  "Events",
  "Entities",
  "Sources",
  "Evidence",
  "Policies",
  "Audit",
] as const;

/** Section tabs with a glowing underline on the active route (CSS only). */
export function FusionNav(): React.ReactElement {
  const pathname = usePathname();
  return (
    <nav aria-label="Security Fusion" className="-mb-px flex flex-wrap gap-1 text-[11px] uppercase tracking-wider">
      {TABS.map((label, i) => {
        const href = `/security-fusion${i ? "/" + label.toLowerCase() : ""}`;
        const active = i === 0 ? pathname === href : pathname === href || pathname.startsWith(`${href}/`);
        return (
          <Link
            key={label}
            href={href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "relative px-3 py-2.5 transition-colors",
              "after:absolute after:inset-x-2 after:bottom-0 after:h-0.5 after:origin-center after:rounded-full after:bg-accent after:shadow-[0_0_8px_var(--color-accent)] after:transition-transform after:duration-300",
              active ? "text-accent after:scale-x-100" : "text-text-muted after:scale-x-0 hover:text-text hover:after:scale-x-50",
            )}
          >
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
