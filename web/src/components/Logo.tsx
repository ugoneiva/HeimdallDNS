// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

/** Marca do HeimdallDNS: escudo com o "olho" do guardião. */
export function Logo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <path d="M16 3 5 7.5V15c0 6.8 4.6 12.3 11 14 6.4-1.7 11-7.2 11-14V7.5z" fill="var(--accent-soft)" stroke="var(--accent)" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="M9.5 15.5c1.8-2.8 4-4.2 6.5-4.2s4.7 1.4 6.5 4.2c-1.8 2.8-4 4.2-6.5 4.2s-4.7-1.4-6.5-4.2z" fill="none" stroke="var(--accent)" strokeWidth="1.6" />
      <circle cx="16" cy="15.5" r="2.4" fill="var(--accent)" />
    </svg>
  )
}
