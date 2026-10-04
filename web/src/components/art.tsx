// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Arte do HeimdallDNS, inspirada em Heimdall, o guardião nórdico que vigia a
// Bifröst (a ponte arco-íris entre os mundos), vê e ouve tudo e toca o
// Gjallarhorn quando o perigo se aproxima. Tudo em SVG, sem imagem externa.
import { useId, type SVGProps } from 'react'

/** Cores da Bifröst (decorativas; nunca usadas para dados). */
const BIFROST = ['#f2545b', '#f59e3b', '#f2d14b', '#4cc38a', '#22d3ee', '#7c6cf0']

function BifrostGradient({ id, x1 = '0', x2 = '1' }: { id: string; x1?: string; x2?: string }) {
  return (
    <linearGradient id={id} x1={x1} y1="0" x2={x2} y2="0">
      {BIFROST.map((c, i) => (
        <stop key={c} offset={`${(i / (BIFROST.length - 1)) * 100}%`} stopColor={c} />
      ))}
    </linearGradient>
  )
}

/**
 * Emblema: o escudo do guardião com o arco da Bifröst, o olho que tudo vê e a
 * runa Algiz (ᛉ, proteção) — o controle de quem atravessa.
 */
export function Emblem({ className, title }: { className?: string; title?: string }) {
  const id = useId().replace(/:/g, '')
  return (
    <svg viewBox="0 0 64 64" className={className} role={title ? 'img' : undefined} aria-hidden={title ? undefined : true}>
      {title && <title>{title}</title>}
      <defs>
        <BifrostGradient id={`${id}b`} />
        <linearGradient id={`${id}s`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.28" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.06" />
        </linearGradient>
      </defs>
      <path
        d="M32 4 9.5 12.2V30c0 14.6 9.4 24.6 22.5 29.6C45.1 54.6 54.5 44.6 54.5 30V12.2z"
        fill={`url(#${id}s)`}
        stroke="var(--accent)"
        strokeWidth="2.6"
        strokeLinejoin="round"
      />
      {/* A ponte arco-íris */}
      <path d="M18 28a14 14 0 0 1 28 0" fill="none" stroke={`url(#${id}b)`} strokeWidth="3.2" strokeLinecap="round" />
      <path d="M22.5 28a9.5 9.5 0 0 1 19 0" fill="none" stroke={`url(#${id}b)`} strokeWidth="2" strokeLinecap="round" opacity="0.6" />
      {/* O olho do guardião */}
      <path d="M20.5 38c3.2-4.6 7-6.9 11.5-6.9s8.3 2.3 11.5 6.9c-3.2 4.6-7 6.9-11.5 6.9s-8.3-2.3-11.5-6.9z" fill="var(--surface)" stroke="var(--accent)" strokeWidth="2.2" />
      <circle cx="32" cy="38" r="3.6" fill="var(--accent)" />
      <circle cx="33.2" cy="36.8" r="1.1" fill="var(--surface)" />
      {/* Runa Algiz */}
      <path d="M32 55.5V48.5m0 3-3.8-4.2M32 51.5l3.8-4.2" fill="none" stroke="var(--accent)" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  )
}

/** Gjallarhorn: o chifre que soa quando há perigo (ícone dos alertas). */
export function HornIcon({ className, sounding, ...rest }: { className?: string; sounding?: boolean } & SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className} {...rest}>
      <path d="M3.5 16.8c4.6.4 8.6-2 11.2-6.3l2.2-4.1" />
      <path d="M4.3 19.8c5.9.6 10.6-2.5 13.6-7.8l2.6-4.7" />
      <path d="m16.9 6.4 3.6.9" />
      <path d="m3.5 16.8.8 3" />
      <path d="m8.4 16.4.9 2.7" />
      <path d="m12.3 14.2 1.4 2.5" />
      {sounding && (
        <>
          <path d="M19.6 3.2c1 .2 1.8.7 2.3 1.5" />
          <path d="M18.2 1.6c1.8.2 3.4 1.2 4.3 2.7" opacity="0.6" />
        </>
      )}
    </svg>
  )
}

// Runas do Futhark antigo desenhadas em traços (caixa 8×14): nenhuma fonte
// especial é necessária.
const RUNES: Record<string, string> = {
  A: 'M2 1v12M2 1l5 4M2 5l5 4', // ᚨ ansuz
  B: 'M2 1v12M2 1l5 3-5 3 5 3-5 3', // ᛒ berkano
  D: 'M1 1v12M7 1v12M1 1l6 12M7 1 1 13', // ᛞ dagaz
  E: 'M1 1v12M7 1v12M1 1l3 4 3-4', // ᛖ ehwaz
  F: 'M2 1v12M2 5l5-4M2 9l5-4', // ᚠ fehu
  G: 'M1 1l6 12M7 1 1 13', // ᚷ gebo
  H: 'M1 1v12M7 1v12M1 4l6 6', // ᚺ hagalaz
  I: 'M4 1v12', // ᛁ isa
  L: 'M2 1v12M2 1l5 4', // ᛚ laguz
  M: 'M1 1v12M7 1v12M1 1l6 6M7 1 1 7', // ᛗ mannaz
  N: 'M4 1v12M1 5l6 4', // ᚾ naudiz
  O: 'M4 1l3 4-5.5 8M4 1 1 5l5.5 8', // ᛟ othala
  R: 'M2 1v12M2 1l5 3-5 3 5 6', // ᚱ raido
  S: 'M6 1 2 5l4 4-4 4', // ᛊ sowilo
  T: 'M4 1v12M1 4l3-3 3 3', // ᛏ tiwaz
  Z: 'M4 13V6M4 6 1 1M4 6l3-5', // ᛉ algiz
}

/** Faixa de runas (ornamento). Letras sem runa viram um ponto. */
export function RuneBand({ text = 'HEIMDALL · BIFROST · GALLARHORN', className }: { text?: string; className?: string }) {
  const glyphs = [...text.toUpperCase()]
  const step = 11
  return (
    <svg viewBox={`0 0 ${glyphs.length * step} 16`} className={className} aria-hidden preserveAspectRatio="xMinYMid meet">
      {glyphs.map((g, i) =>
        RUNES[g] ? (
          <path key={i} d={RUNES[g]} transform={`translate(${i * step + 1.5} 1)`} fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" />
        ) : g === '·' ? (
          <circle key={i} cx={i * step + 5.5} cy="8" r="1" fill="currentColor" />
        ) : null,
      )}
    </svg>
  )
}

/** Cena do guardião: céu do norte, a Bifröst e o portão de Himinbjörg. */
export function GuardianScene({ className }: { className?: string }) {
  const id = useId().replace(/:/g, '')
  // Estrelas em posições fixas (a cena não muda a cada render).
  const stars = [
    [24, 22, 1.1], [58, 40, 0.8], [92, 16, 1.3], [128, 34, 0.7], [170, 12, 1], [214, 28, 0.9], [248, 14, 1.2],
    [286, 38, 0.8], [318, 18, 1.1], [342, 46, 0.7], [44, 64, 0.6], [300, 70, 0.6], [150, 60, 0.5], [230, 56, 0.6],
  ]
  return (
    <svg viewBox="0 0 360 200" className={className} aria-hidden>
      <defs>
        <linearGradient id={`${id}sky`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#070b14" />
          <stop offset="70%" stopColor="#0c1a2a" />
          <stop offset="100%" stopColor="#10283a" />
        </linearGradient>
        <BifrostGradient id={`${id}b`} />
        <radialGradient id={`${id}glow`} cx="0.5" cy="0.62" r="0.5">
          <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
        </radialGradient>
        <linearGradient id={`${id}aur`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#4cc38a" stopOpacity="0" />
          <stop offset="40%" stopColor="#4cc38a" stopOpacity="0.35" />
          <stop offset="70%" stopColor="#22d3ee" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#7c6cf0" stopOpacity="0" />
        </linearGradient>
      </defs>
      <rect width="360" height="200" rx="16" fill={`url(#${id}sky)`} />
      {/* Aurora */}
      <path d="M0 52c60-26 120 10 180-8s120-30 180-4v22c-60-22-120-6-180 12S60 66 0 80z" fill={`url(#${id}aur)`} />
      {stars.map(([x, y, r], i) => (
        <circle key={i} cx={x} cy={y} r={r} fill="#e6edf3" opacity={0.5 + (i % 3) * 0.15} />
      ))}
      {/* A Bifröst */}
      {[0, 1, 2].map((k) => (
        <path
          key={k}
          d={`M${18 + k * 7} 176C${70 + k * 5} ${54 + k * 9} ${290 - k * 5} ${54 + k * 9} ${342 - k * 7} 176`}
          fill="none"
          stroke={`url(#${id}b)`}
          strokeWidth={6 - k * 1.6}
          strokeLinecap="round"
          opacity={0.85 - k * 0.22}
        />
      ))}
      <ellipse cx="180" cy="130" rx="120" ry="70" fill={`url(#${id}glow)`} />
      {/* Montanhas */}
      <path d="M0 176l38-34 26 18 40-42 36 30 22-16 18 14h40l18-14 22 16 36-30 40 42 26-18 38 34v8a16 16 0 0 1-16 16H16A16 16 0 0 1 0 184z" fill="#0a131e" />
      {/* Himinbjörg: o portão do guardião */}
      <path d="M150 176v-50l12-10h36l12 10v50z" fill="#0f1d2b" stroke="#22d3ee" strokeOpacity="0.55" strokeWidth="1.5" />
      <path d="M168 176v-26a12 12 0 0 1 24 0v26" fill="#070b14" stroke="#22d3ee" strokeOpacity="0.55" strokeWidth="1.5" />
      <path d="M150 126h60M156 118v-8m48 8v-8m-24 6v-12" stroke="#22d3ee" strokeOpacity="0.45" strokeWidth="1.5" strokeLinecap="round" />
      {/* Escudo com o olho sobre o portão */}
      <g transform="translate(166 78) scale(0.44)">
        <path d="M32 4 9.5 12.2V30c0 14.6 9.4 24.6 22.5 29.6C45.1 54.6 54.5 44.6 54.5 30V12.2z" fill="#0f1d2b" stroke="#22d3ee" strokeWidth="3" strokeLinejoin="round" />
        <path d="M20.5 33.5c3.2-4.6 7-6.9 11.5-6.9s8.3 2.3 11.5 6.9c-3.2 4.6-7 6.9-11.5 6.9s-8.3-2.3-11.5-6.9z" fill="none" stroke="#22d3ee" strokeWidth="2.6" />
        <circle cx="32" cy="33.5" r="4" fill="#22d3ee" />
      </g>
      {/* Gjallarhorn pendurado ao lado do portão */}
      <g transform="translate(214 132) scale(0.9)" stroke="#f2d14b" strokeOpacity="0.8" fill="none" strokeWidth="1.8" strokeLinecap="round">
        <path d="M3.5 16.8c4.6.4 8.6-2 11.2-6.3l2.2-4.1M4.3 19.8c5.9.6 10.6-2.5 13.6-7.8l2.6-4.7M16.9 6.4l3.6.9" />
      </g>
    </svg>
  )
}

/** Ilustrações das telas vazias. */
export function EmptyArt({ kind, className }: { kind: 'calm' | 'radar' | 'scroll' | 'bridge'; className?: string }) {
  const id = useId().replace(/:/g, '')
  return (
    <svg viewBox="0 0 120 80" className={className} aria-hidden>
      <defs>
        <BifrostGradient id={`${id}b`} />
      </defs>
      {kind === 'calm' && (
        <>
          <path d="M18 64a42 42 0 0 1 84 0" fill="none" stroke={`url(#${id}b)`} strokeWidth="3" strokeLinecap="round" opacity="0.5" />
          <path d="M60 14 44 20v13c0 10.5 6.8 17.7 16 21.3 9.2-3.6 16-10.8 16-21.3V20z" fill="var(--good-soft)" stroke="var(--good)" strokeWidth="2" strokeLinejoin="round" />
          <path d="m52.5 34 5.3 5.3 9.7-10.6" fill="none" stroke="var(--good)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
        </>
      )}
      {kind === 'radar' && (
        <>
          {[30, 21, 12].map((r) => (
            <circle key={r} cx="60" cy="42" r={r} fill="none" stroke="var(--border-strong)" />
          ))}
          <path d="M60 42 84 24a30 30 0 0 1 6 18z" fill="var(--accent-soft)" stroke="var(--accent)" strokeWidth="1.2" />
          <circle cx="60" cy="42" r="3" fill="var(--accent)" />
        </>
      )}
      {kind === 'scroll' && (
        <>
          <rect x="36" y="14" width="48" height="56" rx="5" fill="var(--surface-2)" stroke="var(--border-strong)" />
          {[26, 34, 42, 50].map((y, i) => (
            <path key={y} d={`M44 ${y}h${32 - i * 5}`} stroke="var(--muted)" strokeWidth="2" strokeLinecap="round" opacity={0.7 - i * 0.12} />
          ))}
          <path d="M28 62a32 32 0 0 1 64 0" fill="none" stroke={`url(#${id}b)`} strokeWidth="2.4" strokeLinecap="round" opacity="0.45" />
        </>
      )}
      {kind === 'bridge' && (
        <>
          <path d="M14 66C30 20 90 20 106 66" fill="none" stroke={`url(#${id}b)`} strokeWidth="5" strokeLinecap="round" opacity="0.8" />
          <path d="M22 66C36 32 84 32 98 66" fill="none" stroke={`url(#${id}b)`} strokeWidth="2.4" strokeLinecap="round" opacity="0.45" />
        </>
      )}
    </svg>
  )
}
