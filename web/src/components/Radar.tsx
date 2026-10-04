// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useMemo } from 'react'
import type { Device } from '../types'
import { ago } from '../lib/format'
import { t } from '../lib/i18n'

const SIZE = 240
const C = SIZE / 2
const R = C - 8
const WINDOW_MS = 30 * 60_000 // dispositivos vistos nos últimos 30 min

function angleOf(id: string): number {
  let h = 2166136261
  for (const ch of id) h = Math.imul(h ^ ch.charCodeAt(0), 16777619)
  return ((h >>> 0) % 360) * (Math.PI / 180)
}

/**
 * Radar dos dispositivos ativos: o ângulo é fixo por dispositivo e a distância
 * do centro cresce com o tempo desde a última consulta. Quem consultou no
 * último minuto pulsa; isolados ficam em vermelho.
 */
export function Radar({ devices, now }: { devices: Device[]; now: number }) {
  const blips = useMemo(
    () =>
      devices
        .map((d) => {
          const age = now - Date.parse(d.last_seen)
          if (age > WINDOW_MS) return null
          const a = angleOf(d.id)
          const dist = 0.18 + 0.78 * Math.min(1, Math.max(0, age) / WINDOW_MS)
          return {
            d,
            x: C + Math.cos(a) * R * dist,
            y: C + Math.sin(a) * R * dist,
            r: 3 + Math.min(4, Math.log10(1 + d.queries)),
            fresh: age < 60_000,
          }
        })
        .filter((b) => b !== null),
    [devices, now],
  )
  const isolated = blips.filter((b) => b.d.settings.isolated).length

  return (
    <figure className="m-0 flex flex-col items-center">
      <svg
        viewBox={`0 0 ${SIZE} ${SIZE}`}
        className="w-full max-w-60"
        role="img"
        aria-label={t('Radar: {n} dispositivos ativos nos últimos 30 minutos', { n: blips.length }) + (isolated ? t(', {n} isolados', { n: isolated }) : '')}
      >
        <defs>
          <radialGradient id="radar-bg">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.08" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="radar-sweep" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.35" />
          </linearGradient>
        </defs>
        <circle cx={C} cy={C} r={R} fill="url(#radar-bg)" stroke="var(--axis)" />
        {[0.25, 0.5, 0.75].map((f) => (
          <circle key={f} cx={C} cy={C} r={R * f} fill="none" stroke="var(--grid)" />
        ))}
        <line x1={C - R} y1={C} x2={C + R} y2={C} stroke="var(--grid)" />
        <line x1={C} y1={C - R} x2={C} y2={C + R} stroke="var(--grid)" />
        <g style={{ transformOrigin: `${C}px ${C}px`, animation: 'radar-sweep 4s linear infinite' }}>
          <path d={`M${C},${C} L${C + R},${C} A${R},${R} 0 0,0 ${C + R * Math.cos(-0.6)},${C + R * Math.sin(-0.6)} Z`} fill="url(#radar-sweep)" />
        </g>
        {blips.map((b) => {
          const color = b.d.settings.isolated ? 'var(--critical)' : 'var(--accent)'
          return (
            <g key={b.d.id}>
              {b.fresh && (
                <circle
                  cx={b.x}
                  cy={b.y}
                  r={b.r}
                  fill={color}
                  style={{ transformOrigin: `${b.x}px ${b.y}px`, animation: 'blip 1.6s ease-out infinite' }}
                />
              )}
              <circle cx={b.x} cy={b.y} r={b.r} fill={color} stroke="var(--surface)" strokeWidth={2}>
                <title>{`${b.d.display} — ${ago(b.d.last_seen, now)}${b.d.settings.isolated ? ' (isolado)' : ''}`}</title>
              </circle>
            </g>
          )
        })}
        <circle cx={C} cy={C} r={3} fill="var(--accent)" />
      </svg>
      <figcaption className="mt-2 text-center text-[11px] text-muted">
        {t('Centro = consultou agora · borda = há 30 min')}
      </figcaption>
    </figure>
  )
}
