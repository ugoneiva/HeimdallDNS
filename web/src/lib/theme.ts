// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState, useSyncExternalStore } from 'react'

export type ThemeChoice = 'dark' | 'light' | 'auto'

const KEY = 'heimdall.theme'
const listeners = new Set<() => void>()

function readChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'dark' || v === 'light' || v === 'auto') return v
  } catch {
    /* armazenamento indisponível: fica no padrão */
  }
  return 'dark'
}

let choice: ThemeChoice = readChoice()
const media = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: light)') : null

function resolved(): 'dark' | 'light' {
  if (choice === 'auto') return media?.matches ? 'light' : 'dark'
  return choice
}

function apply() {
  document.documentElement.dataset.theme = resolved()
  listeners.forEach((l) => l())
}

media?.addEventListener('change', () => choice === 'auto' && apply())
apply()

export function setTheme(c: ThemeChoice) {
  choice = c
  try {
    localStorage.setItem(KEY, c)
  } catch {
    /* ignora */
  }
  apply()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => listeners.delete(l)
}

const snapshot = () => `${choice}:${resolved()}`

export function useTheme(): { choice: ThemeChoice; resolved: 'dark' | 'light' } {
  const [c, r] = useSyncExternalStore(subscribe, snapshot).split(':')
  return { choice: c as ThemeChoice, resolved: r as 'dark' | 'light' }
}

export type ChartColors = {
  s1: string
  s2: string
  s3: string
  ink: string
  ink2: string
  muted: string
  grid: string
  axis: string
  surface: string
  good: string
  critical: string
}

/** Cores resolvidas do tema atual (o SVG do Recharts não aceita var()). */
export function useChartColors(): ChartColors {
  const { resolved: mode } = useTheme()
  const [c, setC] = useState<ChartColors>(read)
  useEffect(() => setC(read()), [mode])
  return c
}

function read(): ChartColors {
  const s = getComputedStyle(document.documentElement)
  const v = (n: string) => s.getPropertyValue(n).trim()
  return {
    s1: v('--s1'),
    s2: v('--s2'),
    s3: v('--s3'),
    ink: v('--ink'),
    ink2: v('--ink-2'),
    muted: v('--muted'),
    grid: v('--grid'),
    axis: v('--axis'),
    surface: v('--surface'),
    good: v('--good'),
    critical: v('--critical'),
  }
}
