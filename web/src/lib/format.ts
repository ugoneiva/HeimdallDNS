// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { locale, t } from './i18n'

const intFmt = new Intl.NumberFormat(locale)
const compactFmt = new Intl.NumberFormat(locale, { notation: 'compact', maximumFractionDigits: 1 })
const pctFmt = new Intl.NumberFormat(locale, { maximumFractionDigits: 1 })

export const fmtInt = (n: number) => intFmt.format(Math.round(n))

/** 1.284 · 12,9 mil · 4,2 mi */
export const fmtCompact = (n: number) => (Math.abs(n) < 10_000 ? intFmt.format(Math.round(n)) : compactFmt.format(n))

export const fmtPct = (n: number) => `${pctFmt.format(n)}%`

export function fmtMs(ms: number): string {
  if (!ms) return '—'
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`
  if (ms < 100) return `${ms.toLocaleString(locale, { maximumFractionDigits: 1, minimumFractionDigits: 1 })} ms`
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toLocaleString(locale, { maximumFractionDigits: 2, minimumFractionDigits: 2 })} s`
}

export function ago(iso: string | number | undefined, now = Date.now()): string {
  if (!iso) return '—'
  const tk = typeof iso === 'number' ? iso : Date.parse(iso)
  if (!tk || tk < 86400_000) return '—'
  const s = Math.max(0, Math.round((now - tk) / 1000))
  if (s < 5) return t('agora')
  if (s < 60) return t('há {n}s', { n: s })
  if (s < 3600) return t('há {n} min', { n: Math.floor(s / 60) })
  if (s < 86400) return t('há {n} h', { n: Math.floor(s / 3600) })
  return t('há {n} d', { n: Math.floor(s / 86400) })
}

export function uptime(s: number): string {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d} d ${h} h`
  if (h) return `${h} h ${m} min`
  return `${m} min`
}

const timeFmt = new Intl.DateTimeFormat(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const dateTimeFmt = new Intl.DateTimeFormat(locale, {
  day: '2-digit',
  month: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
})

export const fmtTime = (iso: string | number) => timeFmt.format(new Date(iso))
export const fmtDateTime = (iso: string | number) => dateTimeFmt.format(new Date(iso))

/** HH:MM:SS,mmm — para o log de consultas. */
export function fmtClock(iso: string): string {
  const d = new Date(iso)
  return `${timeFmt.format(d)}${locale === 'pt-BR' ? ',' : '.'}${String(d.getMilliseconds()).padStart(3, '0')}`
}

export const statusLabel: Record<string, string> = {
  forwarded: t('Encaminhada'),
  cached: t('Cache'),
  stale: t('Cache (renovando)'),
  blocked: t('Bloqueada'),
  isolated: t('Isolada'),
  local: t('Local'),
  refused: t('Recusada'),
  ratelimited: t('Limitada (excesso)'),
  error: t('Falha'),
  invalid: t('Inválida'),
}

export const isBlockedStatus = (s: string) => s === 'blocked' || s === 'isolated'

export const modeLabel: Record<string, string> = {
  refused: t('Recusar (REFUSED)'),
  nxdomain: t('Domínio inexistente (NXDOMAIN)'),
  null: t('Endereço nulo (0.0.0.0)'),
  drop: t('Não responder (drop)'),
}

export const kindLabel: Record<string, string> = {
  threat_blocked: t('Domínio malicioso bloqueado'),
  dga: t('Possível malware (DGA)'),
  dns_tunnel: t('Possível túnel DNS'),
  nrd: t('Domínio recém-registrado'),
  new_device: t('Dispositivo novo'),
  query_flood: t('Excesso de consultas'),
}

export const severityLabel: Record<string, string> = {
  critical: t('Crítica'),
  high: t('Alta'),
  medium: t('Média'),
  low: t('Baixa'),
}
