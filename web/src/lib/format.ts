const intFmt = new Intl.NumberFormat('pt-BR')
const compactFmt = new Intl.NumberFormat('pt-BR', { notation: 'compact', maximumFractionDigits: 1 })
const pctFmt = new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 1 })

export const fmtInt = (n: number) => intFmt.format(Math.round(n))

/** 1.284 · 12,9 mil · 4,2 mi */
export const fmtCompact = (n: number) => (Math.abs(n) < 10_000 ? intFmt.format(Math.round(n)) : compactFmt.format(n))

export const fmtPct = (n: number) => `${pctFmt.format(n)}%`

export function fmtMs(ms: number): string {
  if (!ms) return '—'
  if (ms < 1) return `${(ms * 1000).toFixed(0)} µs`
  if (ms < 100) return `${ms.toFixed(1).replace('.', ',')} ms`
  if (ms < 1000) return `${Math.round(ms)} ms`
  return `${(ms / 1000).toFixed(2).replace('.', ',')} s`
}

export function ago(iso: string | number | undefined, now = Date.now()): string {
  if (!iso) return '—'
  const t = typeof iso === 'number' ? iso : Date.parse(iso)
  if (!t || t < 86400_000) return '—'
  const s = Math.max(0, Math.round((now - t) / 1000))
  if (s < 5) return 'agora'
  if (s < 60) return `há ${s}s`
  if (s < 3600) return `há ${Math.floor(s / 60)} min`
  if (s < 86400) return `há ${Math.floor(s / 3600)} h`
  return `há ${Math.floor(s / 86400)} d`
}

export function uptime(s: number): string {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d) return `${d} d ${h} h`
  if (h) return `${h} h ${m} min`
  return `${m} min`
}

const timeFmt = new Intl.DateTimeFormat('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const dateTimeFmt = new Intl.DateTimeFormat('pt-BR', {
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
  return `${timeFmt.format(d)},${String(d.getMilliseconds()).padStart(3, '0')}`
}

export const statusLabel: Record<string, string> = {
  forwarded: 'Encaminhada',
  cached: 'Cache',
  stale: 'Cache (renovando)',
  blocked: 'Bloqueada',
  isolated: 'Isolada',
  local: 'Local',
  refused: 'Recusada',
  ratelimited: 'Limitada (excesso)',
  error: 'Falha',
  invalid: 'Inválida',
}

export const isBlockedStatus = (s: string) => s === 'blocked' || s === 'isolated'

export const modeLabel: Record<string, string> = {
  refused: 'Recusar (REFUSED)',
  nxdomain: 'Domínio inexistente (NXDOMAIN)',
  null: 'Endereço nulo (0.0.0.0)',
  drop: 'Não responder (drop)',
}

export const kindLabel: Record<string, string> = {
  threat_blocked: 'Domínio malicioso bloqueado',
  dga: 'Possível malware (DGA)',
  dns_tunnel: 'Possível túnel DNS',
  nrd: 'Domínio recém-registrado',
  new_device: 'Dispositivo novo',
  query_flood: 'Excesso de consultas',
}

export const severityLabel: Record<string, string> = {
  critical: 'Crítica',
  high: 'Alta',
  medium: 'Média',
  low: 'Baixa',
}
