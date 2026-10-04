import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Activity, Server, ShieldAlert } from 'lucide-react'
import { api, qs } from '../api'
import type { Ranked, Second, Status, Summary, Timeseries } from '../types'
import { useSSE } from '../lib/sse'
import { fmtCompact, fmtInt, fmtMs, fmtPct } from '../lib/format'
import { Card, Segmented, StatusBadge, cx } from '../components/ui'
import { LiveTrafficChart, RankList, TrafficHistoryChart } from '../components/charts'
import { SeverityBadge, useSecuritySummary } from './Security'
import { t } from '../lib/i18n'

export type Range = '1h' | '24h' | '7d' | '30d'

export const rangeOptions: { value: Range; label: string }[] = [
  { value: '1h', label: t('1 hora') },
  { value: '24h', label: t('24 horas') },
  { value: '7d', label: t('7 dias') },
  { value: '30d', label: t('30 dias') },
]

function LiveTraffic() {
  const [data, setData] = useState<Second[]>([])
  const state = useSSE('/api/stats/live', {
    history: (d) => setData(d as Second[]),
    tick: (d) => setData((prev) => [...prev.slice(-59), d as Second]),
  })
  const last = data.at(-1)
  const avg = data.length ? data.reduce((s, x) => s + x.total, 0) / data.length : 0
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Activity className="size-4 text-accent" aria-hidden />
          {t('Tráfego ao vivo')}
        </span>
      }
      subtitle={t('Últimos 60 segundos')}
      actions={
        state === 'open' ? (
          <StatusBadge tone="good">{t('Conectado')}</StatusBadge>
        ) : (
          <StatusBadge tone="warning">{t('Reconectando…')}</StatusBadge>
        )
      }
    >
      <div className="grid gap-5 lg:grid-cols-[200px_1fr]">
        <div className="flex flex-row gap-6 lg:flex-col lg:gap-4">
          <div>
            <p className="text-xs text-muted">{t('Consultas por segundo agora')}</p>
            <p className="text-5xl font-semibold tracking-tight text-ink">{fmtInt(last?.total ?? 0)}</p>
          </div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs lg:grid-cols-1">
            <div>
              <dt className="text-muted">{t('Média em 60 s')}</dt>
              <dd className="font-semibold text-ink">{avg.toFixed(1).replace('.', ',')}{t('/s')}</dd>
            </div>
            <div>
              <dt className="text-muted">{t('Bloqueadas no último segundo')}</dt>
              <dd className="font-semibold text-ink">{fmtInt(last?.blocked ?? 0)}</dd>
            </div>
          </dl>
        </div>
        <LiveTrafficChart data={data} />
      </div>
    </Card>
  )
}

function Stat({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="rounded-xl border border-line bg-surface px-4 py-3.5">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 text-2xl font-semibold tracking-tight text-ink">{value}</p>
      {note && <p className="mt-0.5 text-[11px] text-muted">{note}</p>}
    </div>
  )
}

function Upstreams() {
  const { data } = useQuery({
    queryKey: ['status'],
    queryFn: () => api<Status>('/api/status'),
    refetchInterval: 5000,
  })
  const ups = data?.upstreams ?? []
  const max = Math.max(1, ...ups.map((u) => u.latency_ms))
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Server className="size-4 text-accent" aria-hidden />
          {t('Upstreams')}
        </span>
      }
      subtitle={t('Latência média recente de cada resolvedor')}
    >
      <ul className="space-y-3">
        {ups.map((u) => (
          <li key={u.address}>
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="min-w-0 truncate font-mono text-ink" title={u.address}>
                {u.address.replace(/^https:\/\/|\/dns-query$/g, '')}
              </span>
              <span className="flex items-center gap-2">
                <span className="tabular font-semibold text-ink">{fmtMs(u.latency_ms)}</span>
                {u.healthy ? <StatusBadge tone="good">{t('Saudável')}</StatusBadge> : <StatusBadge tone="critical">{t('Sem resposta')}</StatusBadge>}
              </span>
            </div>
            <div className="mt-1.5 h-1 rounded-full bg-surface-3">
              <div className="h-1 rounded-full bg-s1" style={{ width: `${Math.max(2, (u.latency_ms / max) * 100)}%` }} />
            </div>
            <p className="mt-1 text-[11px] text-muted">
              {fmtInt(u.ok)}{' '}{t('respostas ·')}{' '}{fmtInt(u.fail)}{' '}{t('falhas')}
            </p>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function SecurityStrip({ onOpen }: { onOpen: () => void }) {
  const { data } = useSecuritySummary()
  if (!data) return null
  const total = data.open_total
  return (
    <button
      onClick={onOpen}
      className={cx(
        'flex w-full flex-wrap items-center gap-3 rounded-xl border px-4 py-3 text-left transition-colors hover:bg-surface-2',
        total ? 'border-critical/40 bg-critical-soft' : 'border-line bg-surface',
      )}
    >
      <ShieldAlert className={cx('size-5', total ? 'text-critical-ink' : 'text-good')} aria-hidden />
      <span className="text-sm font-medium text-ink">
        {total ? total > 1 ? t('{n} alertas de segurança em aberto', { n: fmtInt(total) }) : t('1 alerta de segurança em aberto') : t('Nenhum alerta de segurança em aberto')}
      </span>
      <span className="flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low'] as const)
          .filter((s) => data.open[s])
          .map((s) => (
            <span key={s} className="flex items-center gap-1 text-xs text-ink-2">
              <SeverityBadge sev={s} /> {data.open[s]}
            </span>
          ))}
      </span>
      <span className="ml-auto text-xs text-accent">{t('ver alertas →')}</span>
    </button>
  )
}

export function Overview({ onOpenDevice, onOpenSecurity }: { onOpenDevice: (id: string) => void; onOpenSecurity: () => void }) {
  const [range, setRange] = useState<Range>('24h')
  const opts = { placeholderData: keepPreviousData, refetchInterval: 15_000 }
  const sum = useQuery({ queryKey: ['summary', range], queryFn: () => api<Summary>(`/api/stats/summary${qs({ range })}`), ...opts })
  const ts = useQuery({ queryKey: ['timeseries', range], queryFn: () => api<Timeseries>(`/api/stats/timeseries${qs({ range })}`), ...opts })
  const topDomains = useTop('domains', range)
  const topBlocked = useTop('blocked', range)
  const topClients = useTop('clients', range)
  const s = sum.data
  const refetching = sum.isPlaceholderData || ts.isPlaceholderData

  return (
    <div className="space-y-5">
      <SecurityStrip onOpen={onOpenSecurity} />
      <LiveTraffic />

      {/* Filtro único, acima de tudo o que ele afeta. */}
      <div className="flex flex-wrap items-center gap-3">
        <Segmented label={t('Período')} value={range} onChange={setRange} options={rangeOptions} />
        <span className="text-xs text-muted">{t('Os números e gráficos abaixo usam este período.')}</span>
      </div>

      <div className={cx('space-y-5 transition-opacity', refetching && 'opacity-60')}>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Stat label={t('Consultas')} value={fmtCompact(s?.counts.total ?? 0)} />
          <Stat
            label={t('Bloqueadas')}
            value={fmtPct(s?.blocked_pct ?? 0)}
            note={t('{n} consultas', { n: fmtInt((s?.counts.blocked ?? 0) + (s?.counts.isolated ?? 0)) })}
          />
          <Stat label={t('Respondidas do cache')} value={fmtPct(s?.cached_pct ?? 0)} note={t('{n} consultas', { n: fmtInt(s?.counts.cached ?? 0) })} />
          <Stat label={t('Latência média do upstream')} value={fmtMs(s?.avg_forward_ms ?? 0)} />
          <Stat label={t('Dispositivos ativos')} value={fmtInt(s?.active_clients ?? 0)} />
        </div>

        <Card title={t('Consultas no período')} subtitle={ts.data ? t('Cada barra soma {passo}', { passo: stepLabel(ts.data.step_s) }) : undefined}>
          <TrafficHistoryChart points={ts.data?.points ?? []} stepS={ts.data?.step_s ?? 60} />
        </Card>

        <div className="grid gap-5 lg:grid-cols-3">
          <Card title={t('Domínios mais consultados')}>
            <RankList
              color="s1"
              empty={t('Nenhuma consulta no período.')}
              items={(topDomains.data ?? []).map((r) => ({ key: r.key, label: r.key, value: r.count }))}
            />
          </Card>
          <Card title={t('Domínios mais bloqueados')}>
            <RankList
              color="s2"
              empty={t('Nada bloqueado no período.')}
              items={(topBlocked.data ?? []).map((r) => ({ key: r.key, label: r.key, value: r.count }))}
            />
          </Card>
          <Card title={t('Dispositivos mais ativos')}>
            <RankList
              color="s1"
              empty={t('Nenhum dispositivo no período.')}
              items={(topClients.data ?? []).map((r) => ({
                key: r.key,
                label: r.name || r.key,
                value: r.count,
                sub: r.blocked ? t('{n} bloq.', { n: fmtInt(r.blocked) }) : undefined,
              }))}
              render={(key) => (
                <button onClick={() => onOpenDevice(key)} className="text-[11px] text-accent hover:underline">
                  {t('abrir')}
                </button>
              )}
            />
          </Card>
        </div>
      </div>

      <Upstreams />
    </div>
  )
}

function useTop(kind: string, range: Range) {
  return useQuery({
    queryKey: ['top', kind, range],
    queryFn: () => api<Ranked[]>(`/api/stats/top${qs({ kind, range, limit: 8 })}`),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  })
}

function stepLabel(s: number): string {
  if (s >= 86400) return t('{n} dia', { n: s / 86400 })
  if (s >= 3600) return t('{n} hora', { n: s / 3600 })
  return s / 60 > 1 ? t('{n} minutos', { n: s / 60 }) : t('1 minuto')
}
