import { useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { ChartColumn, Table2 } from 'lucide-react'
import type { Bucket, Second } from '../types'
import { useChartColors } from '../lib/theme'
import { fmtCompact, fmtDateTime, fmtInt, fmtTime } from '../lib/format'
import { cx } from './ui'

type Series = { key: string; label: string; color: string }

/** Legenda: chave do mesmo formato da marca (linha ou retângulo). */
export function Legend({ series, shape }: { series: Series[]; shape: 'line' | 'rect' }) {
  return (
    <ul className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-2">
      {series.map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <span
            aria-hidden
            className={shape === 'line' ? 'h-0.5 w-3.5 rounded-full' : 'size-2.5 rounded-[3px]'}
            style={{ background: s.color }}
          />
          {s.label}
        </li>
      ))}
    </ul>
  )
}

/** Dica do gráfico: o valor em destaque, o nome da série em segundo plano. */
// Só o que a dica usa das props do Recharts.
type TipProps = {
  active?: boolean
  payload?: ReadonlyArray<{ dataKey?: unknown; value?: unknown }>
  label?: unknown
  series: Series[]
  title: (label: unknown) => string
}

function ChartTip({ active, payload, label, series, title }: TipProps) {
  if (!active || !payload?.length) return null
  const byKey = new Map(payload.map((p) => [String(p.dataKey), Number(p.value ?? 0)]))
  return (
    <div className="min-w-36 rounded-lg border border-line-strong bg-surface px-3 py-2 shadow-xl">
      <p className="mb-1.5 text-[11px] text-muted">{title(label)}</p>
      <ul className="space-y-1">
        {series.map((s) => (
          <li key={s.key} className="flex items-center gap-2 text-xs">
            <span aria-hidden className="h-0.5 w-3 rounded-full" style={{ background: s.color }} />
            <span className="tabular font-semibold text-ink">{fmtInt(byKey.get(s.key) ?? 0)}</span>
            <span className="text-ink-2">{s.label}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Tráfego dos últimos 60 s, atualizado a cada segundo pelo SSE. */
export function LiveTrafficChart({ data }: { data: Second[] }) {
  const c = useChartColors()
  const series: Series[] = [
    { key: 'total', label: 'Consultas/s', color: c.s1 },
    { key: 'blocked', label: 'Bloqueadas/s', color: c.s2 },
  ]
  return (
    <div>
      <div className="h-44">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid vertical={false} stroke={c.grid} />
            <XAxis
              dataKey="t"
              tickFormatter={(t: number) => fmtTime(t * 1000)}
              stroke={c.axis}
              tick={{ fill: c.muted, fontSize: 11 }}
              tickLine={false}
              minTickGap={48}
            />
            <YAxis
              width={44}
              allowDecimals={false}
              tickFormatter={fmtCompact}
              stroke="none"
              tick={{ fill: c.muted, fontSize: 11 }}
            />
            <Tooltip
              cursor={{ stroke: c.axis, strokeWidth: 1 }}
              content={(p) => <ChartTip {...p} series={series} title={(l) => fmtTime(Number(l) * 1000)} />}
            />
            {series.map((s) => (
              <Area
                key={s.key}
                type="monotone"
                dataKey={s.key}
                stroke={s.color}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
                fill={s.color}
                fillOpacity={0.1}
                isAnimationActive={false}
                activeDot={{ r: 4, stroke: c.surface, strokeWidth: 2, fill: s.color }}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-2">
        <Legend series={series} shape="line" />
      </div>
    </div>
  )
}

/** Consultas por intervalo, empilhadas em permitidas e bloqueadas, com visão em tabela. */
export function TrafficHistoryChart({ points, stepS }: { points: Bucket[]; stepS: number }) {
  const c = useChartColors()
  const [table, setTable] = useState(false)
  const data = useMemo(
    () =>
      points.map((p) => ({
        t: Date.parse(p.time),
        allowed: p.forwarded + p.cached + p.local,
        blocked: p.blocked + p.isolated,
      })),
    [points],
  )
  const series: Series[] = [
    { key: 'allowed', label: 'Permitidas', color: c.s1 },
    { key: 'blocked', label: 'Bloqueadas', color: c.s2 },
  ]
  const tickFmt = (t: number) => (stepS >= 3600 ? fmtDateTime(t).replace(',', '') : fmtTime(t).slice(0, 5))

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <Legend series={series} shape="rect" />
        <button
          onClick={() => setTable(!table)}
          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-ink-2 hover:bg-surface-2 hover:text-ink"
        >
          {table ? <ChartColumn className="size-3.5" aria-hidden /> : <Table2 className="size-3.5" aria-hidden />}
          {table ? 'Ver gráfico' : 'Ver tabela'}
        </button>
      </div>
      {table ? (
        <div className="max-h-72 overflow-auto rounded-lg border border-line">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-2 text-left text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Início</th>
                <th className="px-3 py-2 text-right font-medium">Permitidas</th>
                <th className="px-3 py-2 text-right font-medium">Bloqueadas</th>
              </tr>
            </thead>
            <tbody className="tabular">
              {data
                .filter((d) => d.allowed + d.blocked > 0)
                .map((d) => (
                  <tr key={d.t} className="border-t border-line">
                    <td className="px-3 py-1.5 text-ink-2">{fmtDateTime(d.t)}</td>
                    <td className="px-3 py-1.5 text-right">{fmtInt(d.allowed)}</td>
                    <td className="px-3 py-1.5 text-right">{fmtInt(d.blocked)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barCategoryGap="20%">
              <CartesianGrid vertical={false} stroke={c.grid} />
              <XAxis
                dataKey="t"
                tickFormatter={tickFmt}
                stroke={c.axis}
                tick={{ fill: c.muted, fontSize: 11 }}
                tickLine={false}
                minTickGap={40}
              />
              <YAxis width={44} allowDecimals={false} tickFormatter={fmtCompact} stroke="none" tick={{ fill: c.muted, fontSize: 11 }} />
              <Tooltip
                cursor={{ fill: c.grid, opacity: 0.6 }}
                content={(p) => <ChartTip {...p} series={series} title={(l) => fmtDateTime(Number(l))} />}
              />
              <Bar dataKey="allowed" stackId="q" fill={c.s1} maxBarSize={24} stroke={c.surface} strokeWidth={1} isAnimationActive={false} />
              <Bar
                dataKey="blocked"
                stackId="q"
                fill={c.s2}
                maxBarSize={24}
                radius={[4, 4, 0, 0]}
                stroke={c.surface}
                strokeWidth={1}
                isAnimationActive={false}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

/** Ranking com barra fina proporcional (uma série só: a cor vem do título). */
export function RankList({ items, color, empty, render }: {
  items: { key: string; label: string; value: number; sub?: string }[]
  color: 's1' | 's2'
  empty: string
  render?: (key: string) => React.ReactNode
}) {
  const max = Math.max(1, ...items.map((i) => i.value))
  if (!items.length) return <p className="py-6 text-center text-xs text-muted">{empty}</p>
  return (
    <ol className="space-y-2.5">
      {items.map((i) => (
        <li key={i.key} className="group">
          <div className="flex items-baseline justify-between gap-3 text-xs">
            <span className="min-w-0 truncate text-ink" title={i.label}>
              {i.label}
              {i.sub && <span className="ml-1.5 text-muted">{i.sub}</span>}
            </span>
            <span className="flex items-center gap-2">
              {render?.(i.key)}
              <span className="tabular shrink-0 text-ink-2">{fmtInt(i.value)}</span>
            </span>
          </div>
          <div className="mt-1 h-1 rounded-full bg-surface-3">
            <div
              className={cx('h-1 rounded-full', color === 's1' ? 'bg-s1' : 'bg-s2')}
              style={{ width: `${Math.max(2, (i.value / max) * 100)}%` }}
            />
          </div>
        </li>
      ))}
    </ol>
  )
}
