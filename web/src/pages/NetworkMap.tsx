// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ComponentType } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Briefcase, CircleHelp, Clapperboard, Cloud, Earth, Gamepad2, Globe, Lock, MessageCircle, MonitorCog, Search, ShieldAlert, ShieldBan, ShoppingCart, Table2, Users, Waypoints,
} from 'lucide-react'
import { api, qs } from '../api'
import type { TopoDest, TopoDevice, TopologyResponse } from '../types'
import { fmtInt, fmtPct } from '../lib/format'
import { t } from '../lib/i18n'
import { Card, ErrorNote, Input, LabeledSwitch, Segmented, cx } from '../components/ui'
import { Logo } from '../components/Logo'
import { DeviceModal } from './DeviceModal'
import { useDevices } from './Devices'
import { kindIcon, kindLabel } from '../lib/kinds'

type Icon = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

const catIcon: Record<string, Icon> = {
  social: Users, mensagens: MessageCircle, streaming: Clapperboard, jogos: Gamepad2, busca: Search, sistema: MonitorCog,
  nuvem: Cloud, compras: ShoppingCart, trabalho: Briefcase, bloqueado: ShieldBan, outros: Globe,
}
const catLabel: Record<string, string> = {
  social: t('Redes sociais'), mensagens: t('Mensagens'), streaming: t('Streaming'), jogos: t('Jogos'), busca: t('Busca e Google'),
  sistema: t('Sistema e atualizações'), nuvem: t('Nuvem e CDN'), compras: t('Compras'), trabalho: t('Trabalho'),
  bloqueado: t('Bloqueado'), outros: t('Outros'),
}

const ROW = 52 // altura de cada linha de nó
const TOP = 120 // espaço da internet acima do servidor
const NODE_W = 210

type Hover = { kind: 'device' | 'dest'; id: string } | null

export function NetworkMap() {
  const [range, setRange] = useState('1h')
  const [onlyActive, setOnlyActive] = useState(false)
  const [q, setQ] = useState('')
  const [view, setView] = useState<'map' | 'table'>('map')
  const [hover, setHover] = useState<Hover>(null)
  const [openId, setOpenId] = useState<string | null>(null)
  const topo = useQuery({
    queryKey: ['topology', range],
    queryFn: () => api<TopologyResponse>(`/api/topology${qs({ range })}`),
    refetchInterval: 15_000,
  })
  const devicesQ = useDevices()
  const wrap = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(1000)
  useLayoutEffect(() => {
    const el = wrap.current
    if (!el) return
    const ro = new ResizeObserver(() => setWidth(el.clientWidth))
    ro.observe(el)
    setWidth(el.clientWidth)
    return () => ro.disconnect()
  }, [view])
  // Em tela estreita o mapa não cabe: vira tabela.
  useEffect(() => {
    if (width < 760 && view === 'map') setView('table')
  }, [width, view])

  const m = topo.data?.map
  const devices = useMemo(() => {
    const term = q.trim().toLowerCase()
    return (m?.devices ?? []).filter(
      (d) => (!onlyActive || d.active) && (!term || [d.name, d.vendor, ...d.ips].some((v) => v?.toLowerCase().includes(term))),
    )
  }, [m, onlyActive, q])
  const shown = new Set(devices.map((d) => d.id))
  const links = (m?.links ?? []).filter((l) => shown.has(l.device))
  const dests = (m?.destinations ?? []).filter((d) => links.some((l) => l.dest === d.id))
  const opened = devicesQ.data?.find((d) => d.id === openId) ?? null

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label={t('Período')}
          value={range}
          onChange={setRange}
          options={[
            { value: '15m', label: t('15 min') },
            { value: '1h', label: t('1 hora') },
            { value: '24h', label: t('24 horas') },
          ]}
        />
        <div className="w-56">
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('Buscar dispositivo')} aria-label={t('Buscar dispositivo')} />
        </div>
        <LabeledSwitch checked={onlyActive} onChange={setOnlyActive} label={t('Só os ativos agora')} />
        <Segmented
          label={t('Visualização')}
          value={view}
          onChange={setView}
          options={[
            { value: 'map', label: <span className="flex items-center gap-1.5"><Waypoints className="size-3.5" aria-hidden />{t('Mapa')}</span> },
            { value: 'table', label: <span className="flex items-center gap-1.5"><Table2 className="size-3.5" aria-hidden />{t('Tabela')}</span> },
          ]}
        />
      </div>
      <ErrorNote error={topo.error} />
      {topo.data && !topo.data.history && (
        <p className="rounded-lg border border-line bg-surface px-3 py-2 text-xs text-ink-2">
          {t('O histórico detalhado está desligado (history.store_queries): o mapa mostra os aparelhos, mas não para onde cada um vai.')}
        </p>
      )}
      <Legend />
      <Card pad={false}>
        <div ref={wrap} className="relative overflow-x-auto">
          {!m ? (
            <p className="p-8 text-center text-sm text-muted">{t('Carregando…')}</p>
          ) : devices.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted">{t('Nenhum dispositivo com esse filtro.')}</p>
          ) : view === 'map' ? (
            <MapCanvas
              width={Math.max(width, 760)}
              devices={devices}
              dests={dests}
              links={links}
              upstreams={topo.data?.upstreams ?? []}
              hover={hover}
              setHover={setHover}
              onOpen={setOpenId}
            />
          ) : (
            <MapTable devices={devices} dests={dests} links={links} onOpen={setOpenId} />
          )}
        </div>
      </Card>
      <DeviceModal device={opened} onClose={() => setOpenId(null)} />
    </div>
  )
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-ink-2">
      <span className="flex items-center gap-1.5">
        <svg width="28" height="8" aria-hidden><line x1="0" y1="4" x2="28" y2="4" className="stroke-line-strong" strokeWidth="3" /></svg>
        {t('consultas permitidas (espessura = volume)')}
      </span>
      <span className="flex items-center gap-1.5">
        <svg width="28" height="8" aria-hidden><line x1="0" y1="4" x2="28" y2="4" stroke="var(--critical)" strokeWidth="2" strokeDasharray="4 3" /></svg>
        {t('mais da metade bloqueada')}
      </span>
      <span className="flex items-center gap-1.5">
        <Lock className="size-3.5 text-critical" aria-hidden />
        {t('bloqueado (sem DNS)')}
      </span>
      <span className="flex items-center gap-1.5">
        <ShieldAlert className="size-3.5 text-warning" aria-hidden />
        {t('alertas abertos')}
      </span>
      <span>{t('Passe o mouse num aparelho para ver com quem ele fala; clique para abrir e bloquear.')}</span>
    </div>
  )
}

type Pos = { x: number; y: number }

function MapCanvas({ width, devices, dests, links, upstreams, hover, setHover, onOpen }: {
  width: number
  devices: TopoDevice[]
  dests: TopoDest[]
  links: TopologyResponse['map']['links']
  upstreams: TopologyResponse['upstreams']
  hover: Hover
  setHover: (h: Hover) => void
  onOpen: (id: string) => void
}) {
  // Linhas: aparelhos agrupados (cabeçalho por grupo), destinos em lista.
  const rows: ({ type: 'group'; name: string } | { type: 'device'; d: TopoDevice })[] = []
  let lastGroup: string | undefined = '\u0000'
  for (const d of devices) {
    if ((d.group ?? '') !== lastGroup) {
      lastGroup = d.group ?? ''
      if (devices.some((x) => x.group)) rows.push({ type: 'group', name: d.group || t('Sem grupo') })
    }
    rows.push({ type: 'device', d })
  }
  const leftRows = rows.length
  const maxRows = Math.max(leftRows, dests.length, 4)
  const height = TOP + maxRows * ROW + 24
  const xDev = 12
  const xDest = width - NODE_W - 12
  const hub: Pos = { x: width / 2, y: TOP + (maxRows * ROW) / 2 }
  // A coluna mais curta fica centrada na altura do servidor.
  const devTop = TOP + ((maxRows - leftRows) * ROW) / 2
  const destTop = TOP + ((maxRows - dests.length) * ROW) / 2
  const internet: Pos = { x: width / 2, y: 44 }

  const devPos = new Map<string, Pos>()
  rows.forEach((r, i) => {
    if (r.type === 'device') devPos.set(r.d.id, { x: xDev + NODE_W, y: devTop + i * ROW + ROW / 2 })
  })
  const destPos = new Map<string, Pos>()
  dests.forEach((d, i) => destPos.set(d.id, { x: xDest, y: destTop + i * ROW + ROW / 2 }))

  const maxDev = Math.max(1, ...devices.map((d) => d.queries))
  const maxDest = Math.max(1, ...dests.map((d) => d.queries))
  const maxLink = Math.max(1, ...links.map((l) => l.queries))
  const w = (v: number, max: number) => 1 + 5 * Math.sqrt(v / max)
  const curve = (a: Pos, b: Pos) => {
    const mx = (a.x + b.x) / 2
    return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`
  }
  const viaHub = (a: Pos, b: Pos) => `M${a.x},${a.y} C${hub.x},${a.y} ${hub.x},${b.y} ${b.x},${b.y}`

  const focus = hover
    ? links.filter((l) => (hover.kind === 'device' ? l.device === hover.id : l.dest === hover.id))
    : []
  const focusDevices = new Set(focus.map((l) => l.device))
  const focusDests = new Set(focus.map((l) => l.dest))
  const dimDevice = (id: string) => !!hover && !(hover.kind === 'device' ? hover.id === id : focusDevices.has(id))
  const dimDest = (id: string) => !!hover && !(hover.kind === 'dest' ? hover.id === id : focusDests.has(id))
  const healthy = upstreams.filter((u) => u.healthy).length

  return (
    <div className="relative" style={{ width, height }} onMouseLeave={() => setHover(null)}>
      <svg width={width} height={height} className="absolute inset-0" aria-hidden>
        {/* servidor ↔ internet */}
        <path d={`M${hub.x},${hub.y - 30} L${internet.x},${internet.y + 26}`} className="stroke-line-strong" strokeWidth={2} fill="none" />
        {!hover &&
          devices.map((d) => {
            const p = devPos.get(d.id)!
            return (
              <path
                key={'dh' + d.id}
                d={curve(p, { x: hub.x - 30, y: hub.y })}
                fill="none"
                stroke={d.isolated ? 'var(--critical)' : 'var(--color-line-strong)'}
                strokeDasharray={d.isolated ? '5 4' : undefined}
                strokeWidth={d.isolated ? 2 : w(d.queries, maxDev)}
                strokeOpacity={d.active || d.isolated ? 0.9 : 0.35}
              />
            )
          })}
        {!hover &&
          dests.map((d) => {
            const p = destPos.get(d.id)!
            const bad = d.blocked * 2 > d.queries
            return (
              <path
                key={'hd' + d.id}
                d={curve({ x: hub.x + 30, y: hub.y }, p)}
                fill="none"
                stroke={bad ? 'var(--critical)' : 'var(--color-line-strong)'}
                strokeDasharray={bad ? '5 4' : undefined}
                strokeWidth={bad ? 2 : w(d.queries, maxDest)}
                strokeOpacity={0.8}
              />
            )
          })}
        {focus.map((l) => {
          const a = devPos.get(l.device)
          const b = destPos.get(l.dest)
          if (!a || !b) return null
          const bad = l.blocked * 2 > l.queries
          return (
            <path
              key={'f' + l.device + l.dest}
              d={viaHub(a, b)}
              fill="none"
              stroke={bad ? 'var(--critical)' : 'var(--accent)'}
              strokeDasharray={bad ? '5 4' : undefined}
              strokeWidth={bad ? 2 : w(l.queries, maxLink) + 0.5}
            />
          )
        })}
      </svg>

      {/* Internet e upstreams */}
      <div className="absolute flex -translate-x-1/2 flex-col items-center" style={{ left: internet.x, top: internet.y - 30 }}>
        <span className="grid size-12 place-items-center rounded-full border border-line-strong bg-surface-2 text-ink" title={t('Internet')}>
          <Earth className="size-6" aria-hidden />
        </span>
        <span className="mt-1 text-[11px] whitespace-nowrap text-ink-2">
          {t('Internet')} · {t('{n} de {total} upstreams respondendo', { n: healthy, total: upstreams.length })}
        </span>
      </div>

      {/* O próprio HeimdallDNS */}
      <div className="absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center" style={{ left: hub.x, top: hub.y }}>
        <span className="grid size-16 place-items-center rounded-2xl border-2 border-accent bg-accent-soft shadow-lg">
          <Logo className="size-9" />
        </span>
        <span className="mt-1 text-xs font-semibold text-ink">HeimdallDNS</span>
      </div>

      {rows.map((r, i) =>
        r.type === 'group' ? (
          <p key={'g' + i} className="absolute text-[11px] font-semibold tracking-wide text-muted uppercase" style={{ left: xDev + 4, top: devTop + i * ROW + 22 }}>
            {r.name}
          </p>
        ) : (
          <DeviceNode
            key={r.d.id}
            d={r.d}
            style={{ left: xDev, top: devTop + i * ROW + 4, width: NODE_W }}
            dim={dimDevice(r.d.id)}
            onHover={() => setHover({ kind: 'device', id: r.d.id })}
            onOpen={() => onOpen(r.d.id)}
          />
        ),
      )}
      {dests.map((d, i) => (
        <DestNode key={d.id} d={d} style={{ left: xDest, top: destTop + i * ROW + 4, width: NODE_W }} dim={dimDest(d.id)} onHover={() => setHover({ kind: 'dest', id: d.id })} />
      ))}
    </div>
  )
}

function DeviceNode({ d, style, dim, onHover, onOpen }: { d: TopoDevice; style: React.CSSProperties; dim: boolean; onHover: () => void; onOpen: () => void }) {
  const Icon = kindIcon[d.kind] ?? CircleHelp
  return (
    <button
      type="button"
      onMouseEnter={onHover}
      onFocus={onHover}
      onClick={onOpen}
      style={style}
      title={`${d.name} · ${kindLabel[d.kind] ?? d.kind}${d.vendor ? ' · ' + d.vendor : ''}`}
      className={cx(
        'absolute flex h-11 items-center gap-2 rounded-lg border bg-surface px-2 text-left transition-opacity',
        d.isolated ? 'border-critical' : 'border-line hover:border-accent',
        dim && 'opacity-30',
      )}
    >
      <span
        className={cx(
          'relative grid size-8 shrink-0 place-items-center rounded-full',
          d.isolated ? 'bg-critical-soft text-critical-ink' : d.active ? 'bg-accent-soft text-accent' : 'bg-surface-2 text-muted',
        )}
      >
        <Icon className="size-4" aria-hidden />
        {d.isolated && <Lock className="absolute -right-1 -bottom-1 size-3.5 rounded-full bg-surface text-critical" aria-hidden />}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-xs font-medium text-ink">{d.name}</span>
        <span className="block truncate text-[10px] text-muted">
          {d.isolated ? t('bloqueado') : t('{n} consultas', { n: fmtInt(d.queries) })}
          {d.blocked > 0 && !d.isolated ? ' · ' + t('{n} bloq.', { n: fmtInt(d.blocked) }) : ''}
        </span>
      </span>
      {d.alerts > 0 && (
        <span className="flex items-center gap-0.5 text-[10px] font-semibold text-warning" title={t('{n} alertas abertos', { n: d.alerts })}>
          <ShieldAlert className="size-3.5" aria-hidden />
          {d.alerts}
        </span>
      )}
    </button>
  )
}

function DestNode({ d, style, dim, onHover }: { d: TopoDest; style: React.CSSProperties; dim: boolean; onHover: () => void }) {
  const Icon = catIcon[d.category] ?? Globe
  const pct = d.queries ? (d.blocked / d.queries) * 100 : 0
  return (
    <div
      tabIndex={0}
      onMouseEnter={onHover}
      onFocus={onHover}
      style={style}
      title={`${d.name} · ${catLabel[d.category] ?? d.category}`}
      className={cx(
        'absolute flex h-11 items-center gap-2 rounded-lg border bg-surface px-2 transition-opacity',
        d.category === 'bloqueado' ? 'border-critical/60' : 'border-line',
        dim && 'opacity-30',
      )}
    >
      <span className={cx('grid size-8 shrink-0 place-items-center rounded-full', d.category === 'bloqueado' ? 'bg-critical-soft text-critical-ink' : 'bg-surface-2 text-ink-2')}>
        <Icon className="size-4" aria-hidden />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-xs font-medium text-ink">{d.name}</span>
        <span className="block truncate text-[10px] text-muted">
          {t('{n} consultas', { n: fmtInt(d.queries) })} · {t('{n} aparelho(s)', { n: d.devices })}
          {pct > 0 && d.category !== 'bloqueado' ? ' · ' + t('{p} bloq.', { p: fmtPct(pct) }) : ''}
        </span>
      </span>
    </div>
  )
}

/** A mesma informação em tabela (telas estreitas e leitores de tela). */
function MapTable({ devices, dests, links, onOpen }: {
  devices: TopoDevice[]
  dests: TopoDest[]
  links: TopologyResponse['map']['links']
  onOpen: (id: string) => void
}) {
  const destName = new Map(dests.map((d) => [d.id, d.name]))
  return (
    <table className="w-full min-w-[640px] text-sm">
      <thead className="text-left text-xs text-muted">
        <tr className="border-b border-line">
          <th className="px-4 py-2.5 font-medium">{t('Dispositivo')}</th>
          <th className="px-3 py-2.5 font-medium">{t('Tipo')}</th>
          <th className="px-3 py-2.5 text-right font-medium">{t('Consultas')}</th>
          <th className="px-3 py-2.5 font-medium">{t('Principais destinos')}</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => {
          const Icon = kindIcon[d.kind] ?? CircleHelp
          const top = links.filter((l) => l.device === d.id).slice(0, 5)
          return (
            <tr key={d.id} className="border-b border-line align-top last:border-0">
              <td className="px-4 py-2.5">
                <button className="flex items-center gap-2 text-left hover:text-accent" onClick={() => onOpen(d.id)}>
                  <Icon className={cx('size-4', d.isolated ? 'text-critical' : 'text-ink-2')} aria-hidden />
                  <span className="font-medium text-ink">{d.name}</span>
                  {d.isolated && (
                    <span className="flex items-center gap-1 text-xs text-critical-ink">
                      <Lock className="size-3" aria-hidden />
                      {t('bloqueado')}
                    </span>
                  )}
                </button>
              </td>
              <td className="px-3 py-2.5 text-xs text-ink-2">{kindLabel[d.kind] ?? d.kind}</td>
              <td className="tabular px-3 py-2.5 text-right text-xs text-ink-2">
                {fmtInt(d.queries)}
                {d.blocked > 0 && <span className="block text-muted">{t('{n} bloq.', { n: fmtInt(d.blocked) })}</span>}
              </td>
              <td className="px-3 py-2.5 text-xs text-ink-2">
                {top.length === 0
                  ? '—'
                  : top.map((l) => `${destName.get(l.dest) ?? l.dest} (${fmtInt(l.queries)}${l.blocked ? ', ' + t('{n} bloq.', { n: fmtInt(l.blocked) }) : ''})`).join(' · ')}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
