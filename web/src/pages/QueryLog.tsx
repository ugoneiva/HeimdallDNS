import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Ban, Check, Pause, Play, Radio, Search, Trash } from 'lucide-react'
import { api, qs } from '../api'
import type { QueryEntry } from '../types'
import { useSSE } from '../lib/sse'
import { fmtClock, fmtDateTime, fmtInt, fmtMs, isBlockedStatus, statusLabel } from '../lib/format'
import { Button, Card, ErrorNote, Input, Segmented, Select, StatusBadge, cx } from '../components/ui'
import { useDevices } from './Devices'
import { rangeOptions, type Range } from './Overview'

const MAX_ROWS = 5000
const ROW_H = 44

type Mode = 'live' | 'history'
type StatusFilter = '' | 'allowed' | 'blocked' | 'cached'

const types = ['', 'A', 'AAAA', 'HTTPS', 'CNAME', 'TXT', 'MX', 'PTR', 'SRV', 'SOA', 'NS']

function statusTone(s: string) {
  if (isBlockedStatus(s)) return 'critical' as const
  if (s === 'error' || s === 'refused') return 'warning' as const
  if (s === 'cached' || s === 'stale' || s === 'local') return 'accent' as const
  return 'neutral' as const
}

export function QueryLog() {
  const [mode, setMode] = useState<Mode>('live')
  const [client, setClient] = useState('')
  const [status, setStatus] = useState<StatusFilter>('')
  const [type, setType] = useState('')
  const [search, setSearch] = useState('')
  const [term, setTerm] = useState('') // busca aplicada (com atraso)
  const [range, setRange] = useState<Range>('24h')
  useEffect(() => {
    const t = setTimeout(() => setTerm(search.trim()), 300)
    return () => clearTimeout(t)
  }, [search])

  const devices = useDevices().data ?? []
  const filters = { client, status, type, q: term }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label="Modo"
          value={mode}
          onChange={setMode}
          options={[
            { value: 'live', label: 'Ao vivo' },
            { value: 'history', label: 'Histórico' },
          ]}
        />
        {mode === 'history' && <Segmented label="Período" value={range} onChange={setRange} options={rangeOptions} />}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted" aria-hidden />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Buscar domínio…" className="pl-9" aria-label="Buscar domínio" />
        </div>
        <Select
          label="Dispositivo"
          value={client}
          onChange={setClient}
          className="max-w-56"
          options={[{ value: '', label: 'Todos os dispositivos' }, ...devices.map((d) => ({ value: d.id, label: d.display }))]}
        />
        <Segmented
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: '', label: 'Todas' },
            { value: 'allowed', label: 'Permitidas' },
            { value: 'blocked', label: 'Bloqueadas' },
            { value: 'cached', label: 'Cache' },
          ]}
        />
        <Select label="Tipo" value={type} onChange={setType} options={types.map((t) => ({ value: t, label: t || 'Todos os tipos' }))} />
      </div>
      {mode === 'live' ? <LiveLog filters={filters} /> : <HistoryLog filters={filters} range={range} />}
    </div>
  )
}

type Filters = { client: string; status: string; type: string; q: string }

function LiveLog({ filters }: { filters: Filters }) {
  const [rows, setRows] = useState<(QueryEntry & { _k: number })[]>([])
  const [paused, setPaused] = useState(false)
  const [pending, setPending] = useState(0)
  const [dropped, setDropped] = useState(0)
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const buffer = useRef<(QueryEntry & { _k: number })[]>([])
  const seq = useRef(0)
  const rate = useRef<number[]>([])
  const [perSec, setPerSec] = useState(0)

  const url = `/api/queries/live${qs(filters)}`
  useEffect(() => {
    setRows([])
    buffer.current = []
    setPending(0)
  }, [url])

  const state = useSSE(url, {
    query: (d) => {
      const e = { ...(d as QueryEntry), _k: ++seq.current }
      buffer.current.push(e)
      rate.current.push(Date.now())
    },
    dropped: (d) => setDropped((n) => n + (d as { count: number }).count),
  })

  // Junta os eventos e desenha no máximo 4 vezes por segundo.
  useEffect(() => {
    const t = setInterval(() => {
      const now = Date.now()
      rate.current = rate.current.filter((x) => now - x < 5000)
      setPerSec(rate.current.length / 5)
      if (pausedRef.current) {
        setPending(buffer.current.length)
        return
      }
      if (!buffer.current.length) return
      const batch = buffer.current.reverse()
      buffer.current = []
      setPending(0)
      setRows((prev) => [...batch, ...prev].slice(0, MAX_ROWS))
    }, 250)
    return () => clearInterval(t)
  }, [])

  return (
    <Card pad={false}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex items-center gap-3 text-xs text-ink-2">
          {state === 'open' ? (
            <StatusBadge tone="good">
              <Radio className="size-3" aria-hidden /> Ao vivo
            </StatusBadge>
          ) : (
            <StatusBadge tone="warning">Reconectando…</StatusBadge>
          )}
          <span className="tabular">{perSec.toFixed(1).replace('.', ',')} consultas/s</span>
          <span className="tabular text-muted">{fmtInt(rows.length)} na tela</span>
          {dropped > 0 && (
            <span className="text-muted" title="O navegador não acompanhou o ritmo; essas consultas estão no histórico.">
              {fmtInt(dropped)} não exibidas
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant={paused ? 'primary' : 'secondary'}
            icon={paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
            onClick={() => setPaused(!paused)}
          >
            {paused ? `Retomar${pending ? ` (${fmtInt(pending)} novas)` : ''}` : 'Pausar'}
          </Button>
          <Button size="sm" variant="ghost" icon={<Trash className="size-3.5" />} onClick={() => setRows([])}>
            Limpar
          </Button>
        </div>
      </div>
      <QueryTable rows={rows} live empty={state === 'open' ? 'Aguardando consultas…' : 'Conectando ao servidor…'} />
    </Card>
  )
}

function HistoryLog({ filters, range }: { filters: Filters; range: Range }) {
  const q = useInfiniteQuery({
    queryKey: ['queries', filters, range],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api<{ queries: QueryEntry[]; next_before: number }>(`/api/queries${qs({ ...filters, range, limit: 200, before: pageParam || undefined })}`),
    getNextPageParam: (last) => last.next_before || undefined,
  })
  const rows = useMemo(() => (q.data?.pages ?? []).flatMap((p) => p.queries.map((e) => ({ ...e, _k: e.id ?? 0 }))), [q.data])
  return (
    <Card pad={false}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3 text-xs text-ink-2">
        <span className="tabular">{fmtInt(rows.length)} consultas carregadas</span>
        <Button size="sm" onClick={() => q.refetch()} loading={q.isRefetching}>
          Atualizar
        </Button>
      </div>
      <ErrorNote error={q.error} />
      <QueryTable
        rows={rows}
        empty={q.isLoading ? 'Carregando…' : 'Nenhuma consulta encontrada.'}
        onEnd={() => q.hasNextPage && !q.isFetchingNextPage && q.fetchNextPage()}
      />
    </Card>
  )
}

function QueryTable({ rows, live, empty, onEnd }: {
  rows: (QueryEntry & { _k: number })[]
  live?: boolean
  empty: string
  onEnd?: () => void
}) {
  const parent = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => ROW_H, overscan: 12 })
  const items = v.getVirtualItems()
  const last = items.at(-1)
  useEffect(() => {
    if (onEnd && last && last.index >= rows.length - 20) onEnd()
  }, [last?.index, rows.length, onEnd, last])

  const qc = useQueryClient()
  const quick = useMutation({
    mutationFn: (b: { domain: string; action: 'block' | 'allow' }) => api('/api/rules/quick', { method: 'POST', body: b }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })
  const [done, setDone] = useState<Record<string, string>>({})
  const act = useCallback(
    (domain: string, action: 'block' | 'allow') =>
      quick.mutate({ domain, action }, { onSuccess: () => setDone((d) => ({ ...d, [domain]: action })) }),
    [quick],
  )

  const cols = 'grid grid-cols-[96px_minmax(120px,1fr)_minmax(180px,2fr)_56px_112px_72px_92px] items-center gap-3'
  return (
    <div className="overflow-x-auto">
      <div className="min-w-[860px]">
        <div className={cx(cols, 'border-b border-line px-4 py-2 text-xs font-medium text-muted')}>
          <span>Hora</span>
          <span>Dispositivo</span>
          <span>Domínio</span>
          <span>Tipo</span>
          <span>Resultado</span>
          <span className="text-right">Tempo</span>
          <span />
        </div>
        <div ref={parent} className="h-[calc(100vh-330px)] min-h-80 overflow-y-auto">
          {rows.length === 0 ? (
            <p className="py-16 text-center text-sm text-muted">{empty}</p>
          ) : (
            <div style={{ height: v.getTotalSize(), position: 'relative' }}>
              {items.map((it) => {
                const e = rows[it.index]
                const blocked = isBlockedStatus(e.status)
                const did = done[e.name]
                return (
                  <div
                    key={e._k}
                    className={cx(cols, 'absolute inset-x-0 border-b border-line px-4 text-xs hover:bg-surface-2', live && it.index < 30 && 'row-new')}
                    style={{ top: it.start, height: ROW_H }}
                  >
                    <span className="tabular font-mono text-ink-2" title={fmtDateTime(e.time)}>
                      {live ? fmtClock(e.time) : fmtDateTime(e.time)}
                    </span>
                    <span className="truncate text-ink" title={e.client_ip}>
                      {e.client_name || e.client_ip}
                    </span>
                    <span className="min-w-0">
                      <span className={cx('block truncate font-mono', blocked ? 'text-critical-ink' : 'text-ink')} title={e.name}>
                        {e.name}
                      </span>
                      {e.rule && (
                        <span className="block truncate text-[11px] text-muted" title={e.rule}>
                          {e.category === 'threat' && <strong className="text-critical-ink">ameaça · </strong>}
                          {e.category === 'nrd' && <strong className="text-ink-2">recém-registrado · </strong>}
                          {e.rule}
                        </span>
                      )}
                    </span>
                    <span className="font-mono text-ink-2">{e.type}</span>
                    <span>
                      <StatusBadge tone={statusTone(e.status)}>{statusLabel[e.status] ?? e.status}</StatusBadge>
                    </span>
                    <span className="tabular text-right text-ink-2">{fmtMs(e.duration_ms)}</span>
                    <span className="flex justify-end">
                      {did ? (
                        <span className="text-[11px] text-muted">{did === 'block' ? 'bloqueado' : 'liberado'}</span>
                      ) : blocked ? (
                        <button
                          onClick={() => act(e.name, 'allow')}
                          className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[11px] text-ink-2 hover:bg-surface-3 hover:text-ink"
                          title={`Liberar ${e.name} para todos`}
                        >
                          <Check className="size-3" aria-hidden /> Liberar
                        </button>
                      ) : (
                        <button
                          onClick={() => act(e.name, 'block')}
                          className="inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-[11px] text-ink-2 hover:bg-surface-3 hover:text-ink"
                          title={`Bloquear ${e.name} para todos`}
                        >
                          <Ban className="size-3" aria-hidden /> Bloquear
                        </button>
                      )}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
      {quick.error && (
        <div className="p-3">
          <ErrorNote error={quick.error} />
        </div>
      )}
    </div>
  )
}
