import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ellipsis, Search, ShieldBan } from 'lucide-react'
import { api } from '../api'
import type { Device } from '../types'
import { ago, fmtInt, fmtPct } from '../lib/format'
import { Card, Input, Segmented, StatusBadge, Switch, cx } from '../components/ui'
import { Radar } from '../components/Radar'
import { DeviceModal } from './DeviceModal'
import { GroupsCard } from './Groups'

type Filter = 'all' | 'active' | 'isolated' | 'rules'

export function useDevices() {
  return useQuery({ queryKey: ['clients'], queryFn: () => api<Device[]>('/api/clients'), refetchInterval: 5000 })
}

export function Devices({ openId, onOpen }: { openId: string | null; onOpen: (id: string | null) => void }) {
  const { data = [], isLoading } = useDevices()
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 2000)
    return () => clearInterval(t)
  }, [])

  const toggle = useMutation({
    mutationFn: ({ d, on }: { d: Device; on: boolean }) =>
      api(`/api/clients/${encodeURIComponent(d.id)}/${on ? 'release' : 'isolate'}`, {
        method: 'POST',
        body: on ? undefined : { reason: 'Isolado pelo painel' },
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: ['clients'] }),
  })

  const active = data.filter((d) => now - Date.parse(d.last_seen) < 5 * 60_000).length
  const isolated = data.filter((d) => d.settings.isolated).length
  const withRules = data.filter((d) => (d.settings.deny?.length ?? 0) + (d.settings.allow?.length ?? 0) > 0 || d.settings.skip_global_lists).length

  const rows = useMemo(() => {
    const term = q.trim().toLowerCase()
    return data.filter((d) => {
      if (filter === 'active' && now - Date.parse(d.last_seen) >= 5 * 60_000) return false
      if (filter === 'isolated' && !d.settings.isolated) return false
      if (filter === 'rules' && !((d.settings.deny?.length ?? 0) + (d.settings.allow?.length ?? 0) || d.settings.skip_global_lists)) return false
      if (!term) return true
      return [d.display, d.hostname, d.vendor, d.mac, ...d.ips].some((v) => v?.toLowerCase().includes(term))
    })
    // Ordem estável (por nome): as linhas não trocam de lugar a cada atualização,
    // o que evitaria clicar no interruptor do aparelho errado.
    .sort((a, b) => a.display.localeCompare(b.display, 'pt-BR', { numeric: true }) || a.id.localeCompare(b.id))
  }, [data, q, filter, now])

  const open = data.find((d) => d.id === openId) ?? null

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
        <Card title="Radar" subtitle="Dispositivos ativos nos últimos 30 minutos">
          <Radar devices={data} now={now} />
        </Card>
        <div className="grid grid-cols-2 gap-3 self-start sm:grid-cols-4">
          {[
            ['Dispositivos conhecidos', data.length],
            ['Ativos (5 min)', active],
            ['Isolados', isolated],
            ['Com regras próprias', withRules],
          ].map(([l, v]) => (
            <div key={l} className="rounded-xl border border-line bg-surface px-4 py-3.5">
              <p className="text-xs text-muted">{l}</p>
              <p className="mt-1 text-2xl font-semibold text-ink">{fmtInt(v as number)}</p>
            </div>
          ))}
          <p className="col-span-full text-xs leading-relaxed text-muted">
            O interruptor <strong className="text-ink-2">Acesso</strong> isola o dispositivo na hora: o DNS passa a recusar
            todas as consultas dele. Use <Ellipsis className="inline size-3.5" aria-label="detalhes" /> para escolher o modo,
            liberar exceções ou criar regras só para aquele aparelho.
          </p>
        </div>
      </div>

      <Card pad={false}>
        <div className="flex flex-wrap items-center gap-3 border-b border-line p-4">
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted" aria-hidden />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Nome, IP, MAC, fabricante…" className="pl-9" aria-label="Buscar dispositivo" />
          </div>
          <Segmented
            label="Mostrar"
            value={filter}
            onChange={setFilter}
            options={[
              { value: 'all', label: 'Todos' },
              { value: 'active', label: 'Ativos' },
              { value: 'isolated', label: 'Isolados' },
              { value: 'rules', label: 'Com regras' },
            ]}
          />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line">
                <th className="px-4 py-2.5 font-medium">Dispositivo</th>
                <th className="px-3 py-2.5 font-medium">Endereço</th>
                <th className="px-3 py-2.5 font-medium">Visto</th>
                <th className="px-3 py-2.5 text-right font-medium">Consultas</th>
                <th className="px-3 py-2.5 text-right font-medium">Bloqueadas</th>
                <th className="px-3 py-2.5 font-medium">Estado</th>
                <th className="px-3 py-2.5 font-medium">Acesso</th>
                <th className="w-10 px-3 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => {
                const fresh = now - Date.parse(d.last_seen) < 60_000
                const rules = (d.settings.deny?.length ?? 0) + (d.settings.allow?.length ?? 0) > 0 || d.settings.skip_global_lists
                return (
                  <tr key={d.id} className="border-b border-line last:border-0 hover:bg-surface-2">
                    <td className="px-4 py-2.5">
                      <button onClick={() => onOpen(d.id)} className="text-left">
                        <span className="flex items-center gap-2 font-medium text-ink hover:text-accent">
                          <span
                            aria-hidden
                            className={cx('size-2 shrink-0 rounded-full', d.settings.isolated ? 'bg-critical' : fresh ? 'bg-good' : 'bg-surface-3')}
                          />
                          {d.display}
                        </span>
                        <span className="ml-4 block text-xs text-muted">
                          {[d.hostname !== d.display && d.hostname, d.vendor].filter(Boolean).join(' · ') || '—'}
                        </span>
                      </button>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-ink-2">
                      {d.ips[0] ?? '—'}
                      {d.ips.length > 1 && <span className="text-muted"> +{d.ips.length - 1}</span>}
                      <span className="block text-muted">{d.mac ?? 'MAC desconhecido'}</span>
                    </td>
                    <td className="px-3 py-2.5 text-xs whitespace-nowrap text-ink-2">{ago(d.last_seen, now)}</td>
                    <td className="tabular px-3 py-2.5 text-right text-ink-2">{fmtInt(d.queries)}</td>
                    <td className="tabular px-3 py-2.5 text-right text-ink-2">
                      {fmtInt(d.blocked)}
                      <span className="block text-[11px] text-muted">{d.queries ? fmtPct((d.blocked / d.queries) * 100) : '—'}</span>
                    </td>
                    <td className="px-3 py-2.5">
                      {d.settings.isolated ? (
                        <StatusBadge tone="critical">Isolado</StatusBadge>
                      ) : rules ? (
                        <StatusBadge tone="accent">Regras próprias</StatusBadge>
                      ) : (
                        <StatusBadge tone="neutral">Normal</StatusBadge>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <Switch
                        checked={!d.settings.isolated}
                        label={d.settings.isolated ? `Liberar ${d.display}` : `Isolar ${d.display}`}
                        disabled={toggle.isPending && toggle.variables?.d.id === d.id}
                        onChange={(on) => toggle.mutate({ d, on })}
                      />
                    </td>
                    <td className="px-3 py-2.5">
                      <button onClick={() => onOpen(d.id)} aria-label={`Detalhes de ${d.display}`} className="rounded-md p-1.5 text-muted hover:bg-surface-3 hover:text-ink">
                        <Ellipsis className="size-4" />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {!isLoading && rows.length === 0 && (
            <p className="flex items-center justify-center gap-2 py-10 text-sm text-muted">
              <ShieldBan className="size-4" aria-hidden />
              {data.length ? 'Nenhum dispositivo com esse filtro.' : 'Nenhum dispositivo consultou o DNS ainda.'}
            </p>
          )}
        </div>
      </Card>

      <GroupsCard />

      <DeviceModal device={open} onClose={() => onOpen(null)} />
    </div>
  )
}
