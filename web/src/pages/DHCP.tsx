import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pin, Plus, Trash } from 'lucide-react'
import { api } from '../api'
import type { DHCPState } from '../types'
import { ago, fmtDateTime } from '../lib/format'
import { Button, Card, ErrorNote, Input, StatusBadge } from '../components/ui'

export function useDHCP() {
  return useQuery({ queryKey: ['dhcp'], queryFn: () => api<DHCPState>('/api/dhcp'), refetchInterval: 10_000 })
}

export function DHCP({ onOpenDevice }: { onOpenDevice: (id: string) => void }) {
  const qc = useQueryClient()
  const q = useDHCP()
  const set = (d: DHCPState) => qc.setQueryData(['dhcp'], d)
  const reserve = useMutation({
    mutationFn: (b: { mac: string; ip: string; name?: string }) => api<DHCPState>('/api/dhcp/reservations', { method: 'POST', body: b }),
    onSuccess: set,
  })
  const unreserve = useMutation({
    mutationFn: (mac: string) => api<DHCPState>(`/api/dhcp/reservations/${encodeURIComponent(mac)}`, { method: 'DELETE' }),
    onSuccess: set,
  })
  const [form, setForm] = useState({ mac: '', ip: '', name: '' })
  const d = q.data
  if (!d) return null
  if (!d.enabled || !d.config) {
    return <p className="text-sm text-muted">O DHCP está desligado. Veja Configurações para ligar.</p>
  }
  const c = d.config
  const leases = d.leases ?? []
  const active = leases.filter((l) => l.active).length

  return (
    <div className="space-y-5">
      <Card title="Configuração" subtitle="Definida no heimdalldns.yaml (seção dhcp)">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs sm:grid-cols-4">
          {(
            [
              ['Interface', c.interface],
              ['Faixa', `${c.range_start} – ${c.range_end}`],
              ['Sub-rede', c.subnet],
              ['Este servidor', c.server_ip],
              ['Roteador', (c.routers ?? []).join(', ') || '—'],
              ['DNS entregue', c.dns.join(', ')],
              ['Domínio', c.domain || '—'],
              ['Concessão', c.lease_time],
            ] as const
          ).map(([k, v]) => (
            <div key={k}>
              <dt className="text-muted">{k}</dt>
              <dd className="mt-0.5 font-mono text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Card title="Concessões" subtitle={`${active} ativas · nomes resolvem como <nome>.${c.domain || 'lan'}`} pad={false}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-y border-line">
                <th className="px-4 py-2.5 font-medium">IP</th>
                <th className="px-3 py-2.5 font-medium">Aparelho</th>
                <th className="px-3 py-2.5 font-medium">MAC</th>
                <th className="px-3 py-2.5 font-medium">Vence</th>
                <th className="px-3 py-2.5 font-medium">Situação</th>
                <th className="w-28 px-3 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {leases.map((l) => (
                <tr key={l.ip} className="border-b border-line last:border-0">
                  <td className="px-4 py-2.5 font-mono text-xs text-ink">{l.ip}</td>
                  <td className="px-3 py-2.5">
                    {l.client_id ? (
                      <button onClick={() => onOpenDevice(l.client_id!)} className="text-ink hover:text-accent">
                        {l.client_name || l.hostname || l.mac}
                      </button>
                    ) : (
                      <span className="text-ink">{l.hostname || '—'}</span>
                    )}
                    {l.hostname && <span className="block font-mono text-[11px] text-muted">{l.hostname}.{c.domain}</span>}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-ink-2">{l.mac}</td>
                  <td className="px-3 py-2.5 text-xs text-ink-2" title={fmtDateTime(l.expires)}>
                    {l.active ? fmtDateTime(l.expires) : `vencida ${ago(l.expires)}`}
                  </td>
                  <td className="px-3 py-2.5">
                    {l.reserved ? (
                      <StatusBadge tone="accent">Reservado</StatusBadge>
                    ) : l.active ? (
                      <StatusBadge tone="good">Ativa</StatusBadge>
                    ) : (
                      <StatusBadge tone="neutral">Vencida</StatusBadge>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    {!l.reserved && (
                      <Button size="sm" variant="ghost" icon={<Pin className="size-3.5" />} onClick={() => reserve.mutate({ mac: l.mac, ip: l.ip, name: l.hostname })}>
                        Fixar IP
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {leases.length === 0 && <p className="py-8 text-center text-sm text-muted">Nenhuma concessão ainda.</p>}
        </div>
      </Card>

      <Card title="Reservas" subtitle="O aparelho sempre recebe o mesmo IP (pode ser fora da faixa)">
        <ul className="mb-4 divide-y divide-line">
          {(d.reservations ?? []).map((r) => (
            <li key={r.mac} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <span className="w-32 font-mono text-xs text-ink">{r.ip}</span>
              <span className="w-40 font-mono text-xs text-ink-2">{r.mac}</span>
              <span className="flex-1 text-ink">{r.name || '—'}</span>
              <Button size="sm" variant="ghost" icon={<Trash className="size-3.5" />} onClick={() => unreserve.mutate(r.mac)} aria-label={`Remover reserva de ${r.mac}`}>
                Remover
              </Button>
            </li>
          ))}
        </ul>
        <form
          className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]"
          onSubmit={(e) => {
            e.preventDefault()
            reserve.mutate(form, { onSuccess: () => setForm({ mac: '', ip: '', name: '' }) })
          }}
        >
          <Input value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} placeholder="MAC (aa:bb:cc:dd:ee:ff)" aria-label="MAC" required />
          <Input value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} placeholder="IP" aria-label="IP" required />
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Nome (vira nome.lan)" aria-label="Nome" />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={reserve.isPending}>
            Reservar
          </Button>
        </form>
        <div className="mt-3">
          <ErrorNote error={reserve.error || unreserve.error} />
        </div>
      </Card>
    </div>
  )
}
