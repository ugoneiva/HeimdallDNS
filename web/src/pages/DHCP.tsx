// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pin, Plus, Trash } from 'lucide-react'
import { api } from '../api'
import type { DHCPState } from '../types'
import { ago, fmtDateTime } from '../lib/format'
import { Button, Card, ErrorNote, Input, StatusBadge } from '../components/ui'
import { t } from '../lib/i18n'

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
    return <p className="text-sm text-muted">{t('O DHCP está desligado. Veja Configurações para ligar.')}</p>
  }
  const c = d.config
  const leases = d.leases ?? []
  const active = leases.filter((l) => l.active).length

  return (
    <div className="space-y-5">
      <Card title={t('Configuração')} subtitle={t('Definida no heimdalldns.yaml (seção dhcp)')}>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs sm:grid-cols-4">
          {(
            [
              [t('Interface'), c.interface],
              [t('Faixa'), `${c.range_start} – ${c.range_end}`],
              [t('Sub-rede'), c.subnet],
              [t('Este servidor'), c.server_ip],
              [t('Roteador'), (c.routers ?? []).join(', ') || '—'],
              [t('DNS entregue'), c.dns.join(', ')],
              [t('Domínio'), c.domain || '—'],
              [t('Concessão'), c.lease_time],
            ] as const
          ).map(([k, v]) => (
            <div key={k}>
              <dt className="text-muted">{k}</dt>
              <dd className="mt-0.5 font-mono text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Card title={t('Concessões')} subtitle={t('{n} ativas · nomes resolvem como <nome>.{dominio}', { n: active, dominio: c.domain || 'lan' })} pad={false}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-y border-line">
                <th className="px-4 py-2.5 font-medium">{t('IP')}</th>
                <th className="px-3 py-2.5 font-medium">{t('Aparelho')}</th>
                <th className="px-3 py-2.5 font-medium">{t('MAC')}</th>
                <th className="px-3 py-2.5 font-medium">{t('Vence')}</th>
                <th className="px-3 py-2.5 font-medium">{t('Situação')}</th>
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
                    {l.active ? fmtDateTime(l.expires) : t('vencida {quando}', { quando: ago(l.expires) })}
                  </td>
                  <td className="px-3 py-2.5">
                    {l.reserved ? (
                      <StatusBadge tone="accent">{t('Reservado')}</StatusBadge>
                    ) : l.active ? (
                      <StatusBadge tone="good">{t('Ativa')}</StatusBadge>
                    ) : (
                      <StatusBadge tone="neutral">{t('Vencida')}</StatusBadge>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    {!l.reserved && (
                      <Button size="sm" variant="ghost" icon={<Pin className="size-3.5" />} onClick={() => reserve.mutate({ mac: l.mac, ip: l.ip, name: l.hostname })}>
                        {t('Fixar IP')}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {leases.length === 0 && <p className="py-8 text-center text-sm text-muted">{t('Nenhuma concessão ainda.')}</p>}
        </div>
      </Card>

      <Card title={t('Reservas')} subtitle={t('O aparelho sempre recebe o mesmo IP (pode ser fora da faixa)')}>
        <ul className="mb-4 divide-y divide-line">
          {(d.reservations ?? []).map((r) => (
            <li key={r.mac} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <span className="w-32 font-mono text-xs text-ink">{r.ip}</span>
              <span className="w-40 font-mono text-xs text-ink-2">{r.mac}</span>
              <span className="flex-1 text-ink">{r.name || '—'}</span>
              <Button size="sm" variant="ghost" icon={<Trash className="size-3.5" />} onClick={() => unreserve.mutate(r.mac)} aria-label={t('Remover reserva de {mac}', { mac: r.mac })}>
                {t('Remover')}
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
          <Input value={form.mac} onChange={(e) => setForm({ ...form, mac: e.target.value })} placeholder={t('MAC (aa:bb:cc:dd:ee:ff)')} aria-label={t('MAC')} required />
          <Input value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} placeholder={t('IP')} aria-label={t('IP')} required />
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t('Nome (vira nome.lan)')} aria-label={t('Nome')} />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={reserve.isPending}>
            {t('Reservar')}
          </Button>
        </form>
        <div className="mt-3">
          <ErrorNote error={reserve.error || unreserve.error} />
        </div>
      </Card>
    </div>
  )
}
