// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleAlert, CircleCheck, EyeOff, Lock, ShieldAlert, ShieldCheck, TriangleAlert } from 'lucide-react'
import { api, qs } from '../api'
import type { SecurityEvent, SecuritySettings, SecuritySummary } from '../types'
import { ago, fmtDateTime, fmtInt, kindLabel, severityLabel } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, Modal, Segmented, Select, Switch, Textarea, cx } from '../components/ui'
import { EmptyArt } from '../components/art'
import { t } from '../lib/i18n'

export function useSecuritySummary() {
  return useQuery({
    queryKey: ['security-summary'],
    queryFn: () => api<SecuritySummary>('/api/security/summary'),
    refetchInterval: 10_000,
  })
}

/** Gravidade sempre com ícone + texto (paleta de status, nunca só cor). */
export function SeverityBadge({ sev }: { sev: SecurityEvent['severity'] }) {
  const Icon = sev === 'critical' || sev === 'high' ? CircleAlert : sev === 'medium' ? TriangleAlert : ShieldCheck
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold whitespace-nowrap',
        sev === 'critical' && 'bg-critical text-white',
        sev === 'high' && 'bg-critical-soft text-critical-ink',
        sev === 'medium' && 'bg-warning-soft text-ink',
        sev === 'low' && 'bg-surface-3 text-ink-2',
      )}
    >
      <Icon className="size-3" aria-hidden />
      {severityLabel[sev] ?? sev}
    </span>
  )
}

type StatusFilter = 'open' | 'ack' | ''

export function Security({ onOpenDevice }: { onOpenDevice: (id: string) => void }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<StatusFilter>('open')
  const [kind, setKind] = useState('')
  const [range, setRange] = useState('7d')
  const [detail, setDetail] = useState<SecurityEvent | null>(null)
  const summary = useSecuritySummary()
  const events = useQuery({
    queryKey: ['security-events', status, kind, range],
    queryFn: () => api<SecurityEvent[]>(`/api/security/events${qs({ status, kind, range, limit: 300 })}`),
    refetchInterval: 10_000,
  })
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['security-events'] })
    qc.invalidateQueries({ queryKey: ['security-summary'] })
  }
  const setEv = useMutation({
    mutationFn: ({ id, to }: { id: number | 'all'; to: 'ack' | 'reopen' }) => api(`/api/security/events/${id}/${to}`, { method: 'POST' }),
    onSuccess: refresh,
  })
  const ignore = useMutation({
    mutationFn: (domain: string) => api('/api/security/ignore', { method: 'POST', body: { domain } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['security-settings'] }),
  })
  const isolate = useMutation({
    mutationFn: (e: SecurityEvent) =>
      api(`/api/clients/${encodeURIComponent(e.client_id!)}/isolate`, {
        method: 'POST',
        body: { reason: `Alerta: ${kindLabel[e.kind] ?? e.kind}` },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
  })

  const s = summary.data
  const sevs: SecurityEvent['severity'][] = ['critical', 'high', 'medium', 'low']
  const list = events.data ?? []

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {sevs.map((sv) => (
          <div key={sv} className="rounded-xl border border-line bg-surface px-4 py-3.5">
            <p className="flex items-center gap-2 text-xs text-muted">
              {t('Abertos')}{' '}<SeverityBadge sev={sv} />
            </p>
            <p className="mt-1 text-2xl font-semibold text-ink">{fmtInt(s?.open[sv] ?? 0)}</p>
          </div>
        ))}
      </div>

      <Card title={t('Últimas 24 horas')} subtitle={t('Ocorrências por tipo de detecção (repetições somadas)')}>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {Object.keys(kindLabel).map((k) => (
            <li key={k} className="rounded-lg border border-line px-3 py-2.5">
              <p className="text-[11px] text-muted">{kindLabel[k]}</p>
              <p className="mt-0.5 text-lg font-semibold text-ink">{fmtInt(s?.last_24h[k] ?? 0)}</p>
            </li>
          ))}
        </ul>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        <Segmented
          label={t('Situação')}
          value={status}
          onChange={setStatus}
          options={[
            { value: 'open', label: t('Abertos') },
            { value: 'ack', label: t('Reconhecidos') },
            { value: '', label: t('Todos') },
          ]}
        />
        <Select
          label={t('Tipo')}
          value={kind}
          onChange={setKind}
          options={[{ value: '', label: t('Todos os tipos') }, ...Object.entries(kindLabel).map(([value, label]) => ({ value, label }))]}
        />
        <Segmented
          label={t('Período')}
          value={range}
          onChange={setRange}
          options={[
            { value: '24h', label: t('24 horas') },
            { value: '7d', label: t('7 dias') },
            { value: '30d', label: t('30 dias') },
            { value: '90d', label: t('90 dias') },
          ]}
        />
        {status === 'open' && list.length > 0 && (
          <Button size="sm" className="ml-auto" loading={setEv.isPending} onClick={() => setEv.mutate({ id: 'all', to: 'ack' })}>
            {t('Reconhecer todos')}
          </Button>
        )}
      </div>

      <Card pad={false}>
        <ErrorNote error={events.error || setEv.error || ignore.error || isolate.error} />
        {list.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-sm text-muted">
            {!events.isLoading && <EmptyArt kind="calm" className="h-24" />}
            <p className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-good" aria-hidden />
              {events.isLoading ? t('Carregando…') : status === 'open' ? t('Nenhum alerta aberto.') : t('Nenhum alerta no período.')}
            </p>
            {!events.isLoading && status === 'open' && <p className="text-xs">{t('O Gjallarhorn está em silêncio: a rede está tranquila.')}</p>}
          </div>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((e) => (
              <li key={e.id} className={cx('flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3 sm:px-5', e.status === 'ack' && 'opacity-70')}>
                <div className="w-24 shrink-0 pt-0.5">
                  <SeverityBadge sev={e.severity} />
                </div>
                <div className="min-w-0 flex-1 basis-80">
                  <p className="text-xs font-semibold text-ink">
                    {kindLabel[e.kind] ?? e.kind}
                    {e.count > 1 && <span className="ml-2 font-normal text-muted">{fmtInt(e.count)}{t('×')}</span>}
                  </p>
                  <p className="mt-0.5 text-xs leading-relaxed text-ink-2">{e.summary}</p>
                  <p className="mt-1 text-[11px] text-muted">
                    {ago(e.last_seen)} · {fmtDateTime(e.last_seen)}
                    {e.client_id && (
                      <>
                        {' · '}
                        <button onClick={() => onOpenDevice(e.client_id!)} className="text-accent hover:underline">
                          {e.client_name || e.client_ip}
                        </button>
                      </>
                    )}
                    {e.domain && <span className="font-mono"> · {e.domain}</span>}
                  </p>
                </div>
                <div className="flex shrink-0 flex-wrap items-center gap-1">
                  <Button size="sm" variant="ghost" onClick={() => setDetail(e)}>
                    {t('Detalhes')}
                  </Button>
                  {e.client_id && e.kind !== 'new_device' && (
                    <Button size="sm" variant="ghost" icon={<Lock className="size-3.5" />} loading={isolate.isPending && isolate.variables?.id === e.id} onClick={() => isolate.mutate(e)}>
                      {t('Isolar')}
                    </Button>
                  )}
                  {e.domain && (
                    <Button size="sm" variant="ghost" icon={<EyeOff className="size-3.5" />} onClick={() => ignore.mutate(e.domain!)} title={t('As detecções passam a ignorar este domínio')}>
                      {t('Ignorar domínio')}
                    </Button>
                  )}
                  {e.status === 'open' ? (
                    <Button size="sm" icon={<CircleCheck className="size-3.5" />} onClick={() => setEv.mutate({ id: e.id, to: 'ack' })}>
                      {t('Reconhecer')}
                    </Button>
                  ) : (
                    <Button size="sm" variant="ghost" onClick={() => setEv.mutate({ id: e.id, to: 'reopen' })}>
                      {t('Reabrir')}
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <SettingsCard />

      <Modal open={!!detail} onClose={() => setDetail(null)} title={detail ? kindLabel[detail.kind] ?? detail.kind : ''}>
        {detail && (
          <div className="space-y-3 text-xs">
            <p className="leading-relaxed text-ink-2">{detail.summary}</p>
            <dl className="grid grid-cols-2 gap-3">
              {(
                [
                  [t('Primeira vez'), fmtDateTime(detail.first_seen)],
                  [t('Última vez'), fmtDateTime(detail.last_seen)],
                  [t('Ocorrências'), fmtInt(detail.count)],
                  [t('Dispositivo'), detail.client_name || detail.client_ip || '—'],
                ] as const
              ).map(([k, v]) => (
                <div key={k}>
                  <dt className="text-muted">{k}</dt>
                  <dd className="mt-0.5 text-ink">{v}</dd>
                </div>
              ))}
            </dl>
            <pre className="max-h-72 overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-[11px] text-ink">
              {JSON.stringify(detail.details ?? {}, null, 2)}
            </pre>
          </div>
        )}
      </Modal>
    </div>
  )
}

const isolateKinds = ['threat_blocked', 'dga', 'dns_tunnel', 'nrd']

function SettingsCard() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['security-settings'], queryFn: () => api<SecuritySettings>('/api/security/settings') })
  const [s, setS] = useState<SecuritySettings | null>(null)
  const [ignore, setIgnore] = useState('')
  useEffect(() => {
    if (q.data) {
      setS(q.data)
      setIgnore((q.data.ignore_domains ?? []).join('\n'))
    }
  }, [q.data])
  const save = useMutation({
    mutationFn: (v: SecuritySettings) => api<SecuritySettings>('/api/security/settings', { method: 'PUT', body: v }),
    onSuccess: (d) => qc.setQueryData(['security-settings'], d),
  })
  if (!s) return null
  const set = (patch: Partial<SecuritySettings>) => setS({ ...s, ...patch })
  const toggleIso = (k: string) =>
    set({ auto_isolate: s.auto_isolate.includes(k) ? s.auto_isolate.filter((x) => x !== k) : [...s.auto_isolate, k] })

  const row = (label: string, hint: string, checked: boolean, onChange: (v: boolean) => void) => (
    <label className="flex items-start justify-between gap-4 py-2.5">
      <span>
        <span className="block text-sm text-ink">{label}</span>
        <span className="block text-[11px] text-muted">{hint}</span>
      </span>
      <Switch checked={checked} onChange={onChange} label={label} />
    </label>
  )

  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-accent" aria-hidden />
          {t('Detecções')}
        </span>
      }
      subtitle={t('Valem na hora, sem reiniciar o serviço')}
    >
      <form
        className="grid gap-6 lg:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate({
            ...s,
            ignore_domains: ignore
              .split('\n')
              .map((l) => l.trim())
              .filter(Boolean),
          })
        }}
      >
        <div className="divide-y divide-line">
          {row(t('Malware com DGA'), t('Vários nomes aleatórios inexistentes consultados pelo mesmo dispositivo.'), s.dga, (v) => set({ dga: v }))}
          {row(t('Túnel DNS'), t('Muitos subdomínios longos e únicos sob o mesmo domínio, ou rajadas de TXT.'), s.tunnel, (v) => set({ tunnel: v }))}
          {row(t('Dispositivo novo'), t('Avisa quando um aparelho desconhecido aparece na rede.'), s.new_device, (v) => set({ new_device: v }))}
          {row(
            t('Domínios recém-registrados'),
            t('Consulta a data de registro (RDAP) direto no registro de cada domínio. O nome do domínio sai da rede para o registro.'),
            s.nrd,
            (v) => set({ nrd: v }),
          )}
          {s.nrd && (
            <div className="grid gap-3 py-3 sm:grid-cols-2">
              <Field label={t('Ao encontrar um')}>
                <Select
                  label={t('Ação')}
                  value={s.nrd_action}
                  onChange={(v) => set({ nrd_action: v as 'alert' | 'block' })}
                  className="w-full"
                  options={[
                    { value: 'alert', label: t('Só alertar') },
                    { value: 'block', label: t('Bloquear e alertar') },
                  ]}
                />
              </Field>
              <Field label={t('Considerar novo até (dias)')}>
                <Input type="number" min={1} max={365} value={s.nrd_max_days} onChange={(e) => set({ nrd_max_days: Number(e.target.value) })} />
              </Field>
              {s.nrd_action === 'block' && (
                <p className="col-span-full text-[11px] text-muted">
                  {t('O primeiro acesso a um domínio desconhecido passa enquanto a data é consultada; os seguintes são bloqueados.')}
                </p>
              )}
            </div>
          )}
        </div>
        <div className="space-y-4">
          <div>
            <p className="text-sm text-ink">{t('Isolar o dispositivo automaticamente quando houver')}</p>
            <p className="mb-2 text-[11px] text-muted">{t('Contenção imediata. O alerta registra que o isolamento foi automático.')}</p>
            <div className="flex flex-wrap gap-2">
              {isolateKinds.map((k) => (
                <label key={k} className="flex items-center gap-2 rounded-lg border border-line px-2.5 py-1.5 text-xs text-ink">
                  <input type="checkbox" checked={s.auto_isolate.includes(k)} onChange={() => toggleIso(k)} className="accent-[var(--critical)]" />
                  {kindLabel[k]}
                </label>
              ))}
            </div>
          </div>
          <Field label={t('Domínios ignorados pelas detecções (um por linha)')} hint={t('Ex.: serviços legítimos que consultam muitos subdomínios. CDNs e antivírus conhecidos já são ignorados no túnel DNS.')}>
            <Textarea rows={5} value={ignore} onChange={(e) => setIgnore(e.target.value)} placeholder={t('meu-servico-interno.com.br')} />
          </Field>
          <ErrorNote error={save.error} />
          <div className="flex items-center justify-end gap-3">
            {save.isSuccess && <span className="text-xs text-good-ink">{t('Salvo e em vigor.')}</span>}
            <Button type="submit" variant="primary" loading={save.isPending}>
              {t('Salvar detecções')}
            </Button>
          </div>
        </div>
      </form>
    </Card>
  )
}
