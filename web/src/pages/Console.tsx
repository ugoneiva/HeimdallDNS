// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useState, type ComponentType } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, CircleCheck, FileStack, ExternalLink, LogOut, Monitor, Moon, Plus, ShieldAlert, Sun, Trash } from 'lucide-react'
import { api } from '../api'
import type { ConsoleAlert, TenantState } from '../types'
import { ago, fmtCompact, fmtDateTime, fmtInt, fmtPct, kindLabel, uptime } from '../lib/format'
import { setTheme, useTheme } from '../lib/theme'
import { Button, Card, ErrorNote, Field, Input, Modal, Segmented, StatusBadge, cx } from '../components/ui'
import { Logo } from '../components/Logo'
import { SeverityBadge } from './Security'
import { PasswordForm } from './Settings'
import { ConsoleTemplates } from './ConsoleTemplates'
import { LangPicker } from '../components/LangPicker'
import { AboutLine } from '../components/About'
import { t } from '../lib/i18n'

type Page = 'tenants' | 'alerts' | 'templates' | 'settings'

const nav: { page: Page; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { page: 'tenants', label: t('Clientes'), icon: Building2 },
  { page: 'alerts', label: t('Alertas'), icon: ShieldAlert },
  { page: 'templates', label: t('Modelos de política'), icon: FileStack },
  { page: 'settings', label: t('Configurações'), icon: Moon },
]

function useTenants() {
  return useQuery({ queryKey: ['console-tenants'], queryFn: () => api<TenantState[]>('/api/console/tenants'), refetchInterval: 10_000 })
}
function useAlerts() {
  return useQuery({ queryKey: ['console-alerts'], queryFn: () => api<ConsoleAlert[]>('/api/console/alerts'), refetchInterval: 10_000 })
}

export function ConsoleApp({ version, onLogout }: { version: string; onLogout: () => void }) {
  const [page, setPage] = useState<Page>('tenants')
  const alerts = useAlerts().data ?? []
  const urgent = alerts.filter((a) => a.severity === 'critical' || a.severity === 'high').length
  const title = nav.find((n) => n.page === page)!.label
  return (
    <div className="min-h-full lg:grid lg:grid-cols-[232px_1fr]">
      <aside className="sticky top-0 z-20 border-b border-line bg-surface/95 backdrop-blur lg:h-screen lg:border-r lg:border-b-0">
        <div className="flex items-center gap-2.5 px-4 py-3 lg:px-5 lg:py-5">
          <Logo className="size-7" />
          <div className="leading-tight">
            <p className="text-sm font-semibold text-ink">{t('HeimdallDNS')}</p>
            <p className="text-[11px] text-muted">{t('console de MSP')}</p>
          </div>
        </div>
        <nav aria-label={t('Seções')} className="flex gap-1 overflow-x-auto px-2 pb-2 lg:flex-col lg:px-3 lg:pb-0">
          {nav.map((n) => {
            const Icon = n.icon
            return (
              <button
                key={n.page}
                onClick={() => setPage(n.page)}
                aria-current={n.page === page ? 'page' : undefined}
                className={cx(
                  'flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm whitespace-nowrap transition-colors',
                  n.page === page ? 'bg-accent-soft font-medium text-accent' : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
                )}
              >
                <Icon className="size-4" />
                {n.label}
                {n.page === 'alerts' && alerts.length > 0 && (
                  <span className={cx('ml-auto rounded-full px-1.5 text-[10px] leading-4 font-semibold', urgent ? 'bg-critical text-white' : 'bg-surface-3 text-ink-2')}>
                    {alerts.length}
                  </span>
                )}
              </button>
            )
          })}
        </nav>
        <AboutLine version={version} className="absolute right-5 bottom-4 left-5 hidden text-[11px] leading-relaxed text-muted lg:block" />
      </aside>
      <main className="relative min-w-0">
        <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-64" aria-hidden />
        <div className="relative mx-auto max-w-7xl px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
          <h1 className="mb-5 text-xl font-semibold tracking-tight text-ink">{title}</h1>
          {page === 'tenants' && <Tenants />}
          {page === 'alerts' && <Alerts />}
          {page === 'templates' && <ConsoleTemplates />}
          {page === 'settings' && <ConsoleSettings onLogout={onLogout} />}
        </div>
      </main>
    </div>
  )
}

function Tenants() {
  const qc = useQueryClient()
  const { data = [] } = useTenants()
  const [adding, setAdding] = useState(false)
  const [confirmDel, setConfirmDel] = useState<string | null>(null)
  const del = useMutation({
    mutationFn: (id: string) => api(`/api/console/tenants/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['console-tenants'] }),
  })
  const online = data.filter((tk) => tk.online).length
  const open = data.reduce((s, tk) => s + tk.open_total, 0)
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-ink-2">
          <strong className="text-ink">{online}</strong>{' '}{t('de')}{' '}{data.length}{' '}{t('clientes no ar ·')}{' '}<strong className="text-ink">{fmtInt(open)}</strong>{' '}{t('alertas abertos')}
        </p>
        <Button variant="primary" className="ml-auto" icon={<Plus className="size-4" />} onClick={() => setAdding(true)}>
          {t('Adicionar cliente')}
        </Button>
      </div>
      {data.length === 0 && (
        <Card>
          <p className="text-sm text-ink-2">
            {t('Nenhum cliente ainda. Para cada HeimdallDNS de cliente, informe a URL da API (alcançável daqui, por exemplo pela VPN) e o token da API dele (arquivo')}{' '}<code className="font-mono text-ink">api.token</code>{' '}{t('no diretório de dados).')}
          </p>
        </Card>
      )}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data.map((tk) => (
          <section key={tk.id} className={cx('rounded-xl border bg-surface p-4', tk.online ? 'border-line' : 'border-critical/50')}>
            <header className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <h2 className="truncate text-sm font-semibold text-ink">{tk.name}</h2>
                <p className="truncate font-mono text-[11px] text-muted">{tk.url}</p>
              </div>
              {tk.online ? <StatusBadge tone="good">{t('No ar')}</StatusBadge> : <StatusBadge tone="critical">{t('Fora do ar')}</StatusBadge>}
            </header>
            {tk.online ? (
              <>
                <dl className="mt-3 grid grid-cols-3 gap-2 text-xs">
                  <div>
                    <dt className="text-muted">{t('Consultas 24 h')}</dt>
                    <dd className="text-base font-semibold text-ink">{fmtCompact(tk.queries_24h)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">{t('Bloqueadas')}</dt>
                    <dd className="text-base font-semibold text-ink">{fmtPct(tk.blocked_pct)}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">{t('Dispositivos')}</dt>
                    <dd className="text-base font-semibold text-ink">
                      {fmtInt(tk.active_devices)}
                      <span className="text-xs font-normal text-muted"> / {fmtInt(tk.clients)}</span>
                    </dd>
                  </div>
                </dl>
                <div className="mt-3 flex flex-wrap items-center gap-1.5 text-xs">
                  {tk.open_total === 0 ? (
                    <StatusBadge tone="good">{t('Sem alertas abertos')}</StatusBadge>
                  ) : (
                    (['critical', 'high', 'medium', 'low'] as const)
                      .filter((s) => tk.open_alerts?.[s])
                      .map((s) => (
                        <span key={s} className="flex items-center gap-1 text-ink-2">
                          <SeverityBadge sev={s} /> {tk.open_alerts[s]}
                        </span>
                      ))
                  )}
                  {tk.upstreams_ok < tk.upstreams && <StatusBadge tone="warning">{tk.upstreams - tk.upstreams_ok}{' '}{t('upstream sem resposta')}</StatusBadge>}
                </div>
                <p className="mt-3 text-[11px] text-muted">
                  {t('versão')}{' '}{tk.version}{' '}{t('· ligado há')}{' '}{uptime(tk.uptime_s)} · {fmtCompact(tk.rules)}{' '}{t('regras')}
                  {tk.ha_role && ` · ${tk.ha_role === 'primary' ? 'principal' : t('réplica')}`}
                </p>
              </>
            ) : (
              <p className="mt-3 text-xs break-all text-critical-ink">
                {tk.error || t('Ainda não lido.')}
                {tk.last_ok && <span className="block text-muted">{t('Último contato')}{' '}{ago(tk.last_ok)}</span>}
              </p>
            )}
            <footer className="mt-3 flex items-center justify-between border-t border-line pt-3">
              <a href={tk.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent hover:underline">
                {t('Abrir painel')}{' '}<ExternalLink className="size-3" aria-hidden />
              </a>
              <Button
                size="sm"
                variant={confirmDel === tk.id ? 'danger' : 'ghost'}
                icon={<Trash className="size-3.5" />}
                onBlur={() => setConfirmDel(null)}
                onClick={() => (confirmDel === tk.id ? del.mutate(tk.id) : setConfirmDel(tk.id))}
              >
                {confirmDel === tk.id ? t('Remover') : ''}
              </Button>
            </footer>
          </section>
        ))}
      </div>
      <AddTenant open={adding} onClose={() => setAdding(false)} />
    </div>
  )
}

function AddTenant({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [f, setF] = useState({ name: '', url: '', token: '', insecure_tls: false })
  const add = useMutation({
    mutationFn: () => api('/api/console/tenants', { method: 'POST', body: f }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['console-tenants'] })
      setF({ name: '', url: '', token: '', insecure_tls: false })
      onClose()
    },
  })
  return (
    <Modal open={open} onClose={onClose} title={t('Adicionar cliente')}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          add.mutate()
        }}
      >
        <Field label={t('Nome')}>
          <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder={t('Cliente Exemplo')} required />
        </Field>
        <Field label={t('URL da API')} hint={t('Precisa ser alcançável daqui (por exemplo, pela VPN do cliente).')}>
          <Input value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder={t('https://10.0.0.2:8053')} required />
        </Field>
        <Field label={t('Token da API')} hint={t('Arquivo api.token no diretório de dados do HeimdallDNS do cliente.')}>
          <Input type="password" autoComplete="off" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} required />
        </Field>
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={f.insecure_tls} onChange={(e) => setF({ ...f, insecure_tls: e.target.checked })} />
          {t('Aceitar certificado autoassinado')}
        </label>
        <ErrorNote error={add.error} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={add.isPending}>
            {t('Testar e adicionar')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function Alerts() {
  const qc = useQueryClient()
  const { data = [], isLoading } = useAlerts()
  const ack = useMutation({
    mutationFn: (a: ConsoleAlert) => api<ConsoleAlert[]>(`/api/console/tenants/${a.tenant_id}/ack/${a.id}`, { method: 'POST' }),
    onSuccess: (d) => {
      qc.setQueryData(['console-alerts'], d)
      qc.invalidateQueries({ queryKey: ['console-tenants'] })
    },
  })
  return (
    <Card pad={false}>
      <ErrorNote error={ack.error} />
      {data.length === 0 ? (
        <p className="flex items-center justify-center gap-2 py-12 text-sm text-muted">
          <CircleCheck className="size-4 text-good" aria-hidden />
          {isLoading ? t('Carregando…') : t('Nenhum alerta aberto em nenhum cliente.')}
        </p>
      ) : (
        <ul className="divide-y divide-line">
          {data.map((a) => (
            <li key={`${a.tenant_id}-${a.id}`} className="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3 sm:px-5">
              <div className="w-24 shrink-0 pt-0.5">
                <SeverityBadge sev={a.severity} />
              </div>
              <div className="min-w-0 flex-1 basis-80">
                <p className="text-xs font-semibold text-ink">
                  {a.tenant_name} · {kindLabel[a.kind] ?? a.kind}
                  {a.count > 1 && <span className="ml-2 font-normal text-muted">{fmtInt(a.count)}{t('×')}</span>}
                </p>
                <p className="mt-0.5 text-xs leading-relaxed text-ink-2">{a.summary}</p>
                <p className="mt-1 text-[11px] text-muted">
                  {ago(a.last_seen)} · {fmtDateTime(a.last_seen)}
                  {a.domain && <span className="font-mono"> · {a.domain}</span>}
                </p>
              </div>
              <Button size="sm" icon={<CircleCheck className="size-3.5" />} loading={ack.isPending && ack.variables?.id === a.id} onClick={() => ack.mutate(a)}>
                {t('Reconhecer')}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function ConsoleSettings({ onLogout }: { onLogout: () => void }) {
  const { choice } = useTheme()
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title={t('Aparência')}>
        <Segmented
          label={t('Tema')}
          value={choice}
          onChange={setTheme}
          options={[
            { value: 'dark', label: <span className="flex items-center gap-1.5"><Moon className="size-3.5" aria-hidden />{t('Escuro')}</span> },
            { value: 'light', label: <span className="flex items-center gap-1.5"><Sun className="size-3.5" aria-hidden />{t('Claro')}</span> },
            { value: 'auto', label: <span className="flex items-center gap-1.5"><Monitor className="size-3.5" aria-hidden />{t('Sistema')}</span> },
          ]}
        />
              <div className="mt-3">
          <LangPicker />
        </div>
      </Card>
      <Card title={t('Sessão')}>
        <p className="mb-4 text-xs text-ink-2">{t('O console guarda o token da API de cada cliente: mantenha-o numa rede de gerência e com HTTPS.')}</p>
        <Button icon={<LogOut className="size-4" />} onClick={onLogout}>
          {t('Sair')}
        </Button>
      </Card>
      <Card title={t('Trocar a senha')}>
        <PasswordForm />
      </Card>
    </div>
  )
}
