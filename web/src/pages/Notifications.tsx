// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState, type ComponentType } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { BellRing, CircleCheck, CircleX, Mail, MessagesSquare, Pencil, Plus, Send, Trash, Webhook } from 'lucide-react'
import { api } from '../api'
import { ago } from '../lib/format'
import { t } from '../lib/i18n'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, Modal, Segmented, Select, StatusBadge, cx } from '../components/ui'

export type ChannelType = 'telegram' | 'teams' | 'email' | 'webhook'
export type Channel = {
  id: string
  name: string
  type: ChannelType
  enabled: boolean
  events: string[]
  min_severity: string
  bot_token?: string
  chat_id?: string
  url?: string
  secret?: string
  to?: string[]
}
export type SMTPSettings = { host: string; port: number; security: string; username?: string; password?: string; from: string }
export type NotifySettings = { channels: Channel[]; smtp: SMTPSettings; panel_url?: string }
type Delivery = { time: string; channel: string; name: string; type: string; title: string; ok: boolean; error?: string; suppressed?: number }
type NotifyState = { settings: NotifySettings; history: Delivery[]; events: string[] }

type Icon = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>
const types: Record<ChannelType, { icon: Icon; label: string }> = {
  telegram: { icon: Send, label: t('Telegram') },
  teams: { icon: MessagesSquare, label: t('Microsoft Teams') },
  email: { icon: Mail, label: t('E-mail') },
  webhook: { icon: Webhook, label: t('Webhook') },
}

export const eventLabel: Record<string, string> = {
  security: t('Alertas de segurança'),
  isolation: t('Isolamento de dispositivos'),
  upstream: t('Upstreams fora do ar'),
  system: t('Falhas do serviço (backup, listas)'),
  report: t('Relatório periódico'),
}

const sevOptions = [
  { value: 'low', label: t('Baixa') },
  { value: 'medium', label: t('Média') },
  { value: 'high', label: t('Alta') },
  { value: 'critical', label: t('Crítica') },
]

export function useNotify() {
  return useQuery({ queryKey: ['notify'], queryFn: () => api<NotifyState>('/api/notify'), refetchInterval: 15_000 })
}

export function Notifications() {
  const qc = useQueryClient()
  const q = useNotify()
  const [editing, setEditing] = useState<Channel | null>(null)
  const [tested, setTested] = useState<Record<string, string>>({})
  const save = useMutation({
    mutationFn: (s: NotifySettings) => api<NotifyState>('/api/notify', { method: 'PUT', body: s }),
    onSuccess: (d) => {
      qc.setQueryData(['notify'], d)
      setEditing(null)
    },
  })
  const test = useMutation({
    mutationFn: (id: string) => api('/api/notify/test/' + id, { method: 'POST' }),
    onSuccess: (_, id) => setTested((x) => ({ ...x, [id]: 'ok' })),
    onError: (e, id) => setTested((x) => ({ ...x, [id]: String((e as Error).message) })),
    onSettled: () => qc.invalidateQueries({ queryKey: ['notify'] }),
  })
  const s = q.data?.settings
  const channels = s?.channels ?? []
  const put = (chs: Channel[]) => s && save.mutate({ ...s, channels: chs })
  const upsert = (c: Channel) => put(channels.some((x) => x.id === c.id) ? channels.map((x) => (x.id === c.id ? c : x)) : [...channels, c])

  return (
    <div className="space-y-5">
      <ErrorNote error={q.error} />
      <Card
        title={
          <span className="flex items-center gap-2">
            <BellRing className="size-4 text-accent" aria-hidden />
            {t('Canais')}
          </span>
        }
        subtitle={t('Para onde o Gjallarhorn soa: alertas, isolamentos e falhas chegam aqui, sem precisar olhar o painel')}
        actions={
          <Button
            size="sm"
            variant="primary"
            icon={<Plus className="size-3.5" />}
            onClick={() => setEditing({ id: crypto.randomUUID().slice(0, 8), name: '', type: 'telegram', enabled: true, events: [], min_severity: 'high' })}
          >
            {t('Novo canal')}
          </Button>
        }
      >
        {channels.length === 0 && q.data && (
          <p className="py-6 text-center text-sm text-muted">{t('Nenhum canal ainda. Comece pelo Telegram ou pelo Teams: leva dois minutos.')}</p>
        )}
        <ul className="grid gap-3 md:grid-cols-2">
          {channels.map((c) => {
            const T = types[c.type]
            const r = tested[c.id]
            return (
              <li key={c.id} className={cx('flex flex-col gap-3 rounded-xl border border-line bg-surface-2 p-4', !c.enabled && 'opacity-60')}>
                <div className="flex items-start gap-3">
                  <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-accent/30 bg-accent/10 text-accent">
                    <T.icon className="size-5" aria-hidden />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-ink">{c.name}</p>
                    <p className="truncate text-xs text-ink-2">
                      {T.label}
                      {c.type === 'email' && c.to?.length ? ' · ' + c.to.join(', ') : ''}
                      {c.type === 'telegram' && c.chat_id ? ' · chat ' + c.chat_id : ''}
                    </p>
                  </div>
                  <LabeledSwitch checked={c.enabled} disabled={save.isPending} onChange={(v) => upsert({ ...c, enabled: v })} label={t('Ligado')} />
                </div>
                <div className="flex flex-wrap gap-1.5 text-[11px]">
                  {(c.events.length ? c.events : (q.data?.events ?? [])).map((e) => (
                    <StatusBadge key={e} tone="neutral">
                      {eventLabel[e] ?? e}
                    </StatusBadge>
                  ))}
                  {(c.events.length === 0 || c.events.includes('security')) && (
                    <StatusBadge tone="accent">{t('segurança a partir de {sev}', { sev: sevOptions.find((o) => o.value === c.min_severity)?.label ?? c.min_severity })}</StatusBadge>
                  )}
                </div>
                {r && r !== 'ok' && <p className="text-[11px] break-all text-critical-ink">{r}</p>}
                <div className="mt-auto flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    icon={r === 'ok' ? <CircleCheck className="size-3.5" /> : <Send className="size-3.5" />}
                    loading={test.isPending && test.variables === c.id}
                    onClick={() => test.mutate(c.id)}
                  >
                    {r === 'ok' ? t('Enviado') : t('Testar')}
                  </Button>
                  <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" />} onClick={() => setEditing(c)}>
                    {t('Editar')}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={t('Apagar {nome}', { nome: c.name })}
                    icon={<Trash className="size-3.5" />}
                    onClick={() => put(channels.filter((x) => x.id !== c.id))}
                  />
                </div>
              </li>
            )
          })}
        </ul>
        <ErrorNote error={save.error} />
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        {s && <SMTPCard settings={s} onSave={(x) => save.mutate(x)} saving={save.isPending} />}
        <Card title={t('Últimos envios')} subtitle={t('Desde que o serviço ligou')}>
          {q.data?.history.length ? (
            <ul className="divide-y divide-line">
              {q.data.history.slice(0, 15).map((d, i) => {
                const T = types[d.type as ChannelType]
                return (
                  <li key={i} className="flex items-start gap-2 py-2 text-xs">
                    {d.ok ? <CircleCheck className="mt-0.5 size-3.5 shrink-0 text-good" aria-label={t('enviado')} /> : <CircleX className="mt-0.5 size-3.5 shrink-0 text-critical" aria-label={t('falhou')} />}
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-ink">{d.title}</p>
                      <p className="truncate text-muted">
                        {T?.label ?? d.type} · {d.name} · {ago(d.time)}
                        {d.suppressed ? ' · ' + t('+{n} juntados', { n: d.suppressed }) : ''}
                      </p>
                      {d.error && <p className="break-all text-critical-ink">{d.error}</p>}
                    </div>
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="py-6 text-center text-sm text-muted">{t('Nada enviado ainda.')}</p>
          )}
        </Card>
      </div>

      {editing && s && (
        <ChannelModal channel={editing} events={q.data?.events ?? []} onClose={() => setEditing(null)} onSave={upsert} saving={save.isPending} error={save.error} />
      )}
    </div>
  )
}

function ChannelModal({ channel, events, onClose, onSave, saving, error }: {
  channel: Channel
  events: string[]
  onClose: () => void
  onSave: (c: Channel) => void
  saving: boolean
  error: unknown
}) {
  const [c, setC] = useState<Channel>(channel)
  const [to, setTo] = useState((channel.to ?? []).join(', '))
  useEffect(() => setC(channel), [channel])
  const set = (p: Partial<Channel>) => setC((x) => ({ ...x, ...p }))
  const all = c.events.length === 0
  const toggleEvent = (e: string, on: boolean) => {
    const cur = all ? events : c.events
    const next = on ? [...cur, e] : cur.filter((x) => x !== e)
    set({ events: next.length === events.length ? [] : next })
  }
  return (
    <Modal open onClose={onClose} title={channel.name ? t('Editar canal') : t('Novo canal')} wide>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          onSave({ ...c, to: c.type === 'email' ? to.split(/[\s,;]+/).filter(Boolean) : undefined })
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Nome')}>
            <Input value={c.name} onChange={(e) => set({ name: e.target.value })} placeholder={t('ex.: SOC no Telegram')} required autoFocus />
          </Field>
          <Field label={t('Tipo')}>
            <Select
              label={t('Tipo')}
              value={c.type}
              onChange={(v) => set({ type: v as ChannelType })}
              options={(Object.keys(types) as ChannelType[]).map((k) => ({ value: k, label: types[k].label }))}
            />
          </Field>
        </div>

        {c.type === 'telegram' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('Token do bot')} hint={t('Fale com o @BotFather no Telegram e use /newbot.')}>
              <Input value={c.bot_token ?? ''} onChange={(e) => set({ bot_token: e.target.value })} placeholder="123456:ABC…" autoComplete="off" required />
            </Field>
            <Field label={t('Chat')} hint={t('ID do grupo ou da pessoa (ex.: -1001234567890). Adicione o bot ao grupo antes.')}>
              <Input value={c.chat_id ?? ''} onChange={(e) => set({ chat_id: e.target.value })} required />
            </Field>
          </div>
        )}
        {c.type === 'teams' && (
          <Field
            label={t('Endereço do webhook do Teams')}
            hint={t('No canal do Teams: Fluxos de trabalho → "Postar em um canal quando uma solicitação de webhook for recebida" → copie o endereço.')}
          >
            <Input value={c.url ?? ''} onChange={(e) => set({ url: e.target.value })} placeholder="https://…" autoComplete="off" required />
          </Field>
        )}
        {c.type === 'webhook' && (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t('Endereço')} hint={t('Recebe um POST com JSON (SOAR, n8n, Shuffle, scripts).')}>
              <Input value={c.url ?? ''} onChange={(e) => set({ url: e.target.value })} placeholder="https://…" required />
            </Field>
            <Field label={t('Segredo (opcional)')} hint={t('Assina o corpo: X-Heimdall-Signature = HMAC-SHA256 de "<timestamp>.<corpo>".')}>
              <Input value={c.secret ?? ''} onChange={(e) => set({ secret: e.target.value })} autoComplete="off" />
            </Field>
          </div>
        )}
        {c.type === 'email' && (
          <Field label={t('Destinatários')} hint={t('Separados por vírgula. O servidor SMTP fica no cartão "Servidor de e-mail".')}>
            <Input value={to} onChange={(e) => setTo(e.target.value)} placeholder="soc@empresa.com.br, ti@empresa.com.br" required />
          </Field>
        )}

        <fieldset className="space-y-2">
          <legend className="mb-1 text-xs font-medium text-ink-2">{t('O que avisar')}</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {events.map((e) => (
              <LabeledSwitch key={e} checked={all || c.events.includes(e)} onChange={(v) => toggleEvent(e, v)} label={eventLabel[e] ?? e} />
            ))}
          </div>
        </fieldset>
        {(all || c.events.includes('security')) && (
          <div className="flex flex-wrap items-center gap-3 text-xs text-ink-2">
            <span>{t('Alertas de segurança a partir da gravidade:')}</span>
            <Segmented label={t('Gravidade mínima')} value={c.min_severity || 'medium'} onChange={(v) => set({ min_severity: v })} options={sevOptions} />
          </div>
        )}
        <p className="text-[11px] text-muted">{t('O mesmo alerta repetido em 10 minutos vira um aviso só; o seguinte diz quantos foram juntados.')}</p>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>{t('Cancelar')}</Button>
          <Button type="submit" variant="primary" loading={saving}>
            {t('Salvar')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function SMTPCard({ settings, onSave, saving }: { settings: NotifySettings; onSave: (s: NotifySettings) => void; saving: boolean }) {
  const [m, setM] = useState<SMTPSettings>(settings.smtp)
  const [panel, setPanel] = useState(settings.panel_url ?? '')
  useEffect(() => {
    setM(settings.smtp)
    setPanel(settings.panel_url ?? '')
  }, [settings])
  const set = (p: Partial<SMTPSettings>) => setM((x) => ({ ...x, ...p }))
  return (
    <Card title={t('Servidor de e-mail')} subtitle={t('Usado pelos canais de e-mail e pelo relatório periódico')}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          onSave({ ...settings, smtp: { ...m, port: Number(m.port) || 0 }, panel_url: panel.trim() })
        }}
      >
        <div className="grid gap-3 sm:grid-cols-[1fr_90px_140px]">
          <Field label={t('Servidor SMTP')}>
            <Input value={m.host} onChange={(e) => set({ host: e.target.value })} placeholder="smtp.office365.com" />
          </Field>
          <Field label={t('Porta')}>
            <Input value={m.port || ''} onChange={(e) => set({ port: Number(e.target.value.replace(/\D/g, '')) })} inputMode="numeric" placeholder="587" />
          </Field>
          <Field label={t('Segurança')}>
            <Select
              label={t('Segurança')}
              value={m.security || 'starttls'}
              onChange={(v) => set({ security: v })}
              options={[
                { value: 'starttls', label: 'STARTTLS' },
                { value: 'tls', label: 'TLS' },
                { value: 'none', label: t('nenhuma') },
              ]}
            />
          </Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t('Usuário')}>
            <Input value={m.username ?? ''} onChange={(e) => set({ username: e.target.value })} autoComplete="off" />
          </Field>
          <Field label={t('Senha')}>
            <Input type="password" value={m.password ?? ''} onChange={(e) => set({ password: e.target.value })} autoComplete="new-password" />
          </Field>
          <Field label={t('Remetente')}>
            <Input value={m.from} onChange={(e) => set({ from: e.target.value })} placeholder="heimdall@empresa.com.br" />
          </Field>
        </div>
        <Field label={t('Endereço do painel nos avisos (opcional)')} hint={t('Vira o link "Abrir o painel" nas mensagens.')}>
          <Input value={panel} onChange={(e) => setPanel(e.target.value)} placeholder="https://heimdall.empresa.local:8053" />
        </Field>
        <Button type="submit" variant="primary" loading={saving}>
          {t('Salvar')}
        </Button>
      </form>
    </Card>
  )
}
