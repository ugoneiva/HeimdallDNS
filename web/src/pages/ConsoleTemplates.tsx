// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleCheck, CircleX, FileStack, Plus, Send, Trash } from 'lucide-react'
import { api } from '../api'
import type { ApplyResult, PolicyTemplate, TenantState } from '../types'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, Modal, StatusBadge, Textarea } from '../components/ui'
import { t } from '../lib/i18n'

const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

function useTemplates() {
  return useQuery({ queryKey: ['console-templates'], queryFn: () => api<PolicyTemplate[]>('/api/console/templates') })
}

/** Modelos de política aplicados em vários clientes de uma vez. */
export function ConsoleTemplates() {
  const qc = useQueryClient()
  const tpls = useTemplates()
  const [editing, setEditing] = useState<PolicyTemplate | null>(null)
  const [applying, setApplying] = useState<PolicyTemplate | null>(null)
  const save = useMutation({
    mutationFn: (all: PolicyTemplate[]) => api<PolicyTemplate[]>('/api/console/templates', { method: 'PUT', body: { templates: all } }),
    onSuccess: (d) => {
      qc.setQueryData(['console-templates'], d)
      setEditing(null)
    },
  })
  const list = tpls.data ?? []
  return (
    <div className="space-y-5">
      <Card
        title={t('Modelos de política')}
        subtitle={t('Listas, regras, grupos, upstreams e segurança aplicados em vários clientes de uma vez. Aplicar só acrescenta: nada do cliente é apagado.')}
        actions={
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setEditing({ id: '', name: '' })}>
            {t('Novo modelo')}
          </Button>
        }
      >
        <ErrorNote error={tpls.error || save.error} />
        {list.length === 0 ? (
          <p className="text-xs text-muted">{t('Nenhum modelo. Ex.: "Padrão escritório" com bloqueio de jogos e apostas, lista de ameaças e isolamento automático.')}</p>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((tk) => (
              <li key={tk.id} className="flex flex-wrap items-center gap-3 py-3">
                <FileStack className="size-4 text-muted" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-ink">{tk.name}</span>
                  <span className="block text-xs text-muted">{summary(tk)}</span>
                </span>
                <Button size="sm" variant="ghost" onClick={() => setEditing(tk)}>
                  {t('Editar')}
                </Button>
                <Button size="sm" variant="primary" icon={<Send className="size-3.5" />} onClick={() => setApplying(tk)}>
                  {t('Aplicar')}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <TemplateEditor
        tpl={editing}
        saving={save.isPending}
        error={save.error}
        onClose={() => setEditing(null)}
        onSave={(tk) => save.mutate(tk.id ? list.map((x) => (x.id === tk.id ? tk : x)) : [...list, tk])}
        onDelete={(tk) => save.mutate(list.filter((x) => x.id !== tk.id))}
      />
      <ApplyModal tpl={applying} onClose={() => setApplying(null)} />
    </div>
  )
}

function summary(tk: PolicyTemplate): string {
  const parts = []
  if (tk.lists?.length) parts.push(t('{n} lista(s)', { n: tk.lists.length }))
  if ((tk.deny?.length ?? 0) + (tk.allow?.length ?? 0)) parts.push(t('{n} regra(s)', { n: (tk.deny?.length ?? 0) + (tk.allow?.length ?? 0) }))
  if (tk.groups?.length) parts.push(t('grupos: {nomes}', { nomes: tk.groups.map((g) => g.name).join(', ') }))
  if (tk.upstreams?.length) parts.push('upstreams')
  if (tk.security && Object.keys(tk.security).length) parts.push(t('segurança'))
  return parts.join(' · ') || t('vazio')
}

type Form = { name: string; description: string; lists: string; deny: string; allow: string; upstreams: string; groups: string; sec: Record<string, boolean> }

const secKeys = [
  { key: 'dga', label: t('Detectar malware com DGA') },
  { key: 'tunnel', label: t('Detectar túnel por DNS') },
  { key: 'nrd', label: t('Avisar sobre domínios recém-registrados') },
  { key: 'isolate_threats', label: t('Isolar sozinho quem acessar domínio de ameaça') },
] as const

function toForm(tk: PolicyTemplate): Form {
  const sec = tk.security ?? {}
  return {
    name: tk.name,
    description: tk.description ?? '',
    lists: (tk.lists ?? []).map((l) => `${l.name} | ${l.url}${l.category === 'threat' ? ' | ameaças' : ''}`).join('\n'),
    deny: (tk.deny ?? []).join('\n'),
    allow: (tk.allow ?? []).join('\n'),
    upstreams: (tk.upstreams ?? []).join('\n'),
    groups: (tk.groups ?? []).map((g) => `${g.name}: ${(g.deny ?? []).join(', ')}`).join('\n'),
    sec: {
      dga: sec.dga === true,
      tunnel: sec.tunnel === true,
      nrd: sec.nrd === true,
      isolate_threats: Array.isArray(sec.auto_isolate) && (sec.auto_isolate as string[]).includes('threat_blocked'),
    },
  }
}

function fromForm(id: string, f: Form): PolicyTemplate {
  const security: Record<string, unknown> = {}
  for (const k of ['dga', 'tunnel', 'nrd'] as const) if (f.sec[k]) security[k] = true
  if (f.sec.isolate_threats) security.auto_isolate = ['threat_blocked']
  return {
    id,
    name: f.name.trim(),
    description: f.description.trim() || undefined,
    lists: lines(f.lists).map((l) => {
      const [name, url, cat] = l.split('|').map((x) => x.trim())
      return url ? { name, url, category: cat === 'ameaças' ? 'threat' : undefined } : { name: name, url: name }
    }),
    deny: lines(f.deny),
    allow: lines(f.allow),
    upstreams: lines(f.upstreams),
    groups: lines(f.groups).map((l) => {
      const [name, rules = ''] = l.split(':')
      return { id: '', name: name.trim(), deny: rules.split(',').map((x) => x.trim()).filter(Boolean) }
    }),
    security: Object.keys(security).length ? security : undefined,
  }
}

function TemplateEditor({ tpl, onClose, onSave, onDelete, saving, error }: {
  tpl: PolicyTemplate | null
  onClose: () => void
  onSave: (tk: PolicyTemplate) => void
  onDelete: (tk: PolicyTemplate) => void
  saving: boolean
  error: unknown
}) {
  const [f, setF] = useState<Form | null>(null)
  const [confirmDel, setConfirmDel] = useState(false)
  useEffect(() => {
    setF(tpl ? toForm(tpl) : null)
    setConfirmDel(false)
  }, [tpl])
  if (!tpl || !f) return null
  return (
    <Modal open onClose={onClose} title={tpl.id ? t('Modelo {nome}', { nome: tpl.name }) : t('Novo modelo')} wide>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          onSave(fromForm(tpl.id, f))
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Nome')}>
            <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required placeholder={t('Padrão escritório')} />
          </Field>
          <Field label={t('Descrição')}>
            <Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
          </Field>
        </div>
        <Field label={t('Listas (uma por linha: nome | URL, e | ameaças para lista de ameaças)')}>
          <Textarea rows={3} value={f.lists} onChange={(e) => setF({ ...f, lists: e.target.value })} placeholder={t('HaGeZi TIF | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt | ameaças')} className="font-mono text-xs" />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Bloquear (somado às regras do cliente)')}>
            <Textarea rows={3} value={f.deny} onChange={(e) => setF({ ...f, deny: e.target.value })} placeholder={t('service:jogos\napostas.com')} />
          </Field>
          <Field label={t('Liberar')}>
            <Textarea rows={3} value={f.allow} onChange={(e) => setF({ ...f, allow: e.target.value })} />
          </Field>
        </div>
        <Field label={t('Grupos (um por linha: Nome: regra, regra)')} hint={t('Criados no cliente ou atualizados pelo nome; os horários se ajustam em cada cliente.')}>
          <Textarea rows={2} value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} placeholder={t('Visitantes: service:social, service:streaming')} />
        </Field>
        <Field label={t('Upstreams (deixe vazio para não mexer)')}>
          <Textarea rows={2} value={f.upstreams} onChange={(e) => setF({ ...f, upstreams: e.target.value })} placeholder={t('https://dns.quad9.net/dns-query')} className="font-mono text-xs" />
        </Field>
        <div className="space-y-2">
          <p className="text-xs font-semibold text-ink">{t('Segurança (só liga; o que estiver desmarcado não é mexido)')}</p>
          {secKeys.map((k) => (
            <LabeledSwitch key={k.key} checked={f.sec[k.key]} onChange={(v) => setF({ ...f, sec: { ...f.sec, [k.key]: v } })} label={k.label} />
          ))}
        </div>
        <ErrorNote error={error} />
        <div className="flex items-center justify-between">
          {tpl.id ? (
            <Button variant={confirmDel ? 'danger' : 'ghost'} icon={<Trash className="size-4" />} onClick={() => (confirmDel ? onDelete(tpl) : setConfirmDel(true))}>
              {confirmDel ? t('Confirmar exclusão do modelo') : t('Excluir')}
            </Button>
          ) : (
            <span />
          )}
          <Button type="submit" variant="primary" loading={saving}>
            {t('Salvar modelo')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function ApplyModal({ tpl, onClose }: { tpl: PolicyTemplate | null; onClose: () => void }) {
  const tenants = useQuery({ queryKey: ['console-tenants'], queryFn: () => api<TenantState[]>('/api/console/tenants') })
  const [pick, setPick] = useState<string[]>([])
  const apply = useMutation({
    mutationFn: () => api<ApplyResult[]>(`/api/console/templates/${tpl!.id}/apply`, { method: 'POST', body: { tenants: pick } }),
  })
  useEffect(() => {
    setPick([])
    apply.reset()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tpl])
  if (!tpl) return null
  const list = tenants.data ?? []
  return (
    <Modal open onClose={onClose} title={t('Aplicar "{nome}"', { nome: tpl.name })}>
      {apply.data ? (
        <ul className="space-y-2 text-sm">
          {apply.data.map((r) => (
            <li key={r.tenant_id} className="flex items-start gap-2">
              {r.ok ? <CircleCheck className="mt-0.5 size-4 text-good" aria-hidden /> : <CircleX className="mt-0.5 size-4 text-critical" aria-hidden />}
              <span>
                <strong className="text-ink">{r.tenant_name}</strong>{' '}
                <span className="text-xs text-ink-2">
                  {r.ok ? (r.changes.length ? r.changes.join(', ') : t('já estava igual')) : r.error}
                </span>
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-ink-2">{t('Escolha os clientes. Réplicas recusam alterações (aplique no principal de cada cliente).')}</p>
          <div className="flex gap-2 text-xs">
            <button className="text-accent hover:underline" onClick={() => setPick(list.filter((tk) => tk.online).map((tk) => tk.id))}>
              {t('todos no ar')}
            </button>
            <button className="text-muted hover:underline" onClick={() => setPick([])}>
              {t('nenhum')}
            </button>
          </div>
          <ul className="max-h-72 space-y-1.5 overflow-y-auto">
            {list.map((tk) => (
              <li key={tk.id}>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={pick.includes(tk.id)}
                    onChange={(e) => setPick(e.target.checked ? [...pick, tk.id] : pick.filter((x) => x !== tk.id))}
                  />
                  <span className="flex-1 text-ink">{tk.name}</span>
                  {tk.online ? <StatusBadge tone="good">{t('no ar')}</StatusBadge> : <StatusBadge tone="critical">{t('fora do ar')}</StatusBadge>}
                  {tk.ha_role === 'replica' && <StatusBadge tone="neutral">{t('réplica')}</StatusBadge>}
                </label>
              </li>
            ))}
          </ul>
          <ErrorNote error={apply.error} />
          <div className="flex justify-end">
            <Button variant="primary" icon={<Send className="size-4" />} loading={apply.isPending} disabled={pick.length === 0} onClick={() => apply.mutate()}>
              {t('Aplicar em')}{' '}{pick.length}{' '}{t('cliente(s)')}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  )
}
