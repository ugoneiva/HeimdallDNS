import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CircleCheck, CircleX, FileStack, Plus, Send, Trash } from 'lucide-react'
import { api } from '../api'
import type { ApplyResult, PolicyTemplate, TenantState } from '../types'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, Modal, StatusBadge, Textarea } from '../components/ui'

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
        title="Modelos de política"
        subtitle="Listas, regras, grupos, upstreams e segurança aplicados em vários clientes de uma vez. Aplicar só acrescenta: nada do cliente é apagado."
        actions={
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setEditing({ id: '', name: '' })}>
            Novo modelo
          </Button>
        }
      >
        <ErrorNote error={tpls.error || save.error} />
        {list.length === 0 ? (
          <p className="text-xs text-muted">Nenhum modelo. Ex.: "Padrão escritório" com bloqueio de jogos e apostas, lista de ameaças e isolamento automático.</p>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center gap-3 py-3">
                <FileStack className="size-4 text-muted" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-ink">{t.name}</span>
                  <span className="block text-xs text-muted">{summary(t)}</span>
                </span>
                <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>
                  Editar
                </Button>
                <Button size="sm" variant="primary" icon={<Send className="size-3.5" />} onClick={() => setApplying(t)}>
                  Aplicar
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
        onSave={(t) => save.mutate(t.id ? list.map((x) => (x.id === t.id ? t : x)) : [...list, t])}
        onDelete={(t) => save.mutate(list.filter((x) => x.id !== t.id))}
      />
      <ApplyModal tpl={applying} onClose={() => setApplying(null)} />
    </div>
  )
}

function summary(t: PolicyTemplate): string {
  const parts = []
  if (t.lists?.length) parts.push(`${t.lists.length} lista(s)`)
  if ((t.deny?.length ?? 0) + (t.allow?.length ?? 0)) parts.push(`${(t.deny?.length ?? 0) + (t.allow?.length ?? 0)} regra(s)`)
  if (t.groups?.length) parts.push(`grupos: ${t.groups.map((g) => g.name).join(', ')}`)
  if (t.upstreams?.length) parts.push('upstreams')
  if (t.security && Object.keys(t.security).length) parts.push('segurança')
  return parts.join(' · ') || 'vazio'
}

type Form = { name: string; description: string; lists: string; deny: string; allow: string; upstreams: string; groups: string; sec: Record<string, boolean> }

const secKeys = [
  { key: 'dga', label: 'Detectar malware com DGA' },
  { key: 'tunnel', label: 'Detectar túnel por DNS' },
  { key: 'nrd', label: 'Avisar sobre domínios recém-registrados' },
  { key: 'isolate_threats', label: 'Isolar sozinho quem acessar domínio de ameaça' },
] as const

function toForm(t: PolicyTemplate): Form {
  const sec = t.security ?? {}
  return {
    name: t.name,
    description: t.description ?? '',
    lists: (t.lists ?? []).map((l) => `${l.name} | ${l.url}${l.category === 'threat' ? ' | ameaças' : ''}`).join('\n'),
    deny: (t.deny ?? []).join('\n'),
    allow: (t.allow ?? []).join('\n'),
    upstreams: (t.upstreams ?? []).join('\n'),
    groups: (t.groups ?? []).map((g) => `${g.name}: ${(g.deny ?? []).join(', ')}`).join('\n'),
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
  onSave: (t: PolicyTemplate) => void
  onDelete: (t: PolicyTemplate) => void
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
    <Modal open onClose={onClose} title={tpl.id ? `Modelo ${tpl.name}` : 'Novo modelo'} wide>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          onSave(fromForm(tpl.id, f))
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Nome">
            <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required placeholder="Padrão escritório" />
          </Field>
          <Field label="Descrição">
            <Input value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
          </Field>
        </div>
        <Field label="Listas (uma por linha: nome | URL, e | ameaças para lista de ameaças)">
          <Textarea rows={3} value={f.lists} onChange={(e) => setF({ ...f, lists: e.target.value })} placeholder="HaGeZi TIF | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt | ameaças" className="font-mono text-xs" />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Bloquear (somado às regras do cliente)">
            <Textarea rows={3} value={f.deny} onChange={(e) => setF({ ...f, deny: e.target.value })} placeholder={'service:jogos\napostas.com'} />
          </Field>
          <Field label="Liberar">
            <Textarea rows={3} value={f.allow} onChange={(e) => setF({ ...f, allow: e.target.value })} />
          </Field>
        </div>
        <Field label="Grupos (um por linha: Nome: regra, regra)" hint="Criados no cliente ou atualizados pelo nome; os horários se ajustam em cada cliente.">
          <Textarea rows={2} value={f.groups} onChange={(e) => setF({ ...f, groups: e.target.value })} placeholder="Visitantes: service:social, service:streaming" />
        </Field>
        <Field label="Upstreams (deixe vazio para não mexer)">
          <Textarea rows={2} value={f.upstreams} onChange={(e) => setF({ ...f, upstreams: e.target.value })} placeholder="https://dns.quad9.net/dns-query" className="font-mono text-xs" />
        </Field>
        <div className="space-y-2">
          <p className="text-xs font-semibold text-ink">Segurança (só liga; o que estiver desmarcado não é mexido)</p>
          {secKeys.map((k) => (
            <LabeledSwitch key={k.key} checked={f.sec[k.key]} onChange={(v) => setF({ ...f, sec: { ...f.sec, [k.key]: v } })} label={k.label} />
          ))}
        </div>
        <ErrorNote error={error} />
        <div className="flex items-center justify-between">
          {tpl.id ? (
            <Button variant={confirmDel ? 'danger' : 'ghost'} icon={<Trash className="size-4" />} onClick={() => (confirmDel ? onDelete(tpl) : setConfirmDel(true))}>
              {confirmDel ? 'Confirmar exclusão do modelo' : 'Excluir'}
            </Button>
          ) : (
            <span />
          )}
          <Button type="submit" variant="primary" loading={saving}>
            Salvar modelo
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
    <Modal open onClose={onClose} title={`Aplicar "${tpl.name}"`}>
      {apply.data ? (
        <ul className="space-y-2 text-sm">
          {apply.data.map((r) => (
            <li key={r.tenant_id} className="flex items-start gap-2">
              {r.ok ? <CircleCheck className="mt-0.5 size-4 text-good" aria-hidden /> : <CircleX className="mt-0.5 size-4 text-critical" aria-hidden />}
              <span>
                <strong className="text-ink">{r.tenant_name}</strong>{' '}
                <span className="text-xs text-ink-2">
                  {r.ok ? (r.changes.length ? r.changes.join(', ') : 'já estava igual') : r.error}
                </span>
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-ink-2">Escolha os clientes. Réplicas recusam alterações (aplique no principal de cada cliente).</p>
          <div className="flex gap-2 text-xs">
            <button className="text-accent hover:underline" onClick={() => setPick(list.filter((t) => t.online).map((t) => t.id))}>
              todos no ar
            </button>
            <button className="text-muted hover:underline" onClick={() => setPick([])}>
              nenhum
            </button>
          </div>
          <ul className="max-h-72 space-y-1.5 overflow-y-auto">
            {list.map((t) => (
              <li key={t.id}>
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={pick.includes(t.id)}
                    onChange={(e) => setPick(e.target.checked ? [...pick, t.id] : pick.filter((x) => x !== t.id))}
                  />
                  <span className="flex-1 text-ink">{t.name}</span>
                  {t.online ? <StatusBadge tone="good">no ar</StatusBadge> : <StatusBadge tone="critical">fora do ar</StatusBadge>}
                  {t.ha_role === 'replica' && <StatusBadge tone="neutral">réplica</StatusBadge>}
                </label>
              </li>
            ))}
          </ul>
          <ErrorNote error={apply.error} />
          <div className="flex justify-end">
            <Button variant="primary" icon={<Send className="size-4" />} loading={apply.isPending} disabled={pick.length === 0} onClick={() => apply.mutate()}>
              Aplicar em {pick.length} cliente(s)
            </Button>
          </div>
        </div>
      )}
    </Modal>
  )
}
