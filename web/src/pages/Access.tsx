import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, KeyRound, Plus, ShieldCheck, Trash, UserPlus } from 'lucide-react'
import { api } from '../api'
import type { APIToken, Role, UserInfo } from '../types'
import { ago, fmtDateTime } from '../lib/format'
import { roleLabel, roleNote, useAuth } from '../lib/auth'
import { Button, Card, ErrorNote, Field, Input, Modal, Select, StatusBadge } from '../components/ui'

const roleOptions = (['admin', 'operator', 'viewer'] as Role[]).map((r) => ({ value: r, label: `${roleLabel[r]} — ${roleNote[r]}` }))

export function UsersCard() {
  const qc = useQueryClient()
  const me = useAuth().data?.user
  const users = useQuery({ queryKey: ['users'], queryFn: () => api<UserInfo[]>('/api/users') })
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<UserInfo | null>(null)
  return (
    <Card
      title="Usuários do painel"
      subtitle="Cada pessoa com a própria conta, papel e verificação em duas etapas"
      actions={
        <Button size="sm" variant="primary" icon={<UserPlus className="size-3.5" />} onClick={() => setCreating(true)}>
          Nova conta
        </Button>
      }
    >
      <ErrorNote error={users.error} />
      <ul className="divide-y divide-line">
        {users.data?.map((u) => (
          <li key={u.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm">
            <span className="min-w-0 flex-1">
              <span className="block font-medium text-ink">
                {u.display || u.username}
                {u.id === me?.id && <span className="ml-1.5 text-xs font-normal text-muted">(você)</span>}
              </span>
              <span className="block text-xs text-muted">
                {u.username} · {u.last_login && !u.last_login.startsWith('0001') ? `entrou ${ago(u.last_login)}` : 'nunca entrou'}
              </span>
            </span>
            <span className="flex flex-wrap gap-1">
              <StatusBadge tone={u.role === 'admin' ? 'accent' : 'neutral'}>{roleLabel[u.role]}</StatusBadge>
              {u.source === 'ad' && <StatusBadge tone="neutral">AD</StatusBadge>}
              {u.mfa ? <StatusBadge tone="good">MFA</StatusBadge> : <StatusBadge tone="warning">sem MFA</StatusBadge>}
              {u.disabled && <StatusBadge tone="critical">desativada</StatusBadge>}
            </span>
            <Button size="sm" variant="ghost" onClick={() => setEditing(u)}>
              Gerenciar
            </Button>
          </li>
        ))}
      </ul>
      <NewUserModal open={creating} onClose={() => setCreating(false)} onDone={() => qc.invalidateQueries({ queryKey: ['users'] })} />
      <EditUserModal user={editing} self={editing?.id === me?.id} onClose={() => setEditing(null)} />
    </Card>
  )
}

function NewUserModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const empty = { username: '', display: '', role: 'operator' as Role, password: '' }
  const [f, setF] = useState(empty)
  const create = useMutation({
    mutationFn: () => api('/api/users', { method: 'POST', body: f }),
    onSuccess: () => {
      setF(empty)
      onDone()
      onClose()
    },
  })
  return (
    <Modal open={open} onClose={onClose} title="Nova conta no painel">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Usuário">
            <Input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} autoCapitalize="none" required />
          </Field>
          <Field label="Nome">
            <Input value={f.display} onChange={(e) => setF({ ...f, display: e.target.value })} />
          </Field>
        </div>
        <Field label="Papel">
          <Select label="Papel" value={f.role} onChange={(role) => setF({ ...f, role: role as Role })} options={roleOptions} className="w-full" />
        </Field>
        <Field label="Senha inicial" hint="Passe à pessoa por um canal seguro; ela troca em Configurações.">
          <Input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} minLength={8} required />
        </Field>
        <ErrorNote error={create.error} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={create.isPending}>
            Criar conta
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function EditUserModal({ user, self, onClose }: { user: UserInfo | null; self: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [pw, setPw] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)
  const done = () => {
    qc.invalidateQueries({ queryKey: ['users'] })
    setPw('')
    setConfirmDel(false)
  }
  const patch = useMutation({
    mutationFn: (body: Record<string, unknown>) => api<UserInfo>(`/api/users/${user!.id}`, { method: 'PATCH', body }),
    onSuccess: done,
  })
  const del = useMutation({
    mutationFn: () => api(`/api/users/${user!.id}`, { method: 'DELETE' }),
    onSuccess: () => {
      done()
      onClose()
    },
  })
  const u = (patch.data && patch.data.id === user?.id ? patch.data : user) ?? null
  return (
    <Modal open={!!user} onClose={onClose} title={`Conta ${u?.username ?? ''}`}>
      {u && (
        <div className="space-y-5 text-sm">
          <Field label="Papel" hint={u.source === 'ad' ? 'Contas do AD recebem o papel pelos grupos (ad.login).' : 'Mudar o papel encerra as sessões da conta.'}>
            <Select
              label="Papel"
              value={u.role}
              onChange={(role) => patch.mutate({ role })}
              options={roleOptions}
              className="w-full"
            />
          </Field>
          {u.source === 'local' && (
            <form
              className="flex items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                patch.mutate({ password: pw })
              }}
            >
              <Field label="Redefinir a senha">
                <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required />
              </Field>
              <Button type="submit" icon={<KeyRound className="size-4" />} loading={patch.isPending}>
                Redefinir
              </Button>
            </form>
          )}
          <div className="flex flex-wrap gap-2">
            {u.mfa && (
              <Button onClick={() => patch.mutate({ reset_mfa: true })} loading={patch.isPending}>
                Zerar o MFA (perdeu o celular)
              </Button>
            )}
            {!self && (
              <Button onClick={() => patch.mutate({ disabled: !u.disabled })} loading={patch.isPending}>
                {u.disabled ? 'Reativar' : 'Desativar'}
              </Button>
            )}
            {!self && (
              <Button
                variant={confirmDel ? 'danger' : 'ghost'}
                icon={<Trash className="size-4" />}
                loading={del.isPending}
                onClick={() => (confirmDel ? del.mutate() : setConfirmDel(true))}
              >
                {confirmDel ? 'Confirmar exclusão' : 'Excluir'}
              </Button>
            )}
          </div>
          {patch.isSuccess && <p className="text-xs text-good-ink">Alterado. As sessões abertas da conta foram encerradas quando preciso.</p>}
          <ErrorNote error={patch.error || del.error} />
        </div>
      )}
    </Modal>
  )
}

export function TokensCard() {
  const qc = useQueryClient()
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: () => api<APIToken[]>('/api/tokens') })
  const [f, setF] = useState({ name: '', role: 'viewer' as Role, expires_days: 90 })
  const [created, setCreated] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const create = useMutation({
    mutationFn: () => api<{ token: string }>('/api/tokens', { method: 'POST', body: f }),
    onSuccess: (d) => {
      setCreated(d.token)
      setCopied(false)
      setF({ ...f, name: '' })
      qc.invalidateQueries({ queryKey: ['tokens'] })
    },
  })
  const revoke = useMutation({
    mutationFn: (id: number) => api(`/api/tokens/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['tokens'] }),
  })
  return (
    <Card title="Tokens de API" subtitle="Para integrações (Grafana, scripts, automação), cada um com papel e validade">
      <form
        className="mb-4 grid gap-2 sm:grid-cols-[1fr_150px_110px_auto]"
        onSubmit={(e) => {
          e.preventDefault()
          create.mutate()
        }}
      >
        <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="nome (ex.: Grafana)" aria-label="Nome do token" required />
        <Select
          label="Papel do token"
          value={f.role}
          onChange={(role) => setF({ ...f, role: role as Role })}
          options={(['viewer', 'operator', 'admin'] as Role[]).map((r) => ({ value: r, label: roleLabel[r] }))}
        />
        <Select
          label="Validade"
          value={String(f.expires_days)}
          onChange={(v) => setF({ ...f, expires_days: Number(v) })}
          options={[
            { value: '30', label: '30 dias' },
            { value: '90', label: '90 dias' },
            { value: '365', label: '1 ano' },
            { value: '0', label: 'não vence' },
          ]}
        />
        <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={create.isPending}>
          Criar
        </Button>
      </form>
      <ErrorNote error={create.error || tokens.error || revoke.error} />
      {created && (
        <div className="mb-4 rounded-lg border border-accent bg-accent-soft p-3 text-xs">
          <p className="mb-2 flex items-center gap-1.5 font-semibold text-ink">
            <ShieldCheck className="size-4" aria-hidden /> Copie agora: o token não aparece de novo.
          </p>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 font-mono break-all text-ink">{created}</code>
            <Button
              size="sm"
              icon={<Copy className="size-3.5" />}
              onClick={() => navigator.clipboard.writeText(created).then(() => setCopied(true))}
            >
              {copied ? 'Copiado' : 'Copiar'}
            </Button>
          </div>
          <p className="mt-2 text-ink-2">
            Use no cabeçalho <code className="font-mono">Authorization: Bearer &lt;token&gt;</code>.
          </p>
        </div>
      )}
      <ul className="divide-y divide-line text-xs">
        {tokens.data?.map((t) => {
          const expired = !t.expires.startsWith('0001') && new Date(t.expires) < new Date()
          return (
            <li key={t.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-ink">{t.name}</span>
                <span className="block text-muted">
                  <code className="font-mono">{t.prefix}…</code> · criado por {t.created_by} em {fmtDateTime(t.created)} ·{' '}
                  {t.last_used.startsWith('0001') ? 'nunca usado' : `usado ${ago(t.last_used)}`}
                </span>
              </span>
              <StatusBadge tone="neutral">{roleLabel[t.role]}</StatusBadge>
              {expired ? (
                <StatusBadge tone="critical">vencido</StatusBadge>
              ) : (
                <span className="text-muted">{t.expires.startsWith('0001') ? 'não vence' : `vence ${fmtDateTime(t.expires)}`}</span>
              )}
              <Button size="sm" variant="ghost" aria-label={`Revogar ${t.name}`} icon={<Trash className="size-3.5" />} onClick={() => revoke.mutate(t.id)} />
            </li>
          )
        })}
      </ul>
      {tokens.data?.length === 0 && <p className="text-xs text-muted">Nenhum token. A CLI do servidor usa o token próprio do serviço (api.token).</p>}
    </Card>
  )
}
