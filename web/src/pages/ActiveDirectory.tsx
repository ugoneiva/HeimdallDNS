import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, LockOpen, Plus, Search, Trash, UserCheck, UserPlus, UserX, Users } from 'lucide-react'
import { api, qs } from '../api'
import type { ADGroup, ADInfo, ADRecord, ADUser, ADZone, AuditEntry } from '../types'
import { ago, fmtDateTime } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, Modal, Segmented, Select, StatusBadge, cx } from '../components/ui'

export function useADInfo() {
  return useQuery({ queryKey: ['ad-info'], queryFn: () => api<ADInfo>('/api/ad/info'), retry: false, refetchInterval: 60_000 })
}

type Tab = 'users' | 'groups' | 'dns' | 'audit'

const actionLabel: Record<string, string> = {
  'ad.user.create': 'Criou usuário',
  'ad.user.enable': 'Habilitou usuário',
  'ad.user.disable': 'Desabilitou usuário',
  'ad.user.unlock': 'Desbloqueou usuário',
  'ad.user.password': 'Redefiniu senha',
  'ad.user.delete': 'Excluiu usuário',
  'ad.group.add_member': 'Pôs no grupo',
  'ad.group.remove_member': 'Tirou do grupo',
  'ad.dns.add': 'Criou registro DNS',
  'ad.dns.delete': 'Apagou registro DNS',
}

export function ActiveDirectory() {
  const info = useADInfo()
  const [tab, setTab] = useState<Tab>('users')
  const d = info.data
  if (info.error) return <ErrorNote error={info.error} />
  if (!d) return <p className="text-sm text-muted">Conectando ao AD…</p>
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-surface px-4 py-3 text-xs text-ink-2">
        <span>
          Domínio <strong className="text-ink">{d.info.domain}</strong> em <span className="font-mono">{d.info.dns_host_name}</span>
        </span>
        <StatusBadge tone="neutral">{d.info.vendor === 'Samba' ? 'Samba AD' : 'Windows AD'}</StatusBadge>
        <span className="ml-auto">
          {!d.info.write ? (
            <StatusBadge tone="neutral">Somente leitura (ad.write desligado)</StatusBadge>
          ) : !d.mfa ? (
            <StatusBadge tone="warning">Ligue o MFA em Configurações para alterar o AD</StatusBadge>
          ) : (
            <StatusBadge tone="good">Alterações liberadas (com auditoria)</StatusBadge>
          )}
        </span>
      </div>
      <Segmented
        label="Seção"
        value={tab}
        onChange={setTab}
        options={[
          { value: 'users', label: 'Usuários' },
          { value: 'groups', label: 'Grupos' },
          { value: 'dns', label: 'DNS' },
          { value: 'audit', label: 'Auditoria' },
        ]}
      />
      {tab === 'users' && <UsersTab ad={d} />}
      {tab === 'groups' && <GroupsTab ad={d} />}
      {tab === 'dns' && <DNSTab ad={d} />}
      {tab === 'audit' && <AuditTab />}
    </div>
  )
}

function useDebounced(v: string) {
  const [d, setD] = useState(v)
  useEffect(() => {
    const t = setTimeout(() => setD(v), 300)
    return () => clearTimeout(t)
  }, [v])
  return d
}

function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative w-full sm:w-72">
      <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-muted" aria-hidden />
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="pl-9" aria-label={placeholder} />
    </div>
  )
}

function UsersTab({ ad }: { ad: ADInfo }) {
  const qc = useQueryClient()
  const [q, setQ] = useState('')
  const term = useDebounced(q)
  const users = useQuery({ queryKey: ['ad-users', term], queryFn: () => api<ADUser[]>(`/api/ad/users${qs({ q: term, limit: 200 })}`) })
  const [creating, setCreating] = useState(false)
  const [pwFor, setPwFor] = useState<ADUser | null>(null)
  const [groupsFor, setGroupsFor] = useState<ADUser | null>(null)
  const [confirmDel, setConfirmDel] = useState<string | null>(null)
  const act = useMutation({
    mutationFn: ({ u, path, method }: { u: ADUser; path: string; method: string }) => api(`/api/ad/users/${encodeURIComponent(u.sam)}${path}`, { method }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-users'] }),
  })
  const list = users.data ?? []
  return (
    <Card pad={false}>
      <div className="flex flex-wrap items-center gap-3 border-b border-line p-4">
        <SearchBox value={q} onChange={setQ} placeholder="Login, nome ou e-mail…" />
        {ad.can_write && ad.policy.user_ous.length > 0 && (
          <Button variant="primary" className="ml-auto" icon={<UserPlus className="size-4" />} onClick={() => setCreating(true)}>
            Novo usuário
          </Button>
        )}
      </div>
      <ErrorNote error={users.error || act.error} />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-sm">
          <thead className="text-left text-xs text-muted">
            <tr className="border-b border-line">
              <th className="px-4 py-2.5 font-medium">Usuário</th>
              <th className="px-3 py-2.5 font-medium">Situação</th>
              <th className="px-3 py-2.5 font-medium">Último logon</th>
              <th className="px-3 py-2.5 font-medium">Grupos</th>
              <th className="px-3 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {list.map((u) => (
              <tr key={u.dn} className="border-b border-line last:border-0 align-top">
                <td className="px-4 py-2.5">
                  <span className="block font-medium text-ink">{u.display_name || u.sam}</span>
                  <span className="block font-mono text-[11px] text-muted">{u.sam}{u.mail && ` · ${u.mail}`}</span>
                </td>
                <td className="px-3 py-2.5">
                  <span className="flex flex-wrap gap-1">
                    {u.enabled ? <StatusBadge tone="good">Ativo</StatusBadge> : <StatusBadge tone="neutral">Desabilitado</StatusBadge>}
                    {u.locked && <StatusBadge tone="critical">Bloqueado</StatusBadge>}
                    {u.privileged && <StatusBadge tone="warning">Privilegiado</StatusBadge>}
                  </span>
                </td>
                <td className="px-3 py-2.5 text-xs text-ink-2">{u.last_logon ? ago(u.last_logon) : 'nunca'}</td>
                <td className="max-w-56 px-3 py-2.5 text-xs text-ink-2">{u.groups.join(', ') || '—'}</td>
                <td className="px-3 py-2.5">
                  {ad.can_write && u.manageable ? (
                    <span className="flex flex-wrap justify-end gap-1">
                      <Button size="sm" variant="ghost" icon={u.enabled ? <UserX className="size-3.5" /> : <UserCheck className="size-3.5" />}
                        onClick={() => act.mutate({ u, path: u.enabled ? '/disable' : '/enable', method: 'POST' })}>
                        {u.enabled ? 'Desabilitar' : 'Habilitar'}
                      </Button>
                      {u.locked && (
                        <Button size="sm" variant="ghost" icon={<LockOpen className="size-3.5" />} onClick={() => act.mutate({ u, path: '/unlock', method: 'POST' })}>
                          Desbloquear
                        </Button>
                      )}
                      <Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} onClick={() => setPwFor(u)}>
                        Senha
                      </Button>
                      <Button size="sm" variant="ghost" icon={<Users className="size-3.5" />} onClick={() => setGroupsFor(u)}>
                        Grupos
                      </Button>
                      <Button
                        size="sm"
                        variant={confirmDel === u.sam ? 'danger' : 'ghost'}
                        icon={<Trash className="size-3.5" />}
                        onBlur={() => setConfirmDel(null)}
                        onClick={() => (confirmDel === u.sam ? act.mutate({ u, path: '', method: 'DELETE' }) : setConfirmDel(u.sam))}
                      >
                        {confirmDel === u.sam ? 'Excluir' : ''}
                      </Button>
                    </span>
                  ) : (
                    <span className="block text-right text-[11px] text-muted">{u.privileged ? 'protegido' : ad.can_write ? 'fora das OUs liberadas' : ''}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!users.isLoading && list.length === 0 && <p className="py-8 text-center text-sm text-muted">Nenhum usuário encontrado.</p>}
      </div>
      <NewUserModal open={creating} onClose={() => setCreating(false)} ous={ad.policy.user_ous} />
      <PasswordModal user={pwFor} onClose={() => setPwFor(null)} />
      <UserGroupsModal user={groupsFor} onClose={() => setGroupsFor(null)} managed={ad.policy.managed_groups} />
    </Card>
  )
}

function NewUserModal({ open, onClose, ous }: { open: boolean; onClose: () => void; ous: string[] }) {
  const qc = useQueryClient()
  const empty = { ou: ous[0] ?? '', sam: '', given_name: '', surname: '', mail: '', password: '', must_change: true, enabled: true }
  const [f, setF] = useState(empty)
  const create = useMutation({
    mutationFn: () => api<ADUser>('/api/ad/users', { method: 'POST', body: f }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ad-users'] })
      setF(empty)
      onClose()
    },
  })
  return (
    <Modal open={open} onClose={onClose} title="Novo usuário no AD">
      <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), create.mutate())}>
        <Field label="OU">
          <Select label="OU" value={f.ou} onChange={(ou) => setF({ ...f, ou })} className="w-full" options={ous.map((o) => ({ value: o, label: o }))} />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Nome">
            <Input value={f.given_name} onChange={(e) => setF({ ...f, given_name: e.target.value })} required />
          </Field>
          <Field label="Sobrenome">
            <Input value={f.surname} onChange={(e) => setF({ ...f, surname: e.target.value })} />
          </Field>
          <Field label="Login (sAMAccountName)" hint="Até 20 caracteres, sem espaços.">
            <Input value={f.sam} onChange={(e) => setF({ ...f, sam: e.target.value })} required maxLength={20} />
          </Field>
          <Field label="E-mail">
            <Input type="email" value={f.mail} onChange={(e) => setF({ ...f, mail: e.target.value })} />
          </Field>
        </div>
        <Field label="Senha inicial" hint="Precisa passar na política de senha do domínio.">
          <Input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required />
        </Field>
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={f.must_change} onChange={(e) => setF({ ...f, must_change: e.target.checked })} />
          Trocar a senha no primeiro logon
        </label>
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
          Criar já habilitado
        </label>
        <ErrorNote error={create.error} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={create.isPending}>
            Criar usuário
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function PasswordModal({ user, onClose }: { user: ADUser | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [pw, setPw] = useState('')
  const [must, setMust] = useState(true)
  const save = useMutation({
    mutationFn: () => api(`/api/ad/users/${encodeURIComponent(user!.sam)}/password`, { method: 'POST', body: { password: pw, must_change: must } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ad-users'] })
      setPw('')
      onClose()
    },
  })
  return (
    <Modal open={!!user} onClose={onClose} title={`Redefinir senha de ${user?.sam ?? ''}`}>
      <form className="space-y-3" onSubmit={(e) => (e.preventDefault(), save.mutate())}>
        <Field label="Nova senha">
          <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} required />
        </Field>
        <label className="flex items-center gap-2 text-xs text-ink-2">
          <input type="checkbox" checked={must} onChange={(e) => setMust(e.target.checked)} />
          Trocar no próximo logon
        </label>
        <p className="text-[11px] text-muted">A senha não é guardada nem vai para a auditoria; só fica registrado que houve a troca.</p>
        <ErrorNote error={save.error} />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" loading={save.isPending}>
            Redefinir
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function UserGroupsModal({ user, onClose, managed }: { user: ADUser | null; onClose: () => void; managed: string[] }) {
  const qc = useQueryClient()
  const toggle = useMutation({
    mutationFn: ({ group, add }: { group: string; add: boolean }) =>
      add
        ? api(`/api/ad/groups/${encodeURIComponent(group)}/members`, { method: 'POST', body: { sam: user!.sam } })
        : api(`/api/ad/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(user!.sam)}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-users'] }),
  })
  const fresh = useQuery({
    queryKey: ['ad-user', user?.sam],
    queryFn: () => api<ADUser>(`/api/ad/users/${encodeURIComponent(user!.sam)}`),
    enabled: !!user,
  })
  const groups = fresh.data?.groups ?? user?.groups ?? []
  return (
    <Modal open={!!user} onClose={onClose} title={`Grupos de ${user?.sam ?? ''}`}>
      <p className="mb-3 text-xs text-ink-2">Só os grupos liberados em ad.managed_groups aparecem aqui. Grupos privilegiados nunca são alterados.</p>
      <ul className="divide-y divide-line">
        {managed.map((g) => {
          const member = groups.some((x) => x.toLowerCase() === g.toLowerCase())
          return (
            <li key={g} className="flex items-center justify-between py-2 text-sm">
              <span className="text-ink">{g}</span>
              <Button
                size="sm"
                variant={member ? 'ghost' : 'secondary'}
                loading={toggle.isPending && toggle.variables?.group === g}
                onClick={() => toggle.mutate({ group: g, add: !member }, { onSuccess: () => fresh.refetch() })}
              >
                {member ? 'Tirar' : 'Colocar'}
              </Button>
            </li>
          )
        })}
      </ul>
      <ErrorNote error={toggle.error} />
    </Modal>
  )
}

function GroupsTab({ ad }: { ad: ADInfo }) {
  const [q, setQ] = useState('')
  const term = useDebounced(q)
  const [open, setOpen] = useState<string | null>(null)
  const groups = useQuery({ queryKey: ['ad-groups', term], queryFn: () => api<ADGroup[]>(`/api/ad/groups${qs({ q: term, limit: 300 })}`) })
  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
      <Card pad={false}>
        <div className="border-b border-line p-4">
          <SearchBox value={q} onChange={setQ} placeholder="Nome do grupo…" />
        </div>
        <ErrorNote error={groups.error} />
        <ul className="max-h-[60vh] divide-y divide-line overflow-y-auto">
          {(groups.data ?? []).map((g) => (
            <li key={g.dn}>
              <button onClick={() => setOpen(g.name)} className={cx('flex w-full items-center gap-2 px-4 py-2.5 text-left text-sm hover:bg-surface-2', open === g.name && 'bg-surface-2')}>
                <span className="flex-1 text-ink">{g.name}</span>
                <span className="text-xs text-muted">{g.members}</span>
                {g.privileged && <StatusBadge tone="warning">Privilegiado</StatusBadge>}
                {g.managed && <StatusBadge tone="accent">Liberado</StatusBadge>}
              </button>
            </li>
          ))}
        </ul>
      </Card>
      {open ? <GroupDetail name={open} canWrite={ad.can_write} /> : <Card><p className="text-sm text-muted">Escolha um grupo para ver os membros.</p></Card>}
    </div>
  )
}

function GroupDetail({ name, canWrite }: { name: string; canWrite: boolean }) {
  const qc = useQueryClient()
  const g = useQuery({ queryKey: ['ad-group', name], queryFn: () => api<{ group: ADGroup; members: string[] }>(`/api/ad/groups/${encodeURIComponent(name)}`) })
  const [sam, setSam] = useState('')
  const change = useMutation({
    mutationFn: ({ who, add }: { who: string; add: boolean }) =>
      add
        ? api(`/api/ad/groups/${encodeURIComponent(name)}/members`, { method: 'POST', body: { sam: who } })
        : api(`/api/ad/groups/${encodeURIComponent(name)}/members/${encodeURIComponent(who)}`, { method: 'DELETE' }),
    onSuccess: () => {
      setSam('')
      qc.invalidateQueries({ queryKey: ['ad-group', name] })
      qc.invalidateQueries({ queryKey: ['ad-groups'] })
    },
  })
  const editable = canWrite && !!g.data?.group.managed
  return (
    <Card title={name} subtitle={g.data?.group.description || (editable ? 'Grupo liberado para alteração' : 'Somente leitura')}>
      <ErrorNote error={g.error || change.error} />
      {editable && (
        <form className="mb-4 flex gap-2" onSubmit={(e) => (e.preventDefault(), change.mutate({ who: sam.trim(), add: true }))}>
          <Input value={sam} onChange={(e) => setSam(e.target.value)} placeholder="login do usuário" required />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={change.isPending}>
            Colocar
          </Button>
        </form>
      )}
      <ul className="divide-y divide-line">
        {(g.data?.members ?? []).map((m) => (
          <li key={m} className="flex items-center justify-between py-2 text-sm">
            <span className="text-ink">{m}</span>
            {editable && (
              <Button size="sm" variant="ghost" onClick={() => change.mutate({ who: m, add: false })}>
                Tirar
              </Button>
            )}
          </li>
        ))}
      </ul>
      {g.data && g.data.members.length === 0 && <p className="text-sm text-muted">Sem membros.</p>}
    </Card>
  )
}

function DNSTab({ ad }: { ad: ADInfo }) {
  const qc = useQueryClient()
  const zones = useQuery({ queryKey: ['ad-zones'], queryFn: () => api<ADZone[]>('/api/ad/zones') })
  const [zone, setZone] = useState('')
  useEffect(() => {
    if (!zone && zones.data?.length) setZone((zones.data.find((z) => z.editable) ?? zones.data[0]).name)
  }, [zones.data, zone])
  const z = zones.data?.find((x) => x.name === zone)
  const recs = useQuery({
    queryKey: ['ad-records', zone],
    queryFn: () => api<ADRecord[]>(`/api/ad/zones/${encodeURIComponent(zone)}/records`),
    enabled: !!zone,
  })
  const [f, setF] = useState({ name: '', type: 'A', data: '', ttl: 3600 })
  const change = useMutation({
    mutationFn: ({ add, r }: { add: boolean; r: { name: string; type: string; data: string; ttl?: number } }) =>
      api(`/api/ad/zones/${encodeURIComponent(zone)}/records`, { method: add ? 'POST' : 'DELETE', body: r }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ad-records', zone] }),
  })
  const editable = ad.can_write && !!z?.editable
  const canDelete = (r: ADRecord) => editable && !r.protected && ['A', 'AAAA', 'CNAME', 'PTR'].includes(r.type)
  return (
    <Card pad={false}>
      <div className="flex flex-wrap items-center gap-3 border-b border-line p-4">
        <Select
          label="Zona"
          value={zone}
          onChange={setZone}
          options={(zones.data ?? []).map((x) => ({ value: x.name, label: `${x.name}${x.editable ? '' : ' (somente leitura)'}` }))}
        />
        {z && <span className="text-xs text-muted">{z.location}</span>}
      </div>
      {editable && (
        <form
          className="grid gap-2 border-b border-line p-4 sm:grid-cols-[1fr_110px_1.4fr_100px_auto]"
          onSubmit={(e) => (e.preventDefault(), change.mutate({ add: true, r: f }, { onSuccess: () => setF({ ...f, name: '', data: '' }) }))}
        >
          <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder={`nome (vira nome.${zone})`} required />
          <Select label="Tipo" value={f.type} onChange={(type) => setF({ ...f, type })} options={['A', 'AAAA', 'CNAME', 'PTR'].map((t) => ({ value: t, label: t }))} />
          <Input value={f.data} onChange={(e) => setF({ ...f, data: e.target.value })} placeholder={f.type === 'CNAME' || f.type === 'PTR' ? 'destino.empresa.local' : 'IP'} required />
          <Input type="number" min={60} value={f.ttl} onChange={(e) => setF({ ...f, ttl: Number(e.target.value) })} aria-label="TTL" />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={change.isPending}>
            Criar
          </Button>
          {ad.info.vendor !== 'Samba' && (
            <p className="col-span-full text-[11px] text-muted">
              No AD do Windows, o servidor DNS lê as mudanças do AD periodicamente: o registro pode levar alguns minutos para responder.
            </p>
          )}
        </form>
      )}
      <ErrorNote error={zones.error || recs.error || change.error} />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead className="text-left text-xs text-muted">
            <tr className="border-b border-line">
              <th className="px-4 py-2.5 font-medium">Nome</th>
              <th className="px-3 py-2.5 font-medium">Tipo</th>
              <th className="px-3 py-2.5 font-medium">Valor</th>
              <th className="px-3 py-2.5 text-right font-medium">TTL</th>
              <th className="w-24 px-3 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {(recs.data ?? []).map((r, i) => (
              <tr key={`${r.name}-${r.type}-${r.data}-${i}`} className="border-b border-line last:border-0">
                <td className="px-4 py-2 font-mono text-xs text-ink">{r.name}</td>
                <td className="px-3 py-2 font-mono text-xs text-ink-2">{r.type}</td>
                <td className="px-3 py-2 font-mono text-xs break-all text-ink-2">{r.data}</td>
                <td className="tabular px-3 py-2 text-right text-xs text-ink-2">{r.ttl}</td>
                <td className="px-3 py-2 text-right">
                  {canDelete(r) && (
                    <Button size="sm" variant="ghost" icon={<Trash className="size-3.5" />} onClick={() => change.mutate({ add: false, r: { name: r.name, type: r.type, data: r.data } })} aria-label={`Apagar ${r.name} ${r.type}`} />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function AuditTab() {
  const audit = useQuery({ queryKey: ['audit'], queryFn: () => api<AuditEntry[]>('/api/audit?range=90d&limit=300'), refetchInterval: 15_000 })
  return (
    <Card pad={false} title="Auditoria" subtitle="Toda alteração no AD fica registrada (e vai para o SIEM, se a exportação estiver ligada)">
      <ErrorNote error={audit.error} />
      <ul className="divide-y divide-line">
        {(audit.data ?? []).map((e) => (
          <li key={e.id} className="flex flex-wrap items-start gap-x-4 gap-y-1 px-4 py-2.5 text-xs sm:px-5">
            <span className="w-32 shrink-0 text-ink-2">{fmtDateTime(e.time)}</span>
            <span className="w-20 shrink-0">{e.ok ? <StatusBadge tone="good">ok</StatusBadge> : <StatusBadge tone="critical">recusado</StatusBadge>}</span>
            <span className="min-w-0 flex-1">
              <strong className="text-ink">{actionLabel[e.action] ?? e.action}</strong> <span className="font-mono text-ink">{e.target}</span>
              {e.details && Object.keys(e.details).length > 0 && (
                <span className="ml-2 text-muted">
                  {Object.entries(e.details)
                    .filter(([, v]) => v !== '' && v !== null && v !== undefined)
                    .map(([k, v]) => `${k}=${String(v)}`)
                    .join(' · ')}
                </span>
              )}
              {e.error && <span className="block text-critical-ink">{e.error}</span>}
            </span>
            <span className="text-muted">
              {e.actor} · {e.ip}
            </span>
          </li>
        ))}
      </ul>
      {audit.data?.length === 0 && <p className="py-8 text-center text-sm text-muted">Nenhuma alteração registrada.</p>}
    </Card>
  )
}
