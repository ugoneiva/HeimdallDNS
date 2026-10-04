import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, FileUp, History, RotateCcw, Upload } from 'lucide-react'
import { api, download, upload, ApiError } from '../api'
import type { BackupList, PiholePreview, PiholeResult, RestoreState } from '../types'
import { fmtDateTime, fmtInt } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, StatusBadge } from '../components/ui'

const mb = (n: number) => (n / 1e6).toLocaleString('pt-BR', { maximumFractionDigits: 1 }) + ' MB'

export function BackupCard() {
  const qc = useQueryClient()
  const list = useQuery({ queryKey: ['backups'], queryFn: () => api<BackupList>('/api/backups') })
  const restoreState = useQuery({ queryKey: ['restore'], queryFn: () => api<RestoreState>('/api/restore') })
  const [full, setFull] = useState(false)
  const [encrypt, setEncrypt] = useState(true)
  const [pass, setPass] = useState('')
  const dl = useMutation({
    mutationFn: () => download('/api/backup', { full, passphrase: encrypt ? pass : '' }, 'heimdalldns-backup.tar.gz'),
  })
  const now = useMutation({
    mutationFn: () => api<BackupList>('/api/backups', { method: 'POST' }),
    onSuccess: (d) => qc.setQueryData(['backups'], d),
  })

  return (
    <Card title="Backup" subtitle="Banco (dispositivos, listas, regras, alertas, configurações do painel) e o arquivo de configuração">
      <div className="space-y-3">
        <LabeledSwitch checked={encrypt} onChange={setEncrypt} label="Cifrar com senha (recomendado: o backup leva o hash da senha do painel e os tokens)" />
        {encrypt && (
          <Field label="Senha do backup" hint="10 caracteres ou mais. Sem ela não há como restaurar; guarde num cofre de senhas.">
            <Input type="password" autoComplete="new-password" value={pass} onChange={(e) => setPass(e.target.value)} />
          </Field>
        )}
        <LabeledSwitch checked={full} onChange={setFull} label="Incluir o histórico de consultas (arquivo bem maior)" />
        <ErrorNote error={dl.error} />
        <Button
          variant="primary"
          icon={<Download className="size-4" />}
          loading={dl.isPending}
          disabled={encrypt && pass.length < 10}
          onClick={() => dl.mutate()}
        >
          Baixar backup
        </Button>
      </div>

      <div className="mt-6 border-t border-line pt-4">
        <div className="mb-2 flex items-center gap-2">
          <History className="size-4 text-muted" aria-hidden />
          <p className="text-xs font-semibold text-ink">Cópias automáticas no servidor</p>
          {list.data && (list.data.auto ? <StatusBadge tone="good">diárias</StatusBadge> : <StatusBadge tone="neutral">desligadas</StatusBadge>)}
          <Button size="sm" variant="ghost" className="ml-auto" loading={now.isPending} onClick={() => now.mutate()}>
            Gerar agora
          </Button>
        </div>
        <ErrorNote error={list.error || now.error} />
        <ul className="divide-y divide-line text-xs">
          {list.data?.files.map((f) => (
            <li key={f.name} className="flex items-center gap-3 py-1.5">
              <span className="flex-1 text-ink">{fmtDateTime(f.created)}</span>
              <span className="tabular text-ink-2">{mb(f.size)}</span>
              <a className="text-accent hover:underline" href={`/api/backups/${encodeURIComponent(f.name)}`} download>
                baixar
              </a>
            </li>
          ))}
        </ul>
        {list.data?.files.length === 0 && <p className="text-xs text-muted">Nenhuma cópia ainda (a primeira sai 5 minutos depois de ligar).</p>}
        {list.data && <p className="mt-2 text-[11px] text-muted">Pasta: <span className="font-mono">{list.data.dir}</span>. Copie para fora do servidor também.</p>}
      </div>

      <div className="mt-6 border-t border-line pt-4">
        <RestoreForm state={restoreState.data} />
      </div>
    </Card>
  )
}

function RestoreForm({ state }: { state?: RestoreState }) {
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [pass, setPass] = useState('')
  const [needPass, setNeedPass] = useState(false)
  const [restarting, setRestarting] = useState(false)
  const send = useMutation({
    mutationFn: () => {
      const fd = new FormData()
      fd.append('passphrase', pass) // antes do arquivo: o servidor lê em ordem
      fd.append('file', file!)
      return upload<RestoreState>('/api/restore', fd)
    },
    onSuccess: (d) => {
      qc.setQueryData(['restore'], d)
      setFile(null)
      setPass('')
      setNeedPass(false)
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 401) setNeedPass(true)
    },
  })
  const cancel = useMutation({
    mutationFn: () => api('/api/restore', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['restore'] }),
  })
  const restart = useMutation({
    mutationFn: () => api('/api/restart', { method: 'POST' }),
    onSuccess: () => {
      setRestarting(true)
      // Espera o serviço voltar e recarrega o painel (a sessão pode ter mudado).
      const t = setInterval(() => {
        fetch('/api/auth/state')
          .then((r) => r.ok && (clearInterval(t), location.reload()))
          .catch(() => {})
      }, 1500)
    },
  })
  const p = state?.pending
  if (p) {
    return (
      <div className="space-y-3 text-xs">
        <p className="font-semibold text-ink">Restauração pronta</p>
        <p className="text-ink-2">
          Backup de <strong className="text-ink">{p.hostname}</strong>, versão {p.version}, gerado em {fmtDateTime(p.created)}
          {p.full ? ', com histórico' : ''}. Vale quando o serviço reiniciar; o banco atual fica guardado ao lado.
        </p>
        {p.has_config && (
          <p className="text-ink-2">
            O arquivo de configuração do backup não é aplicado sozinho (ele fica em /etc, fora do alcance do serviço): confira se o atual serve.
          </p>
        )}
        <ErrorNote error={restart.error || cancel.error} />
        {restarting ? (
          <p className="text-accent">Reiniciando… o painel recarrega sozinho.</p>
        ) : (
          <div className="flex gap-2">
            {state?.can_restart ? (
              <Button variant="primary" icon={<RotateCcw className="size-4" />} loading={restart.isPending} onClick={() => restart.mutate()}>
                Reiniciar e restaurar agora
              </Button>
            ) : (
              <p className="text-ink-2">Reinicie o serviço: systemctl restart heimdalldns</p>
            )}
            <Button variant="ghost" loading={cancel.isPending} onClick={() => cancel.mutate()}>
              Desistir
            </Button>
          </div>
        )}
      </div>
    )
  }
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        send.mutate()
      }}
    >
      <p className="text-xs font-semibold text-ink">Restaurar um backup</p>
      <Input type="file" accept=".gz,.age,.tar.gz" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Arquivo de backup" />
      {(needPass || file?.name.endsWith('.age')) && (
        <Field label="Senha do backup">
          <Input type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
        </Field>
      )}
      <ErrorNote error={send.error} />
      <Button type="submit" icon={<Upload className="size-4" />} loading={send.isPending} disabled={!file}>
        Conferir e preparar
      </Button>
    </form>
  )
}

const sections = [
  { key: 'lists', label: 'Listas de bloqueio', count: (p: Record<string, number>) => p.lists },
  { key: 'rules', label: 'Regras próprias (bloqueio e liberação)', count: (p: Record<string, number>) => p.deny + p.allow },
  { key: 'hosts', label: 'Registros DNS locais', count: (p: Record<string, number>) => p.hosts },
  { key: 'reservations', label: 'Reservas de DHCP', count: (p: Record<string, number>) => p.reservations },
  { key: 'upstreams', label: 'Upstreams (servidores DNS de saída)', count: (p: Record<string, number>) => p.upstreams },
  { key: 'clients', label: 'Nomes dos dispositivos', count: (p: Record<string, number>) => p.clients_found },
] as const

/** Importação do backup do Pi-hole (Teleporter), em duas etapas: prévia e aplicação. */
export function PiholeImport({ onDone }: { onDone?: () => void }) {
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [pick, setPick] = useState<Record<string, boolean>>({ lists: true, rules: true, hosts: true, reservations: true, upstreams: false, clients: true })
  const preview = useMutation({
    mutationFn: () => {
      const fd = new FormData()
      fd.append('file', file!)
      return upload<PiholePreview>('/api/import/pihole', fd)
    },
  })
  const apply = useMutation({
    mutationFn: () => api<PiholeResult>(`/api/import/pihole/${preview.data!.id}/apply`, { method: 'POST', body: pick }),
    onSuccess: () => {
      qc.invalidateQueries()
      onDone?.()
    },
  })

  if (apply.data) {
    const r = apply.data.result
    return (
      <div className="space-y-3 text-xs">
        <p className="font-semibold text-good-ink">Importação concluída</p>
        <ul className="grid gap-1 sm:grid-cols-2">
          {sections.map((s) => (
            <li key={s.key} className="text-ink-2">
              {s.label}: <strong className="text-ink">{fmtInt(r[s.key] ?? 0)}</strong>
            </li>
          ))}
        </ul>
        {apply.data.notes.length > 0 && (
          <details className="text-ink-2">
            <summary className="cursor-pointer">{apply.data.notes.length} avisos</summary>
            <ul className="mt-2 max-h-48 list-disc space-y-0.5 overflow-y-auto pl-5">
              {apply.data.notes.map((n, i) => (
                <li key={i}>{n}</li>
              ))}
            </ul>
          </details>
        )}
      </div>
    )
  }
  if (preview.data) {
    const { plan, export: e } = preview.data
    return (
      <div className="space-y-3 text-xs">
        <p className="text-ink-2">
          Backup do Pi-hole <strong className="text-ink">{e.version}</strong>. Escolha o que trazer (só entra o que ainda não existe aqui):
        </p>
        <div className="space-y-2">
          {sections.map((s) => (
            <LabeledSwitch
              key={s.key}
              checked={pick[s.key]}
              onChange={(v) => setPick({ ...pick, [s.key]: v })}
              label={`${s.label}: ${fmtInt(s.count(plan) ?? 0)}${s.key === 'upstreams' && e.upstreams.length ? ` (${e.upstreams.join(', ')})` : ''}${s.key === 'clients' ? ` de ${plan.clients} (só os já vistos aqui)` : ''}`}
            />
          ))}
        </div>
        {(plan.allow_lists > 0 || plan.groups > 0 || plan.skipped > 0) && (
          <ul className="list-disc space-y-0.5 pl-5 text-muted">
            {plan.allow_lists > 0 && <li>{plan.allow_lists} listas de liberação não têm equivalente e ficam de fora.</li>}
            {plan.groups > 0 && <li>{plan.groups} grupos do Pi-hole não são migrados; use as regras por dispositivo.</li>}
            {plan.skipped > 0 && <li>{plan.skipped} itens não puderam ser convertidos (detalhes no fim).</li>}
            <li>Domínio exato do Pi-hole vira "domínio e subdomínios" aqui.</li>
          </ul>
        )}
        <ErrorNote error={apply.error} />
        <div className="flex gap-2">
          <Button variant="primary" loading={apply.isPending} onClick={() => apply.mutate()}>
            Importar
          </Button>
          <Button variant="ghost" onClick={() => preview.reset()}>
            Outro arquivo
          </Button>
        </div>
      </div>
    )
  }
  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault()
        preview.mutate()
      }}
    >
      <p className="text-xs text-ink-2">
        No Pi-hole: <strong>Settings → Teleporter → Export</strong> (v6 gera um .zip; a v5, um .tar.gz). Nada é aplicado antes da prévia.
      </p>
      <Input type="file" accept=".zip,.gz,.tar.gz" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="Arquivo do Teleporter" />
      <ErrorNote error={preview.error} />
      <Button type="submit" icon={<FileUp className="size-4" />} loading={preview.isPending} disabled={!file}>
        Ver o que será importado
      </Button>
    </form>
  )
}
