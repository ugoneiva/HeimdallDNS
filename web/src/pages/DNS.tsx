import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RotateCcw, Trash } from 'lucide-react'
import { api } from '../api'
import type { LocalRecord, LocalRecords, UpstreamState } from '../types'
import { Button, Card, ErrorNote, Field, Input, Select, StatusBadge, Textarea, cx } from '../components/ui'

// Resolvedores públicos conhecidos, todos com criptografia (DoH/DoT).
export const upstreamPresets = [
  { id: 'cloudflare', name: 'Cloudflare', note: 'O mais rápido na maioria das redes', servers: ['https://cloudflare-dns.com/dns-query', 'tls://1.1.1.1'] },
  { id: 'quad9', name: 'Quad9', note: 'Bloqueia domínios maliciosos na origem', servers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'] },
  { id: 'google', name: 'Google', note: 'Alta disponibilidade', servers: ['https://dns.google/dns-query', 'tls://dns.google'] },
  { id: 'adguard', name: 'AdGuard DNS', note: 'Bloqueio extra de anúncios', servers: ['https://dns.adguard-dns.com/dns-query'] },
]

const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

export function useUpstream() {
  return useQuery({ queryKey: ['upstream'], queryFn: () => api<UpstreamState>('/api/dns/upstream'), refetchInterval: 15_000 })
}

export function DNS() {
  return (
    <div className="space-y-5">
      <UpstreamCard />
      <LocalRecordsCard />
    </div>
  )
}

/** Escolha dos upstreams: predefinições (somam) e/ou endereços próprios. */
export function UpstreamPicker({ initial, initialMode = 'fastest', onSave, saving, saveLabel = 'Salvar' }: {
  initial: string[]
  initialMode?: string
  onSave: (servers: string[], mode: string) => void
  saving?: boolean
  saveLabel?: string
}) {
  const [text, setText] = useState(initial.join('\n'))
  const [mode, setMode] = useState(initialMode)
  // Só reinicia o texto quando a lista do servidor muda de fato (a consulta
  // repete a cada 15 s e devolve um array novo).
  const initialText = initial.join('\n')
  useEffect(() => setText(initialText), [initialText])
  useEffect(() => setMode(initialMode), [initialMode])
  const current = lines(text)
  const toggle = (servers: string[]) => {
    const on = servers.every((s) => current.includes(s))
    setText((on ? current.filter((s) => !servers.includes(s)) : [...current, ...servers.filter((s) => !current.includes(s))]).join('\n'))
  }
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-2">
        {upstreamPresets.map((p) => {
          const on = p.servers.every((s) => current.includes(s))
          return (
            <button
              key={p.id}
              type="button"
              aria-pressed={on}
              onClick={() => toggle(p.servers)}
              className={cx(
                'rounded-lg border px-3 py-2.5 text-left transition-colors',
                on ? 'border-accent bg-accent-soft' : 'border-line hover:bg-surface-2',
              )}
            >
              <span className="block text-sm font-medium text-ink">{p.name}</span>
              <span className="block text-xs text-ink-2">{p.note}</span>
            </button>
          )
        })}
      </div>
      <Field label="Servidores (um por linha)" hint="Aceita https:// (DoH), tls:// (DoT), quic:// (DoQ) ou IP comum (ex.: 192.168.0.1:53).">
        <Textarea rows={4} value={text} onChange={(e) => setText(e.target.value)} className="font-mono text-xs" />
      </Field>
      <div className="flex flex-wrap items-end gap-3">
        <Field label="Como escolher">
          <Select
            label="Como escolher"
            value={mode}
            onChange={setMode}
            options={[
              { value: 'fastest', label: 'O mais rápido (recomendado)' },
              { value: 'parallel', label: 'Todos ao mesmo tempo' },
              { value: 'failover', label: 'Em ordem (o próximo só se o anterior falhar)' },
            ]}
          />
        </Field>
        <Button variant="primary" loading={saving} disabled={current.length === 0} onClick={() => onSave(current, mode)}>
          {saveLabel}
        </Button>
      </div>
    </div>
  )
}

function UpstreamCard() {
  const qc = useQueryClient()
  const up = useUpstream()
  const save = useMutation({
    mutationFn: ({ servers, mode }: { servers: string[]; mode: string }) => api('/api/dns/upstream', { method: 'PUT', body: { servers, mode } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['upstream'] }),
  })
  const reset = useMutation({
    mutationFn: () => api('/api/dns/upstream', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['upstream'] }),
  })
  const d = up.data
  return (
    <Card
      title="Para onde as consultas vão"
      subtitle={d?.custom ? 'Definido pelo painel (sobrepõe o arquivo de configuração)' : 'Vindo do arquivo de configuração'}
      actions={
        d?.custom && d.config_servers.length > 0 ? (
          <Button size="sm" variant="ghost" icon={<RotateCcw className="size-3.5" />} loading={reset.isPending} onClick={() => reset.mutate()}>
            Voltar ao arquivo
          </Button>
        ) : undefined
      }
    >
      <ErrorNote error={up.error || save.error || reset.error} />
      {d && (
        <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
          <UpstreamPicker initial={d.servers} initialMode={d.mode} saving={save.isPending} onSave={(servers, mode) => save.mutate({ servers, mode })} />
          <div>
            <p className="mb-2 text-xs font-semibold text-ink">Em uso agora</p>
            <ul className="divide-y divide-line rounded-lg border border-line">
              {d.stats.map((s) => (
                <li key={s.address} className="flex items-center gap-3 px-3 py-2 text-xs">
                  <span className="min-w-0 flex-1 truncate font-mono text-ink" title={s.address}>
                    {s.address}
                  </span>
                  <span className="tabular text-ink-2">{s.latency_ms ? `${s.latency_ms} ms` : '—'}</span>
                  {s.healthy ? <StatusBadge tone="good">ok</StatusBadge> : <StatusBadge tone="critical">sem resposta</StatusBadge>}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[11px] text-muted">A troca vale na hora, sem reiniciar; o cache é limpo.</p>
          </div>
        </div>
      )}
    </Card>
  )
}

function LocalRecordsCard() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['local-records'], queryFn: () => api<LocalRecords>('/api/dns/local') })
  const [f, setF] = useState<LocalRecord>({ name: '', type: 'A', value: '' })
  const save = useMutation({
    mutationFn: (records: LocalRecord[]) => api<LocalRecords>('/api/dns/local', { method: 'PUT', body: { records } }),
    onSuccess: (d) => qc.setQueryData(['local-records'], d),
  })
  const recs = q.data?.records ?? []
  const add = () =>
    save.mutate([...recs, { ...f, name: f.name.trim(), value: f.value.trim() }], { onSuccess: () => setF({ ...f, name: '', value: '' }) })
  return (
    <Card title="Registros locais" subtitle="Nomes da sua rede: impressora, NAS, câmeras, sistemas internos">
      <form
        className="mb-4 grid gap-2 sm:grid-cols-[1fr_110px_1fr_auto]"
        onSubmit={(e) => {
          e.preventDefault()
          add()
        }}
      >
        <Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="nome (ex.: nas.casa)" aria-label="Nome" required />
        <Select
          label="Tipo"
          value={f.type}
          onChange={(type) => setF({ ...f, type: type as LocalRecord['type'] })}
          options={[
            { value: 'A', label: 'A (IPv4)' },
            { value: 'AAAA', label: 'AAAA (IPv6)' },
            { value: 'CNAME', label: 'CNAME (apelido)' },
          ]}
        />
        <Input
          value={f.value}
          onChange={(e) => setF({ ...f, value: e.target.value })}
          placeholder={f.type === 'CNAME' ? 'nome de destino' : 'IP'}
          aria-label="Valor"
          required
        />
        <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={save.isPending}>
          Adicionar
        </Button>
      </form>
      <ErrorNote error={q.error || save.error} />
      <div className="overflow-x-auto">
        <table className="w-full min-w-[520px] text-sm">
          <thead className="text-left text-xs text-muted">
            <tr className="border-b border-line">
              <th className="py-2 pr-3 font-medium">Nome</th>
              <th className="px-3 py-2 font-medium">Tipo</th>
              <th className="px-3 py-2 font-medium">Valor</th>
              <th className="px-3 py-2 font-medium">Origem</th>
              <th className="w-12" />
            </tr>
          </thead>
          <tbody>
            {recs.map((r, i) => (
              <tr key={`p-${r.name}-${r.type}-${r.value}`} className="border-b border-line last:border-0">
                <td className="py-2 pr-3 font-mono text-xs text-ink">{r.name}</td>
                <td className="px-3 py-2 font-mono text-xs text-ink-2">{r.type}</td>
                <td className="px-3 py-2 font-mono text-xs text-ink-2">{r.value}</td>
                <td className="px-3 py-2 text-xs text-ink-2">painel</td>
                <td className="py-2 text-right">
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`Apagar ${r.name}`}
                    icon={<Trash className="size-3.5" />}
                    onClick={() => save.mutate(recs.filter((_, j) => j !== i))}
                  />
                </td>
              </tr>
            ))}
            {q.data?.config.map((r) => (
              <tr key={`c-${r.name}-${r.type}-${r.value}`} className="border-b border-line last:border-0">
                <td className="py-2 pr-3 font-mono text-xs text-ink">{r.name}</td>
                <td className="px-3 py-2 font-mono text-xs text-ink-2">{r.type}</td>
                <td className="px-3 py-2 font-mono text-xs text-ink-2">{r.value}</td>
                <td className="px-3 py-2 text-xs text-muted">arquivo</td>
                <td />
              </tr>
            ))}
          </tbody>
        </table>
        {q.data && recs.length + q.data.config.length === 0 && (
          <p className="py-6 text-center text-sm text-muted">Nenhum registro local.</p>
        )}
      </div>
    </Card>
  )
}
