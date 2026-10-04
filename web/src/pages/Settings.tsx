import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { LogOut, Monitor, Moon, Sun } from 'lucide-react'
import { api } from '../api'
import type { Status } from '../types'
import { setTheme, useTheme } from '../lib/theme'
import { fmtInt, fmtPct, uptime } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, Segmented } from '../components/ui'
import { useDHCP } from './DHCP'

export function Settings({ onLogout }: { onLogout: () => void }) {
  const { choice } = useTheme()
  const status = useQuery({ queryKey: ['status'], queryFn: () => api<Status>('/api/status'), refetchInterval: 5000 })
  const s = status.data
  const hit = s && s.cache.hits + s.cache.misses ? (s.cache.hits / (s.cache.hits + s.cache.misses)) * 100 : 0

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Aparência">
        <Segmented
          label="Tema"
          value={choice}
          onChange={setTheme}
          options={[
            { value: 'dark', label: <span className="flex items-center gap-1.5"><Moon className="size-3.5" aria-hidden />Escuro</span> },
            { value: 'light', label: <span className="flex items-center gap-1.5"><Sun className="size-3.5" aria-hidden />Claro</span> },
            { value: 'auto', label: <span className="flex items-center gap-1.5"><Monitor className="size-3.5" aria-hidden />Sistema</span> },
          ]}
        />
      </Card>

      <Card title="Sobre este servidor">
        {s ? (
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs">
            {(
              [
                ['Versão', s.version],
                ['Ligado há', uptime(s.uptime_s)],
                ['Consultas desde que ligou', fmtInt(s.queries.total)],
                ['Regras de bloqueio', fmtInt(s.rules.block)],
                ['Respostas no cache', fmtInt(s.cache.entries)],
                ['Acerto do cache', fmtPct(hit)],
                ['Dispositivos conhecidos', fmtInt(s.clients)],
                ['Histórico descartado', s.history ? fmtInt(s.history.dropped_rows) + ' linhas' : '—'],
              ] as const
            ).map(([k, v]) => (
              <div key={k}>
                <dt className="text-muted">{k}</dt>
                <dd className="mt-0.5 font-medium text-ink">{v}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="text-xs text-muted">Carregando…</p>
        )}
      </Card>

      <DHCPCard />

      <PasswordCard />

      <Card title="Sessão">
        <p className="mb-4 text-xs text-ink-2">
          A sessão dura 7 dias. Se perder a senha, rode <code className="font-mono text-ink">sudo heimdalldns passwd</code> no servidor.
        </p>
        <Button icon={<LogOut className="size-4" />} onClick={onLogout}>
          Sair
        </Button>
      </Card>
    </div>
  )
}

function DHCPCard() {
  const { data } = useDHCP()
  if (!data || data.enabled) return null
  return (
    <Card title="DHCP" subtitle="Desligado">
      <p className="mb-3 text-xs leading-relaxed text-ink-2">
        Com o DHCP do HeimdallDNS, cada aparelho recebe este servidor como DNS automaticamente, o radar aprende nome e MAC direto da
        concessão, e os nomes resolvem como <code className="font-mono text-ink">notebook-da-ana.lan</code>. Desligue o DHCP do roteador
        antes: dois servidores DHCP na mesma rede brigam.
      </p>
      <pre className="overflow-x-auto rounded-lg bg-surface-2 p-3 font-mono text-[11px] text-ink">{`dhcp:
  enabled: true
  interface: eth0
  range_start: 192.168.1.100
  range_end: 192.168.1.200
  domain: lan`}</pre>
    </Card>
  )
}

function PasswordCard() {
  const [current, setCurrent] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const [ok, setOk] = useState(false)
  const change = useMutation({
    mutationFn: () => {
      if (pw !== pw2) throw new Error('As senhas novas não conferem.')
      return api('/api/auth/password', { method: 'POST', body: { current, password: pw } })
    },
    onSuccess: () => {
      setOk(true)
      setCurrent('')
      setPw('')
      setPw2('')
    },
  })
  return (
    <Card title="Trocar a senha" subtitle="Encerra as outras sessões abertas">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          setOk(false)
          change.mutate()
        }}
      >
        <Field label="Senha atual">
          <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Nova senha" hint="Pelo menos 8 caracteres.">
            <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required />
          </Field>
          <Field label="Repita a nova senha">
            <Input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} minLength={8} required />
          </Field>
        </div>
        <ErrorNote error={change.error} />
        {ok && <p className="text-xs text-good-ink">Senha alterada.</p>}
        <Button type="submit" variant="primary" loading={change.isPending}>
          Trocar senha
        </Button>
      </form>
    </Card>
  )
}
