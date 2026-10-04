import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { LogOut, Monitor, Moon, Sun } from 'lucide-react'
import { api } from '../api'
import type { Status } from '../types'
import { setTheme, useTheme } from '../lib/theme'
import { ago, fmtInt, fmtPct, uptime } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, Segmented, StatusBadge } from '../components/ui'
import { useDHCP } from './DHCP'
import { useHA } from '../components/HABanner'

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

      <HACard />

      <DHCPCard />

      <PasswordCard />

      <MFACard />

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

function HACard() {
  const { data } = useHA()
  if (!data) return null
  if (data.role === '') {
    return (
      <Card title="Alta disponibilidade" subtitle="Nó único">
        <p className="mb-3 text-xs leading-relaxed text-ink-2">
          Com um segundo HeimdallDNS como réplica, a rede continua com DNS se um dos dois cair. Entregue os dois como servidores DNS
          (no DHCP ou no roteador). Listas, regras, segurança, dispositivos e a senha vão do principal para a réplica em cerca de 1 segundo.
        </p>
        <pre className="overflow-x-auto rounded-lg bg-surface-2 p-3 font-mono text-[11px] text-ink">{`# no principal
ha:
  role: primary
  sync_token: <segredo de 16+ caracteres>

# na réplica
ha:
  role: replica
  sync_token: <o mesmo segredo>
  primary_url: http://IP-DO-PRINCIPAL:8053`}</pre>
      </Card>
    )
  }
  if (data.role === 'replica') {
    const r = data.replica
    return (
      <Card title="Alta disponibilidade" subtitle="Este nó é uma réplica">
        <dl className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <dt className="text-muted">Principal</dt>
            <dd className="mt-0.5 font-mono text-ink">{r?.primary_url}</dd>
          </div>
          <div>
            <dt className="text-muted">Última sincronização</dt>
            <dd className="mt-0.5 text-ink">{ago(r?.last_sync)}</dd>
          </div>
          {r?.error && (
            <div className="col-span-2">
              <dt className="text-muted">Erro</dt>
              <dd className="mt-0.5 break-all text-critical-ink">{r.error}</dd>
            </div>
          )}
        </dl>
      </Card>
    )
  }
  const reps = data.replicas ?? []
  return (
    <Card title="Alta disponibilidade" subtitle="Este nó é o principal">
      {reps.length === 0 ? (
        <p className="text-xs text-muted">Nenhuma réplica conectada na última hora.</p>
      ) : (
        <ul className="space-y-2 text-xs">
          {reps.map((r) => (
            <li key={r.addr} className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-ink">{r.addr}</span>
              <span className="text-ink-2">visto {ago(r.last_seen)}</span>
              {r.version === data.version ? <StatusBadge tone="good">Em dia</StatusBadge> : <StatusBadge tone="warning">Atualizando</StatusBadge>}
            </li>
          ))}
        </ul>
      )}
    </Card>
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
  const ha = useHA()
  if (ha.data?.role === 'replica') {
    return (
      <Card title="Trocar a senha" subtitle="Feito no principal">
        <p className="text-xs text-ink-2">Nesta réplica a senha vem do principal: troque por lá e ela chega aqui em cerca de 1 segundo.</p>
      </Card>
    )
  }
  return <PasswordForm />
}

export function MFACard() {
  const qc = useQueryClient()
  const auth = useQuery({ queryKey: ['auth'], queryFn: () => api<{ mfa?: boolean }>('/api/auth/state') })
  const ha = useHA()
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [pw, setPw] = useState('')
  const start = useMutation({
    mutationFn: async () => {
      const r = await api<{ secret: string; uri: string }>('/api/auth/mfa/setup', { method: 'POST' })
      const qr = await QRCode.toDataURL(r.uri, { margin: 1, width: 200 })
      return { ...r, qr }
    },
    onSuccess: setSetup,
  })
  const enable = useMutation({
    mutationFn: () => api('/api/auth/mfa/enable', { method: 'POST', body: { code } }),
    onSuccess: () => {
      setSetup(null)
      setCode('')
      qc.invalidateQueries({ queryKey: ['auth'] })
    },
  })
  const disable = useMutation({
    mutationFn: () => api('/api/auth/mfa/disable', { method: 'POST', body: { password: pw, code } }),
    onSuccess: () => {
      setPw('')
      setCode('')
      qc.invalidateQueries({ queryKey: ['auth'] })
    },
  })
  const on = !!auth.data?.mfa
  if (ha.data?.role === 'replica') {
    return (
      <Card title="Verificação em duas etapas" subtitle={on ? 'Ligada (vem do principal)' : 'Desligada'}>
        <p className="text-xs text-ink-2">Nesta réplica o MFA vem do principal.</p>
      </Card>
    )
  }
  return (
    <Card title="Verificação em duas etapas" subtitle={on ? 'Ligada' : 'Desligada — recomendada, e obrigatória para alterar o Active Directory'}>
      {on ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            disable.mutate()
          }}
        >
          <p className="text-xs text-ink-2">
            Para desligar, informe a senha e um código. Perdeu o celular? Rode <code className="font-mono text-ink">sudo heimdalldns mfa-off</code> no servidor.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            <Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Senha" autoComplete="current-password" required />
            <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="Código" inputMode="numeric" required />
          </div>
          <ErrorNote error={disable.error} />
          <Button type="submit" loading={disable.isPending}>
            Desligar
          </Button>
        </form>
      ) : setup ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            enable.mutate()
          }}
        >
          <p className="text-xs text-ink-2">Leia o QR code no aplicativo autenticador (Google Authenticator, Microsoft Authenticator, Aegis…) e digite o código.</p>
          <div className="flex flex-wrap items-center gap-4">
            <img src={setup.qr} alt="QR code do segredo" className="size-40 rounded-lg bg-white p-1" />
            <div className="min-w-0 text-xs">
              <p className="text-muted">Ou digite o segredo:</p>
              <code className="font-mono break-all text-ink">{setup.secret}</code>
            </div>
          </div>
          <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="Código de 6 dígitos" inputMode="numeric" autoComplete="one-time-code" required />
          <ErrorNote error={enable.error} />
          <Button type="submit" variant="primary" loading={enable.isPending}>
            Confirmar e ligar
          </Button>
        </form>
      ) : (
        <>
          <ErrorNote error={start.error} />
          <Button variant="primary" loading={start.isPending} onClick={() => start.mutate()}>
            Ligar verificação em duas etapas
          </Button>
        </>
      )}
    </Card>
  )
}

export function PasswordForm() {
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
