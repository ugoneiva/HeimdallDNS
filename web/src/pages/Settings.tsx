// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

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
import { BackupCard, PiholeImport } from './Maintenance'
import { TokensCard, UsersCard } from './Access'
import { AuditTab } from './ActiveDirectory'
import { roleLabel, useAuth, useCan } from '../lib/auth'
import { LangPicker } from '../components/LangPicker'
import { AboutLine } from '../components/About'
import { PasskeysCard, RecoveryCodes, RecoveryStatus, SessionsCard } from './Account'
import { t } from '../lib/i18n'

export function Settings({ onLogout }: { onLogout: () => void }) {
  const { choice } = useTheme()
  const admin = useCan('admin')
  const me = useAuth().data?.user
  const status = useQuery({ queryKey: ['status'], queryFn: () => api<Status>('/api/status'), refetchInterval: 5000 })
  const s = status.data
  const hit = s && s.cache.hits + s.cache.misses ? (s.cache.hits / (s.cache.hits + s.cache.misses)) * 100 : 0

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

      <Card title={t('Sobre este servidor')}>
        {s ? (
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs">
            {(
              [
                [t('Versão'), s.version],
                [t('Ligado há'), uptime(s.uptime_s)],
                [t('Consultas desde que ligou'), fmtInt(s.queries.total)],
                [t('Regras de bloqueio'), fmtInt(s.rules.block)],
                [t('Respostas no cache'), fmtInt(s.cache.entries)],
                [t('Acerto do cache'), fmtPct(hit)],
                [t('Dispositivos conhecidos'), fmtInt(s.clients)],
                [t('Histórico descartado'), s.history ? fmtInt(s.history.dropped_rows) + ' linhas' : '—'],
              ] as const
            ).map(([k, v]) => (
              <div key={k}>
                <dt className="text-muted">{k}</dt>
                <dd className="mt-0.5 font-medium text-ink">{v}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="text-xs text-muted">{t('Carregando…')}</p>
        )}
              {s && <AboutLine version={s.version} className="mt-4 text-[11px] text-muted" />}
      </Card>

      {admin && (
        <>
          <UsersCard />

          <TokensCard />

          <HACard />

          <DHCPCard />

          <BackupCard />

          <Card title={t('Migrar do Pi-hole')} subtitle={t('Listas, regras, registros locais, reservas de DHCP e nomes dos aparelhos')}>
            <PiholeImport />
          </Card>

          <div className="lg:col-span-2">
            <AuditTab />
          </div>
        </>
      )}

      {me?.source === 'ad' ? (
        <Card title={t('Senha')} subtitle={t('Conta do Active Directory')}>
          <p className="text-xs text-ink-2">{t('A senha é a do AD: troque pelo Windows (Ctrl+Alt+Del) ou pela política da empresa.')}</p>
        </Card>
      ) : (
        <PasswordCard />
      )}

      <MFACard />

      <PasskeysCard />

      <SessionsCard />

      <Card title={t('Sessão')}>
        {me && (
          <p className="mb-2 text-xs text-ink-2">
            {t('Conectado como')}{' '}<strong className="text-ink">{me.display || me.username}</strong> ({roleLabel[me.role]}
            {me.source === 'ad' ? t(', conta do AD') : ''}).
          </p>
        )}
        <p className="mb-4 text-xs text-ink-2">
          {t('A sessão dura 7 dias. Se perder a senha, rode')}{' '}<code className="font-mono text-ink">sudo heimdalldns passwd</code>{' '}{t('no servidor.')}
        </p>
        <Button icon={<LogOut className="size-4" />} onClick={onLogout}>
          {t('Sair')}
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
      <Card title={t('Alta disponibilidade')} subtitle={t('Nó único')}>
        <p className="mb-3 text-xs leading-relaxed text-ink-2">
          {t('Com um segundo HeimdallDNS como réplica, a rede continua com DNS se um dos dois cair. Entregue os dois como servidores DNS (no DHCP ou no roteador). Listas, regras, segurança, dispositivos e a senha vão do principal para a réplica em cerca de 1 segundo.')}
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
      <Card title={t('Alta disponibilidade')} subtitle={t('Este nó é uma réplica')}>
        <dl className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <dt className="text-muted">{t('Principal')}</dt>
            <dd className="mt-0.5 font-mono text-ink">{r?.primary_url}</dd>
          </div>
          <div>
            <dt className="text-muted">{t('Última sincronização')}</dt>
            <dd className="mt-0.5 text-ink">{ago(r?.last_sync)}</dd>
          </div>
          {r?.error && (
            <div className="col-span-2">
              <dt className="text-muted">{t('Erro')}</dt>
              <dd className="mt-0.5 break-all text-critical-ink">{r.error}</dd>
            </div>
          )}
        </dl>
      </Card>
    )
  }
  const reps = data.replicas ?? []
  return (
    <Card title={t('Alta disponibilidade')} subtitle={t('Este nó é o principal')}>
      {reps.length === 0 ? (
        <p className="text-xs text-muted">{t('Nenhuma réplica conectada na última hora.')}</p>
      ) : (
        <ul className="space-y-2 text-xs">
          {reps.map((r) => (
            <li key={r.addr} className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-ink">{r.addr}</span>
              <span className="text-ink-2">{t('visto')}{' '}{ago(r.last_seen)}</span>
              {r.version === data.version ? <StatusBadge tone="good">{t('Em dia')}</StatusBadge> : <StatusBadge tone="warning">{t('Atualizando')}</StatusBadge>}
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
    <Card title={t('DHCP')} subtitle={t('Desligado')}>
      <p className="mb-3 text-xs leading-relaxed text-ink-2">
        {t('Com o DHCP do HeimdallDNS, cada aparelho recebe este servidor como DNS automaticamente, o radar aprende nome e MAC direto da concessão, e os nomes resolvem como')}{' '}<code className="font-mono text-ink">notebook-da-ana.lan</code>{t('. Desligue o DHCP do roteador antes: dois servidores DHCP na mesma rede brigam.')}
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
      <Card title={t('Trocar a senha')} subtitle={t('Feito no principal')}>
        <p className="text-xs text-ink-2">{t('Nesta réplica a senha vem do principal: troque por lá e ela chega aqui em cerca de 1 segundo.')}</p>
      </Card>
    )
  }
  return <PasswordForm />
}

export function MFACard() {
  const qc = useQueryClient()
  const auth = useAuth()
  const ha = useHA()
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [pw, setPw] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const start = useMutation({
    mutationFn: async () => {
      const r = await api<{ secret: string; uri: string }>('/api/auth/mfa/setup', { method: 'POST' })
      const qr = await QRCode.toDataURL(r.uri, { margin: 1, width: 200 })
      return { ...r, qr }
    },
    onSuccess: setSetup,
  })
  const enable = useMutation({
    mutationFn: () => api<{ recovery_codes?: string[] }>('/api/auth/mfa/enable', { method: 'POST', body: { code } }),
    onSuccess: (r) => {
      setSetup(null)
      setCode('')
      if (r.recovery_codes) setCodes(r.recovery_codes)
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
  const me = auth.data?.user
  const on = !!me?.mfa
  const ad = me?.source === 'ad'
  if (ha.data?.role === 'replica') {
    return (
      <Card title={t('Verificação em duas etapas')} subtitle={on ? t('Ligada (vem do principal)') : t('Desligada')}>
        <p className="text-xs text-ink-2">{t('Nesta réplica o MFA vem do principal.')}</p>
      </Card>
    )
  }
  return (
    <Card title={t('Verificação em duas etapas')} subtitle={on ? t('Ligada') : t('Desligada — recomendada, e obrigatória para alterar o Active Directory')}>
      {codes ? (
        <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />
      ) : on ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            disable.mutate()
          }}
        >
          <p className="text-xs text-ink-2">
            {ad
              ? t('Contas do Active Directory mantêm a verificação ligada. Trocou de celular? Peça a um administrador para zerar o MFA e cadastre de novo.')
              : <>{t('Para desligar, informe a senha e um código. Perdeu o celular? Um administrador zera o MFA em Usuários, ou rode')}{' '}<code className="font-mono text-ink">sudo heimdalldns mfa-off -user {me?.username}</code>{' '}{t('no servidor.')}</>}
          </p>
          <div className={ad ? 'hidden' : 'grid gap-3 sm:grid-cols-2'}>
            <Input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder={t('Senha')} autoComplete="current-password" required={!ad} />
            <Input value={code} onChange={(e) => setCode(e.target.value.slice(0, 12))} placeholder={t('Código do app ou de recuperação')} autoComplete="one-time-code" required />
          </div>
          <ErrorNote error={disable.error} />
          {!ad && (
            <Button type="submit" loading={disable.isPending}>
              {t('Desligar')}
            </Button>
          )}
        </form>
      ) : setup ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            enable.mutate()
          }}
        >
          <p className="text-xs text-ink-2">{t('Leia o QR code no aplicativo autenticador (Google Authenticator, Microsoft Authenticator, Aegis…) e digite o código.')}</p>
          <div className="flex flex-wrap items-center gap-4">
            <img src={setup.qr} alt={t('QR code do segredo')} className="size-40 rounded-lg bg-white p-1" />
            <div className="min-w-0 text-xs">
              <p className="text-muted">{t('Ou digite o segredo:')}</p>
              <code className="font-mono break-all text-ink">{setup.secret}</code>
            </div>
          </div>
          <Input value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} placeholder={t('Código de 6 dígitos')} inputMode="numeric" autoComplete="one-time-code" required />
          <ErrorNote error={enable.error} />
          <Button type="submit" variant="primary" loading={enable.isPending}>
            {t('Confirmar e ligar')}
          </Button>
        </form>
      ) : (
        <>
          <ErrorNote error={start.error} />
          <Button variant="primary" loading={start.isPending} onClick={() => start.mutate()}>
            {t('Ligar verificação em duas etapas')}
          </Button>
        </>
      )}
      {!codes && !setup && (
        <div className="mt-4">
          <RecoveryStatus />
        </div>
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
      if (pw !== pw2) throw new Error(t('As senhas novas não conferem.'))
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
    <Card title={t('Trocar a senha')} subtitle={t('Encerra as outras sessões abertas')}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          setOk(false)
          change.mutate()
        }}
      >
        <Field label={t('Senha atual')}>
          <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Nova senha')} hint={t('Pelo menos 8 caracteres.')}>
            <Input type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} minLength={8} required />
          </Field>
          <Field label={t('Repita a nova senha')}>
            <Input type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} minLength={8} required />
          </Field>
        </div>
        <ErrorNote error={change.error} />
        {ok && <p className="text-xs text-good-ink">{t('Senha alterada.')}</p>}
        <Button type="submit" variant="primary" loading={change.isPending}>
          {t('Trocar senha')}
        </Button>
      </form>
    </Card>
  )
}
