// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Download, Fingerprint, KeyRound, LogOut, Monitor, Plus, Smartphone, Trash } from 'lucide-react'
import { api } from '../api'
import type { PasskeyInfo, SessionInfo } from '../types'
import { ago } from '../lib/format'
import { t } from '../lib/i18n'
import { useAuth, useCan } from '../lib/auth'
import { answer, createPasskey, passkeySupport, type PasskeyChallenge } from '../lib/webauthn'
import { Button, Card, ErrorNote, Input, Segmented, StatusBadge } from '../components/ui'
import { useHA } from '../components/HABanner'

/** Códigos de recuperação recém-gerados: aparecem uma vez só. */
export function RecoveryCodes({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  const text = codes.join('\n')
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-3 rounded-xl border border-warning/40 bg-warning-soft p-4">
      <p className="text-sm font-semibold text-ink">{t('Guarde os códigos de recuperação')}</p>
      <p className="text-xs text-ink-2">
        {t('Cada código entra uma vez no lugar do aplicativo ou da passkey, se você perder o celular. Eles não aparecem de novo: guarde num gerenciador de senhas ou imprima.')}
      </p>
      <ol className="grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm text-ink">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          icon={<Copy className="size-3.5" />}
          onClick={() => navigator.clipboard?.writeText(text).then(() => setCopied(true))}
        >
          {copied ? t('Copiados') : t('Copiar')}
        </Button>
        <Button
          size="sm"
          icon={<Download className="size-3.5" />}
          onClick={() => {
            const a = document.createElement('a')
            a.href = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }))
            a.download = 'heimdalldns-codigos-de-recuperacao.txt'
            a.click()
            URL.revokeObjectURL(a.href)
          }}
        >
          {t('Baixar')}
        </Button>
        <Button size="sm" variant="primary" onClick={onClose}>
          {t('Já guardei')}
        </Button>
      </div>
    </div>
  )
}

/** Quantos códigos sobram, e gerar uma lista nova (pede a segunda etapa). */
export function RecoveryStatus() {
  const qc = useQueryClient()
  const me = useAuth().data?.user
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const regen = useMutation({
    mutationFn: async (withPasskey: boolean) => {
      let body: Record<string, unknown> = { code }
      if (withPasskey) {
        const ch = await api<PasskeyChallenge>('/api/auth/passkeys/verify', { method: 'POST' })
        body = { passkey: await answer(ch) }
      }
      return api<{ recovery_codes: string[] }>('/api/auth/mfa/recovery', { method: 'POST', body })
    },
    onSuccess: (r) => {
      setCodes(r.recovery_codes)
      setCode('')
      qc.invalidateQueries({ queryKey: ['auth'] })
    },
  })
  if (!me || !(me.mfa || me.passkeys > 0)) return null
  if (codes) return <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />
  const left = me.recovery_left
  return (
    <div className="space-y-2 border-t border-line pt-3">
      <p className="flex flex-wrap items-center gap-2 text-xs text-ink-2">
        <KeyRound className="size-3.5 text-accent" aria-hidden />
        {t('Códigos de recuperação:')}
        <StatusBadge tone={left === 0 ? 'critical' : left <= 3 ? 'warning' : 'good'}>{t('{n} restantes', { n: left })}</StatusBadge>
      </p>
      <form
        className="flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          regen.mutate(false)
        }}
      >
        {me.mfa && (
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={t('Código atual')}
            aria-label={t('Código atual')}
            className="w-36"
            autoComplete="one-time-code"
            required
          />
        )}
        {me.mfa && (
          <Button type="submit" size="sm" loading={regen.isPending}>
            {t('Gerar novos códigos')}
          </Button>
        )}
        {!me.mfa && passkeySupport() === 'ok' && (
          <Button size="sm" icon={<Fingerprint className="size-3.5" />} loading={regen.isPending} onClick={() => regen.mutate(true)}>
            {t('Gerar novos códigos (confirmar com a passkey)')}
          </Button>
        )}
      </form>
      <ErrorNote error={regen.error} />
    </div>
  )
}

/** Passkeys da conta: entrar com a digital, o rosto ou a chave de segurança. */
export function PasskeysCard() {
  const qc = useQueryClient()
  const ha = useHA()
  const support = passkeySupport()
  const [name, setName] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const q = useQuery({ queryKey: ['passkeys'], queryFn: () => api<PasskeyInfo[]>('/api/auth/passkeys') })
  const add = useMutation({
    mutationFn: async () => {
      const begin = await api<PasskeyChallenge>('/api/auth/passkeys/begin', { method: 'POST', body: {} })
      const credential = await createPasskey(begin.options)
      return api<{ passkeys: PasskeyInfo[]; recovery_codes?: string[] }>('/api/auth/passkeys/finish', {
        method: 'POST',
        body: { challenge_id: begin.challenge_id, name, credential },
      })
    },
    onSuccess: (r) => {
      qc.setQueryData(['passkeys'], r.passkeys)
      qc.invalidateQueries({ queryKey: ['auth'] })
      setName('')
      if (r.recovery_codes) setCodes(r.recovery_codes)
    },
  })
  const del = useMutation({
    mutationFn: (id: string) => api<PasskeyInfo[]>(`/api/auth/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    onSuccess: (r) => {
      qc.setQueryData(['passkeys'], r)
      qc.invalidateQueries({ queryKey: ['auth'] })
    },
  })
  const list = q.data ?? []
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Fingerprint className="size-4 text-accent" aria-hidden />
          {t('Passkeys')}
        </span>
      }
      subtitle={t('Entre com a digital, o rosto ou uma chave de segurança, sem digitar senha')}
    >
      {codes && (
        <div className="mb-4">
          <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />
        </div>
      )}
      {list.length > 0 && (
        <ul className="mb-4 divide-y divide-line rounded-lg border border-line">
          {list.map((p) => (
            <li key={p.id} className="flex items-center gap-3 px-3 py-2">
              <KeyRound className="size-4 shrink-0 text-accent" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm text-ink">{p.name}</p>
                <p className="text-[11px] text-muted">
                  {t('criada {quando}', { quando: ago(p.created) })}
                  {p.last_used ? ' · ' + t('usada {quando}', { quando: ago(p.last_used) }) : ''}
                </p>
              </div>
              {ha.data?.role !== 'replica' && (
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label={t('Apagar {nome}', { nome: p.name })}
                  icon={<Trash className="size-3.5" />}
                  loading={del.isPending && del.variables === p.id}
                  onClick={() => del.mutate(p.id)}
                />
              )}
            </li>
          ))}
        </ul>
      )}
      {ha.data?.role === 'replica' ? (
        <p className="text-xs text-ink-2">{t('Nesta réplica as passkeys vêm do principal: cadastre por lá.')}</p>
      ) : support === 'ok' ? (
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            add.mutate()
          }}
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('nome (ex.: Notebook, Celular)')}
            aria-label={t('Nome da passkey')}
            className="min-w-0 flex-1"
            maxLength={60}
          />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={add.isPending}>
            {t('Cadastrar passkey')}
          </Button>
        </form>
      ) : (
        <p className="text-xs text-ink-2">
          {support === 'browser'
            ? t('Este navegador não tem suporte a passkeys.')
            : t('Passkeys precisam do painel aberto por um nome com HTTPS (ex.: https://heimdall.empresa.local:8080), não pelo IP. Configure api.tls_cert e um nome no DNS local.')}
        </p>
      )}
      <ErrorNote error={add.error || del.error || q.error} />
      <p className="mt-3 text-[11px] text-muted">
        {t('A passkey vale como segunda etapa depois da senha. Nas contas locais ela também entra sozinha, sem senha; nas do Active Directory a senha do domínio continua sendo pedida.')}
      </p>
    </Card>
  )
}

/** Navegador e sistema a partir do User-Agent, em poucas palavras. */
export function describeUA(ua: string): { label: string; mobile: boolean } {
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /OPR\//.test(ua)
      ? 'Opera'
      : /Firefox\//.test(ua)
        ? 'Firefox'
        : /Chrome\//.test(ua)
          ? 'Chrome'
          : /Safari\//.test(ua)
            ? 'Safari'
            : /curl|Go-http|python/i.test(ua)
              ? ua.split(/[ /]/)[0]
              : ''
  const os = /Android/.test(ua)
    ? 'Android'
    : /iPhone|iPad/.test(ua)
      ? 'iOS'
      : /Windows/.test(ua)
        ? 'Windows'
        : /Mac OS X/.test(ua)
          ? 'macOS'
          : /Linux/.test(ua)
            ? 'Linux'
            : ''
  const label = [browser, os].filter(Boolean).join(' · ') || ua.slice(0, 40) || t('desconhecido')
  return { label, mobile: /Android|iPhone|iPad|Mobile/.test(ua) }
}

const methodLabel = (m: string) =>
  m
    .split('+')
    .map(
      (p) =>
        ({
          senha: t('senha'),
          ad: t('senha do AD'),
          totp: t('app autenticador'),
          passkey: t('passkey'),
          'recuperação': t('código de recuperação'),
        })[p] ?? p,
    )
    .join(' + ')

/** Sessões abertas: onde a conta está logada, e encerrar as que não reconhece. */
export function SessionsCard() {
  const qc = useQueryClient()
  const admin = useCan('admin')
  const [scope, setScope] = useState<'mine' | 'all'>('mine')
  const url = scope === 'all' ? '/api/users/sessions' : '/api/auth/sessions'
  const q = useQuery({ queryKey: ['sessions', scope], queryFn: () => api<SessionInfo[]>(url), refetchInterval: 30_000 })
  const end = useMutation({
    mutationFn: (id: string) => api(`${url}/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  })
  const endOthers = useMutation({
    mutationFn: () => api('/api/auth/sessions', { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  })
  const list = q.data ?? []
  const others = list.filter((s) => !s.current).length
  return (
    <Card
      title={t('Sessões ativas')}
      subtitle={t('Onde a conta está aberta. Não reconhece alguma? Encerre e troque a senha.')}
      actions={
        admin ? (
          <Segmented
            label={t('Sessões de')}
            value={scope}
            onChange={setScope}
            options={[
              { value: 'mine', label: t('Minhas') },
              { value: 'all', label: t('Todas as contas') },
            ]}
          />
        ) : undefined
      }
    >
      <ul className="divide-y divide-line">
        {list.map((s) => {
          const ua = describeUA(s.user_agent)
          const Icon = ua.mobile ? Smartphone : Monitor
          return (
            <li key={s.id} className="flex items-center gap-3 py-2.5">
              <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-line bg-surface-2 text-ink-2">
                <Icon className="size-4" aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2 text-sm text-ink">
                  {scope === 'all' && s.username && <strong>{s.username}</strong>}
                  <span className="truncate">{ua.label}</span>
                  {s.current && <StatusBadge tone="good">{t('esta sessão')}</StatusBadge>}
                </p>
                <p className="text-[11px] text-muted">
                  <span className="font-mono">{s.ip || '—'}</span>
                  {' · '}
                  {s.method ? methodLabel(s.method) : t('entrada antiga')}
                  {' · '}
                  {t('ativa {quando}', { quando: ago(s.last_seen || s.created) })}
                  {' · '}
                  {t('entrou {quando}', { quando: ago(s.created) })}
                </p>
              </div>
              {!s.current && (
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<LogOut className="size-3.5" />}
                  loading={end.isPending && end.variables === s.id}
                  onClick={() => end.mutate(s.id)}
                >
                  {t('Encerrar')}
                </Button>
              )}
            </li>
          )
        })}
      </ul>
      {q.data && list.length === 0 && <p className="py-4 text-center text-sm text-muted">{t('Nenhuma sessão.')}</p>}
      <ErrorNote error={q.error || end.error || endOthers.error} />
      {scope === 'mine' && others > 0 && (
        <Button className="mt-3" size="sm" icon={<LogOut className="size-3.5" />} loading={endOthers.isPending} onClick={() => endOthers.mutate()}>
          {t('Sair de todos os outros lugares')}
        </Button>
      )}
    </Card>
  )
}
