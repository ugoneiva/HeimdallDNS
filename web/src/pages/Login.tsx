// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Fingerprint, KeyRound } from 'lucide-react'
import { api, ApiError } from '../api'
import { Button, ErrorNote, Field, Input } from '../components/ui'
import { Logo } from '../components/Logo'
import { LangPicker } from '../components/LangPicker'
import { GuardianScene, RuneBand } from '../components/art'
import { t } from '../lib/i18n'
import { answer, passkeySupport, type PasskeyChallenge } from '../lib/webauthn'

export function Login({ setup, adLogin, onDone }: { setup: boolean; adLogin?: boolean; onDone: () => void }) {
  const [code, setCode] = useState('')
  const [user, setUser] = useState(setup ? 'admin' : '')
  const [otp, setOtp] = useState('')
  const [askOtp, setAskOtp] = useState(false)
  // Segunda etapa pedida pelo servidor: métodos aceitos e o desafio da passkey.
  const [second, setSecond] = useState<{ methods: string[]; passkey?: PasskeyChallenge; recovery: boolean } | null>(null)
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const m = useMutation({
    mutationFn: () => {
      if (setup) {
        if (pw !== pw2) throw new Error(t('As senhas não conferem.'))
        return api('/api/auth/setup', { method: 'POST', body: { code, username: user, password: pw } })
      }
      return api('/api/auth/login', { method: 'POST', body: { username: user, password: pw, code: otp } })
    },
    onSuccess: onDone,
    onError: (e) => {
      // Senha certa e conta com MFA: o servidor pede a segunda etapa.
      if (e instanceof ApiError && e.data?.mfa_required) {
        setAskOtp(true)
        setSecond({
          methods: (e.data.methods as string[]) ?? ['totp'],
          passkey: e.data.passkey as PasskeyChallenge | undefined,
          recovery: !!e.data.recovery,
        })
      }
    },
  })
  // Segunda etapa com a passkey (depois da senha certa).
  const withKey = useMutation({
    mutationFn: async () => {
      if (!second?.passkey) throw new Error(t('Peça o desafio de novo.'))
      return api('/api/auth/login', { method: 'POST', body: { username: user, password: pw, passkey: await answer(second.passkey) } })
    },
    onSuccess: onDone,
    onError: () => m.mutate(), // desafio gasto: pede um novo
  })
  // Entrar só com a passkey (contas locais).
  const passwordless = useMutation({
    mutationFn: async () => {
      const ch = await api<PasskeyChallenge>('/api/auth/passkey/begin', { method: 'POST' })
      return api('/api/auth/passkey/login', { method: 'POST', body: await answer(ch) })
    },
    onSuccess: onDone,
  })
  const needsOtpNow = m.error instanceof ApiError && m.error.data?.mfa_required && !otp
  const totp = !second || second.methods.includes('totp')

  return (
    <div className="relative grid min-h-full place-items-center px-4 py-10">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative w-full max-w-sm">
        <GuardianScene className="mb-5 w-full rounded-2xl shadow-2xl ring-1 ring-white/5" />
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Logo className="size-14" />
          <div>
            <h1 className="text-xl font-semibold text-ink">{t('HeimdallDNS')}</h1>
            <p className="mt-1 text-sm text-ink-2">{setup ? t('Primeiro acesso: crie a conta de administrador') : t('Entre para continuar')}</p>
          </div>
        </div>
        <form
          className="space-y-4 rounded-xl border border-line bg-surface p-5 shadow-2xl"
          onSubmit={(e) => {
            e.preventDefault()
            m.mutate()
          }}
        >
          {setup && (
            <Field
              label={t('Código de configuração')}
              hint={
                <>
                  {t('Está no log do serviço:')}{' '}<code className="font-mono">journalctl -u heimdalldns | grep codigo</code>
                </>
              }
            >
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={t('XXXX-XXXX')}
                autoComplete="one-time-code"
                className="font-mono tracking-widest uppercase"
                required
                autoFocus
              />
            </Field>
          )}
          <Field label={t('Usuário')} hint={!setup && adLogin ? t('Contas do Active Directory também entram (usuario ou usuario@dominio).') : undefined}>
            <Input value={user} onChange={(e) => setUser(e.target.value)} autoComplete="username" autoCapitalize="none" spellCheck={false} required autoFocus={!setup} />
          </Field>
          <Field label={setup ? t('Senha') : t('Senha')} hint={setup ? t('Pelo menos 8 caracteres.') : undefined}>
            <Input
              type="password"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              autoComplete={setup ? 'new-password' : 'current-password'}
              minLength={setup ? 8 : undefined}
              required
            />
          </Field>
          {!setup && askOtp && second?.passkey && (
            <Button
              variant="primary"
              className="w-full"
              loading={withKey.isPending}
              icon={<Fingerprint className="size-4" />}
              onClick={() => withKey.mutate()}
            >
              {t('Confirmar com a passkey')}
            </Button>
          )}
          {!setup && askOtp && (totp || second?.recovery) && (
            <Field
              label={totp ? t('Código do aplicativo autenticador') : t('Código de recuperação')}
              hint={second?.recovery ? t('Sem o celular? Use um código de recuperação.') : undefined}
            >
              <Input
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\s/g, '').slice(0, 12))}
                autoComplete="one-time-code"
                placeholder={totp ? '000000' : 'xxxxx-xxxxx'}
                className="font-mono tracking-widest"
                required={!second?.passkey}
                autoFocus={!second?.passkey}
              />
            </Field>
          )}
          {setup && (
            <Field label={t('Repita a senha')}>
              <Input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" minLength={8} required />
            </Field>
          )}
          {!needsOtpNow && <ErrorNote error={m.error} />}
          <ErrorNote error={withKey.error} />
          <Button type="submit" variant="primary" className="w-full" loading={m.isPending} icon={<KeyRound className="size-4" />}>
            {setup ? t('Criar e entrar') : t('Entrar')}
          </Button>
        </form>
        {!setup && !askOtp && passkeySupport() === 'ok' && (
          <div className="mt-3 space-y-2">
            <Button className="w-full" loading={passwordless.isPending} icon={<Fingerprint className="size-4" />} onClick={() => passwordless.mutate()}>
              {t('Entrar com passkey')}
            </Button>
            <ErrorNote error={passwordless.error} />
          </div>
        )}
        <div className="mt-4 flex justify-center">
          <LangPicker />
        </div>
        <RuneBand text="HEIMDALL · BIFROST · GALLARHORN" className="mx-auto mt-5 h-3 w-72 text-accent opacity-30" />
      </div>
    </div>
  )
}
