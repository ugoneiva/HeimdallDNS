import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'
import { api, ApiError } from '../api'
import { Button, ErrorNote, Field, Input } from '../components/ui'
import { Logo } from '../components/Logo'
import { LangPicker } from '../components/LangPicker'
import { t } from '../lib/i18n'

export function Login({ setup, adLogin, onDone }: { setup: boolean; adLogin?: boolean; onDone: () => void }) {
  const [code, setCode] = useState('')
  const [user, setUser] = useState(setup ? 'admin' : '')
  const [otp, setOtp] = useState('')
  const [askOtp, setAskOtp] = useState(false)
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
      // Senha certa e conta com MFA: o servidor pede o código.
      if (e instanceof ApiError && e.data?.mfa_required) setAskOtp(true)
    },
  })
  const needsOtpNow = m.error instanceof ApiError && m.error.data?.mfa_required && !otp

  return (
    <div className="relative grid min-h-full place-items-center px-4 py-10">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Logo className="size-12" />
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
          {!setup && askOtp && (
            <Field label={t('Código do aplicativo autenticador')}>
              <Input
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="000000"
                className="font-mono tracking-widest"
                required
                autoFocus
              />
            </Field>
          )}
          {setup && (
            <Field label={t('Repita a senha')}>
              <Input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" minLength={8} required />
            </Field>
          )}
          {!needsOtpNow && <ErrorNote error={m.error} />}
          <Button type="submit" variant="primary" className="w-full" loading={m.isPending} icon={<KeyRound className="size-4" />}>
            {setup ? t('Criar e entrar') : t('Entrar')}
          </Button>
        </form>
        <div className="mt-4 flex justify-center">
          <LangPicker />
        </div>
      </div>
    </div>
  )
}
