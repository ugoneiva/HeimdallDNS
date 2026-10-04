import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'
import { api } from '../api'
import { Button, ErrorNote, Field, Input } from '../components/ui'
import { Logo } from '../components/Logo'

export function Login({ setup, onDone }: { setup: boolean; onDone: () => void }) {
  const [code, setCode] = useState('')
  const [pw, setPw] = useState('')
  const [pw2, setPw2] = useState('')
  const m = useMutation({
    mutationFn: () => {
      if (setup) {
        if (pw !== pw2) throw new Error('As senhas não conferem.')
        return api('/api/auth/setup', { method: 'POST', body: { code, password: pw } })
      }
      return api('/api/auth/login', { method: 'POST', body: { password: pw } })
    },
    onSuccess: onDone,
  })

  return (
    <div className="relative grid min-h-full place-items-center px-4 py-10">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <Logo className="size-12" />
          <div>
            <h1 className="text-xl font-semibold text-ink">HeimdallDNS</h1>
            <p className="mt-1 text-sm text-ink-2">{setup ? 'Primeiro acesso: defina a senha do painel' : 'Entre para continuar'}</p>
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
              label="Código de configuração"
              hint={
                <>
                  Está no log do serviço: <code className="font-mono">journalctl -u heimdalldns | grep codigo</code>
                </>
              }
            >
              <Input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="XXXX-XXXX"
                autoComplete="one-time-code"
                className="font-mono tracking-widest uppercase"
                required
                autoFocus
              />
            </Field>
          )}
          <Field label={setup ? 'Nova senha' : 'Senha'} hint={setup ? 'Pelo menos 8 caracteres.' : undefined}>
            <Input
              type="password"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              autoComplete={setup ? 'new-password' : 'current-password'}
              minLength={setup ? 8 : undefined}
              required
              autoFocus={!setup}
            />
          </Field>
          {setup && (
            <Field label="Repita a senha">
              <Input type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" minLength={8} required />
            </Field>
          )}
          <ErrorNote error={m.error} />
          <Button type="submit" variant="primary" className="w-full" loading={m.isPending} icon={<KeyRound className="size-4" />}>
            {setup ? 'Definir senha e entrar' : 'Entrar'}
          </Button>
        </form>
      </div>
    </div>
  )
}
