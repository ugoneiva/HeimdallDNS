// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, FileKey2, Globe, LockKeyhole, Power, RefreshCw, RotateCcw, ShieldCheck, TriangleAlert } from 'lucide-react'
import { api } from '../api'
import { ago } from '../lib/format'
import { t } from '../lib/i18n'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, Segmented, StatusBadge, cx } from '../components/ui'

type CertSettings = {
  enabled: boolean
  domains: string[]
  email: string
  challenge: 'http-01' | 'dns-01-cloudflare'
  cloudflare_token?: string
  auto_renew: boolean
  staging: boolean
  use_panel: boolean
  use_dns: boolean
}
type CertStatus = {
  state: 'none' | 'issuing' | 'active' | 'error'
  domains?: string[]
  issuer?: string
  not_before?: string
  not_after?: string
  staging?: boolean
  last_attempt?: string
  last_error?: string
  next_renewal?: string
  log: string[]
  cert_file?: string
  key_file?: string
}
type CertState = { settings: CertSettings; status: CertStatus; running: boolean; panel_https: boolean; dns_tls: boolean }

const day = 86_400_000
const fmtDate = (s?: string) => (s ? new Date(s).toLocaleDateString() : '—')

export function Certificate() {
  const qc = useQueryClient()
  const q = useQuery({
    queryKey: ['certs'],
    queryFn: () => api<CertState>('/api/certs'),
    refetchInterval: (query) => (query.state.data?.running ? 1500 : 30_000),
  })
  const [s, setS] = useState<CertSettings | null>(null)
  const [domains, setDomains] = useState('')
  useEffect(() => {
    if (q.data && !s) {
      setS(q.data.settings)
      setDomains(q.data.settings.domains.join(', '))
    }
  }, [q.data, s])
  const body = () => s && { ...s, domains: domains.split(/[\s,;]+/).filter(Boolean) }
  const onData = (d: CertState) => qc.setQueryData(['certs'], d)
  const save = useMutation({ mutationFn: () => api<CertState>('/api/certs', { method: 'PUT', body: body() }), onSuccess: onData })
  const issue = useMutation({ mutationFn: () => api<CertState>('/api/certs/issue', { method: 'POST', body: body() }), onSuccess: onData })
  const disable = useMutation({
    mutationFn: () => api<CertState>('/api/certs/disable', { method: 'POST' }),
    onSuccess: (d) => {
      onData(d)
      setS(d.settings)
    },
  })
  const restart = useMutation({ mutationFn: () => api('/api/restart', { method: 'POST' }) })

  const d = q.data
  const st = d?.status
  const set = (p: Partial<CertSettings>) => setS((x) => (x ? { ...x, ...p } : x))
  const left = st?.not_after ? Math.floor((new Date(st.not_after).getTime() - Date.now()) / day) : null
  const total = st?.not_after && st.not_before ? (new Date(st.not_after).getTime() - new Date(st.not_before).getTime()) / day : 90
  const active = st?.state === 'active' || (st?.state !== 'issuing' && !!st?.not_after)
  const using = d?.settings.enabled && !!st?.not_after
  const panelNeedsRestart = using && d?.settings.use_panel && !d.panel_https
  const firstDomain = d?.settings.domains[0]

  return (
    <div className="space-y-5">
      <ErrorNote error={q.error} />
      <div className="grid gap-5 lg:grid-cols-[1.1fr_1fr]">
        <Card
          title={
            <span className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-accent" aria-hidden />
              {t('Certificado em uso')}
            </span>
          }
          subtitle={t('Emitido pelo Let\'s Encrypt, instalado e renovado por aqui')}
        >
          {!st ? null : !active && st.state !== 'issuing' ? (
            <div className="flex items-center gap-4 py-2">
              <span className="grid size-14 shrink-0 place-items-center rounded-2xl border border-line bg-surface-2 text-muted">
                <LockKeyhole className="size-7" aria-hidden />
              </span>
              <p className="text-sm text-ink-2">
                {t('Nenhum certificado emitido ainda. Preencha o domínio ao lado e clique em "Emitir e ativar".')}
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                {st.state === 'issuing' && <StatusBadge tone="accent">{t('emitindo…')}</StatusBadge>}
                {st.state === 'error' && <StatusBadge tone="critical">{t('última tentativa falhou')}</StatusBadge>}
                {using ? <StatusBadge tone="good">{t('em uso')}</StatusBadge> : st.not_after && <StatusBadge tone="neutral">{t('desativado')}</StatusBadge>}
                {st.staging && <StatusBadge tone="warning">{t('teste (staging): navegadores não confiam')}</StatusBadge>}
              </div>
              {st.domains && st.domains.length > 0 && (
                <ul className="flex flex-wrap gap-1.5">
                  {st.domains.map((n) => (
                    <li key={n} className="flex items-center gap-1.5 rounded-lg border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-ink">
                      <Globe className="size-3.5 text-accent" aria-hidden />
                      {n}
                    </li>
                  ))}
                </ul>
              )}
              {left !== null && (
                <div>
                  <div className="mb-1 flex justify-between text-xs">
                    <span className="text-ink-2">
                      {t('Válido de {de} até {ate}', { de: fmtDate(st.not_before), ate: fmtDate(st.not_after) })}
                    </span>
                    <span className={cx('font-semibold', left < 14 ? 'text-critical-ink' : left < 30 ? 'text-warning' : 'text-good')}>
                      {t('{n} dias', { n: left })}
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-surface-2" role="meter" aria-valuenow={left} aria-valuemin={0} aria-valuemax={total} aria-label={t('Dias restantes')}>
                    <div
                      className={cx('h-full rounded-full', left < 14 ? 'bg-critical' : left < 30 ? 'bg-warning' : 'bg-good')}
                      style={{ width: `${Math.max(2, Math.min(100, (left / total) * 100))}%` }}
                    />
                  </div>
                </div>
              )}
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
                <div>
                  <dt className="text-muted">{t('Emissor')}</dt>
                  <dd className="text-ink">{st.issuer || '—'}</dd>
                </div>
                <div>
                  <dt className="text-muted">{t('Renovação automática')}</dt>
                  <dd className="flex items-center gap-1.5 text-ink">
                    <CalendarClock className="size-3.5 text-accent" aria-hidden />
                    {d?.settings.auto_renew && st.next_renewal ? t('a partir de {quando}', { quando: fmtDate(st.next_renewal) }) : t('desligada')}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-muted">{t('Arquivos')}</dt>
                  <dd className="flex items-start gap-1.5 font-mono text-[11px] break-all text-ink-2">
                    <FileKey2 className="mt-0.5 size-3.5 shrink-0 text-accent" aria-hidden />
                    <span>
                      {st.cert_file}
                      <br />
                      {st.key_file} <span className="font-sans text-muted">({t('somente o serviço lê')})</span>
                    </span>
                  </dd>
                </div>
              </dl>
            </div>
          )}

          {panelNeedsRestart && (
            <div className="mt-4 flex flex-wrap items-center gap-3 rounded-xl border border-warning/40 bg-warning-soft p-3 text-xs text-ink">
              <TriangleAlert className="size-4 shrink-0 text-warning" aria-hidden />
              <span className="min-w-0 flex-1">
                {t('O painel ainda está em HTTP. Reinicie o serviço para abrir a porta já com HTTPS; depois acesse por https://{dominio}.', { dominio: firstDomain ?? '' })}
              </span>
              <Button size="sm" icon={<RotateCcw className="size-3.5" />} loading={restart.isPending} onClick={() => restart.mutate()}>
                {t('Reiniciar o serviço')}
              </Button>
            </div>
          )}
          {restart.isSuccess && <p className="mt-2 text-xs text-good">{t('Reiniciando… abra o painel pelo endereço HTTPS em alguns segundos.')}</p>}
          {using && d?.settings.use_dns && !d.dns_tls && (
            <p className="mt-3 text-[11px] text-muted">
              {t('O certificado também está pronto para o DNS criptografado, mas DoT/DoH não estão ligados no arquivo de configuração (dns.dot_listen e dns.doh_listen).')}
            </p>
          )}

          {st && st.log.length > 0 && (
            <div className="mt-4">
              <p className="mb-1 text-xs font-medium text-ink-2">
                {t('Última emissão')} {st.last_attempt ? '· ' + ago(st.last_attempt) : ''}
              </p>
              <pre className="max-h-48 overflow-auto rounded-lg border border-line bg-surface-2 p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap text-ink-2">
                {st.log.join('\n')}
              </pre>
            </div>
          )}
          {st?.last_error && <p className="mt-2 text-xs break-words text-critical-ink">{st.last_error}</p>}
        </Card>

        {s && (
          <Card title={t('Emitir certificado')} subtitle={t('Para instalações oficiais, com um domínio público')}>
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault()
                issue.mutate()
              }}
            >
              <Field label={t('Domínios')} hint={t('O primeiro é o principal; separe por vírgula. Ex.: heimdall.empresa.com.br, dns.empresa.com.br')}>
                <Input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="heimdall.empresa.com.br" required />
              </Field>
              <Field label={t('E-mail (opcional)')} hint={t('O Let\'s Encrypt avisa nele se algo der errado com o certificado.')}>
                <Input type="email" value={s.email} onChange={(e) => set({ email: e.target.value })} placeholder="ti@empresa.com.br" />
              </Field>
              <div className="space-y-2">
                <p className="text-xs font-medium text-ink-2">{t('Como provar que o domínio é seu')}</p>
                <Segmented
                  label={t('Validação')}
                  value={s.challenge}
                  onChange={(v) => set({ challenge: v })}
                  options={[
                    { value: 'http-01', label: t('HTTP (porta 80)') },
                    { value: 'dns-01-cloudflare', label: t('DNS (Cloudflare)') },
                  ]}
                />
                {s.challenge === 'http-01' ? (
                  <ul className="list-disc space-y-1 pl-5 text-[11px] text-ink-2">
                    <li>{t('O domínio precisa apontar (registro A) para o IP público deste servidor.')}</li>
                    <li>{t('A porta 80 precisa chegar da internet até aqui (firewall e redirecionamento no roteador). Ela só fica aberta durante a emissão.')}</li>
                  </ul>
                ) : (
                  <>
                    <Field label={t('Token da API da Cloudflare')} hint={t('Crie em My Profile → API Tokens com a permissão Zone → DNS → Edit, só para a zona do domínio. Serve para servidores sem porta aberta para a internet e para curinga (*.empresa.com.br).')}>
                      <Input
                        value={s.cloudflare_token ?? ''}
                        onChange={(e) => set({ cloudflare_token: e.target.value })}
                        autoComplete="off"
                        required
                      />
                    </Field>
                  </>
                )}
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                <LabeledSwitch checked={s.use_panel} onChange={(v) => set({ use_panel: v })} label={t('Usar no painel (HTTPS)')} />
                <LabeledSwitch checked={s.use_dns} onChange={(v) => set({ use_dns: v })} label={t('Usar no DoT/DoH')} />
                <LabeledSwitch checked={s.auto_renew} onChange={(v) => set({ auto_renew: v })} label={t('Renovar automaticamente')} />
                <LabeledSwitch checked={s.staging} onChange={(v) => set({ staging: v })} label={t('Ambiente de teste (staging)')} />
              </div>
              <p className="text-[11px] text-muted">
                {s.auto_renew
                  ? t('A renovação roda dentro do próprio serviço: quando falta um terço da validade (30 dias nos certificados de 90), ele emite de novo e troca o certificado sem derrubar ninguém. Falhas viram notificação.')
                  : t('Sem renovação automática, o certificado vence sozinho (90 dias no Let\'s Encrypt). O HeimdallDNS avisa pelas notificações quando faltar um terço da validade; renove por esta tela.')}
                {s.staging ? ' ' + t('No staging o certificado não é confiável: use só para conferir a configuração sem gastar o limite de emissões.') : ''}
              </p>
              <ErrorNote error={issue.error || save.error || disable.error || restart.error} />
              <div className="flex flex-wrap gap-2">
                <Button type="submit" variant="primary" icon={active ? <RefreshCw className="size-4" /> : <ShieldCheck className="size-4" />} loading={issue.isPending || d?.running}>
                  {d?.running ? t('Emitindo…') : active ? t('Salvar e renovar agora') : t('Emitir e ativar')}
                </Button>
                <Button loading={save.isPending} onClick={() => save.mutate()}>
                  {t('Só salvar')}
                </Button>
                {d?.settings.enabled && (
                  <Button variant="ghost" icon={<Power className="size-4" />} loading={disable.isPending} onClick={() => disable.mutate()}>
                    {t('Desativar')}
                  </Button>
                )}
              </div>
            </form>
          </Card>
        )}
      </div>
    </div>
  )
}
