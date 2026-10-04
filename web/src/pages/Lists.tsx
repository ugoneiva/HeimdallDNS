// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FlaskConical, Plus, RefreshCw, Trash } from 'lucide-react'
import { api, qs } from '../api'
import type { DomainTest, ListStatus, Rules } from '../types'
import { ago, fmtInt } from '../lib/format'
import { Button, Card, ErrorNote, Field, Input, Select, StatusBadge, Switch, Textarea } from '../components/ui'
import { useDevices } from './Devices'
import { t } from '../lib/i18n'

// Listas conhecidas, para adicionar com um clique.
export const listSuggestions = [
  { name: 'StevenBlack Unified', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', note: t('Anúncios e malware (formato hosts)') },
  { name: 'HaGeZi Pro', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt', note: t('Anúncios, rastreadores e telemetria') },
  {
    name: 'HaGeZi Threat Intelligence',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt',
    note: t('Malware, phishing, C2 e golpes (gera alertas)'),
    category: 'threat' as const,
  },
]

const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

export function Lists() {
  return (
    <div className="space-y-5">
      <ListsCard />
      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <RulesCard />
        <TestCard />
      </div>
    </div>
  )
}

function ListsCard() {
  const qc = useQueryClient()
  const lists = useQuery({
    queryKey: ['lists'],
    queryFn: () => api<ListStatus[]>('/api/lists'),
    refetchInterval: (q) => (q.state.data?.some((l) => l.enabled && !l.updated_at && !l.error) ? 2000 : 15_000),
    // Enquanto uma lista baixa, acompanha mesmo com a aba em segundo plano.
    refetchIntervalInBackground: true,
  })
  const set = (data: ListStatus[]) => qc.setQueryData(['lists'], data)
  const add = useMutation({
    mutationFn: (b: { name: string; url: string; category?: string }) => api<ListStatus[]>('/api/lists', { method: 'POST', body: b }),
    onSuccess: set,
  })
  const patch = useMutation({
    mutationFn: ({ id, ...body }: { id: number; enabled?: boolean; category?: string }) =>
      api<ListStatus[]>(`/api/lists/${id}`, { method: 'PATCH', body }),
    onSuccess: set,
  })
  const del = useMutation({ mutationFn: (id: number) => api<ListStatus[]>(`/api/lists/${id}`, { method: 'DELETE' }), onSuccess: set })
  const refresh = useMutation({
    mutationFn: () => api('/api/lists/refresh', { method: 'POST' }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['lists'] }), 3000),
  })
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [confirmDel, setConfirmDel] = useState<number | null>(null)

  const data = lists.data ?? []
  const total = data.reduce((s, l) => s + (l.enabled ? l.rules : 0), 0)
  const have = new Set(data.map((l) => l.url))

  return (
    <Card
      title={t('Listas de bloqueio')}
      subtitle={t('{n} regras ativas · baixadas de novo automaticamente', { n: fmtInt(total) })}
      actions={
        <Button size="sm" icon={<RefreshCw className="size-3.5" />} loading={refresh.isPending} onClick={() => refresh.mutate()}>
          {t('Atualizar agora')}
        </Button>
      }
      pad={false}
    >
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] text-sm">
          <thead className="text-left text-xs text-muted">
            <tr className="border-y border-line">
              <th className="px-4 py-2.5 font-medium">{t('Lista')}</th>
              <th className="px-3 py-2.5 font-medium">{t('Tipo')}</th>
              <th className="px-3 py-2.5 text-right font-medium">{t('Regras')}</th>
              <th className="px-3 py-2.5 font-medium">{t('Atualizada')}</th>
              <th className="px-3 py-2.5 font-medium">{t('Situação')}</th>
              <th className="px-3 py-2.5 font-medium">{t('Ativa')}</th>
              <th className="w-24 px-3 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {data.map((l) => (
              <tr key={`${l.fixed}-${l.id}-${l.url}`} className="border-b border-line last:border-0">
                <td className="max-w-md px-4 py-2.5">
                  <span className="block font-medium text-ink">{l.name}</span>
                  <span className="block truncate font-mono text-[11px] text-muted" title={l.url}>
                    {l.url}
                  </span>
                </td>
                <td className="px-3 py-2.5">
                  {l.fixed ? (
                    <StatusBadge tone={l.category === 'threat' ? 'critical' : 'neutral'}>{l.category === 'threat' ? t('Ameaças') : t('Anúncios')}</StatusBadge>
                  ) : (
                    <Select
                      label={t('Tipo de {nome}', { nome: l.name })}
                      value={l.category}
                      onChange={(category) => l.id && patch.mutate({ id: l.id, category })}
                      className="h-8 text-xs"
                      options={[
                        { value: '', label: t('Anúncios e rastreio') },
                        { value: 'threat', label: t('Ameaças (alerta)') },
                      ]}
                    />
                  )}
                </td>
                <td className="tabular px-3 py-2.5 text-right text-ink-2">{l.enabled ? fmtInt(l.rules) : '—'}</td>
                <td className="px-3 py-2.5 text-xs whitespace-nowrap text-ink-2">{l.updated_at ? ago(l.updated_at) : '—'}</td>
                <td className="px-3 py-2.5">
                  {l.error ? (
                    <span title={l.error}>
                      <StatusBadge tone="critical">{t('Falha ao baixar')}</StatusBadge>
                    </span>
                  ) : !l.enabled ? (
                    <StatusBadge tone="neutral">{t('Desativada')}</StatusBadge>
                  ) : l.updated_at ? (
                    <StatusBadge tone="good">{t('Em uso')}</StatusBadge>
                  ) : (
                    <StatusBadge tone="warning">{t('Baixando…')}</StatusBadge>
                  )}
                  {l.fixed && (
                    <span className="mt-1 block text-[11px] text-muted" title={t('Definida no heimdalldns.yaml; altere por lá.')}>
                      {t('arquivo de configuração')}
                    </span>
                  )}
                </td>
                <td className="px-3 py-2.5">
                  <Switch
                    checked={l.enabled}
                    disabled={l.fixed || patch.isPending}
                    label={l.fixed ? t('Definida no arquivo de configuração') : l.enabled ? t('Desativar {nome}', { nome: l.name }) : t('Ativar {nome}', { nome: l.name })}
                    onChange={(enabled) => l.id && patch.mutate({ id: l.id, enabled })}
                  />
                </td>
                <td className="px-3 py-2.5 text-right">
                  {!l.fixed && l.id && (
                    <Button
                      size="sm"
                      variant={confirmDel === l.id ? 'danger' : 'ghost'}
                      icon={<Trash className="size-3.5" />}
                      onBlur={() => setConfirmDel(null)}
                      onClick={() => (confirmDel === l.id ? del.mutate(l.id) : setConfirmDel(l.id!))}
                      aria-label={t('Remover {nome}', { nome: l.name })}
                    >
                      {confirmDel === l.id ? t('Remover') : ''}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="space-y-3 border-t border-line p-4 sm:p-5">
        <form
          className="grid gap-2 sm:grid-cols-[1fr_2fr_auto]"
          onSubmit={(e) => {
            e.preventDefault()
            add.mutate({ name, url }, { onSuccess: () => (setName(''), setUrl('')) })
          }}
        >
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('Nome (opcional)')} aria-label={t('Nome da lista')} />
          <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={t('https://… (hosts, domínios ou Adblock)')} aria-label={t('URL da lista')} required />
          <Button type="submit" variant="primary" icon={<Plus className="size-4" />} loading={add.isPending}>
            {t('Adicionar')}
          </Button>
        </form>
        <ErrorNote error={add.error || patch.error || del.error} />
        <div className="flex flex-wrap gap-2">
          {listSuggestions
            .filter((s) => !have.has(s.url))
            .map((s) => (
              <button
                key={s.url}
                onClick={() => add.mutate({ name: s.name, url: s.url, category: 'category' in s ? s.category : '' })}
                className="rounded-lg border border-dashed border-line-strong px-3 py-1.5 text-left text-xs hover:border-accent"
              >
                <span className="font-medium text-ink">+ {s.name}</span>
                <span className="block text-muted">{s.note}</span>
              </button>
            ))}
        </div>
      </div>
    </Card>
  )
}

function RulesCard() {
  const qc = useQueryClient()
  const rules = useQuery({ queryKey: ['rules'], queryFn: () => api<Rules>('/api/rules') })
  const [deny, setDeny] = useState('')
  const [allow, setAllow] = useState('')
  const [dirty, setDirty] = useState(false)
  useEffect(() => {
    if (rules.data && !dirty) {
      setDeny(rules.data.deny.join('\n'))
      setAllow(rules.data.allow.join('\n'))
    }
  }, [rules.data, dirty])
  const save = useMutation({
    mutationFn: () => api<Rules>('/api/rules', { method: 'PUT', body: { deny: lines(deny), allow: lines(allow) } }),
    onSuccess: (d) => {
      qc.setQueryData(['rules'], d)
      setDirty(false)
    },
  })
  const cfg = rules.data
  return (
    <Card title={t('Regras próprias')} subtitle={t('Valem para todos os dispositivos, por cima das listas')}>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate()
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label={t('Bloquear (um por linha)')} hint={t('Domínio vale com os subdomínios. Aceita ||dominio^, /regex/ e service:nome.')}>
            <Textarea rows={8} value={deny} onChange={(e) => (setDeny(e.target.value), setDirty(true))} placeholder={t('exemplo.com\nservice:tiktok')} />
          </Field>
          <Field label={t('Liberar (um por linha)')} hint={t('Exceções: vencem as listas de bloqueio.')}>
            <Textarea rows={8} value={allow} onChange={(e) => (setAllow(e.target.value), setDirty(true))} placeholder={t('s.youtube.com')} />
          </Field>
        </div>
        {cfg && cfg.config_deny.length + cfg.config_allow.length > 0 && (
          <p className="text-[11px] text-muted">
            {t('Também valem')}{' '}{cfg.config_deny.length}{' '}{t('bloqueios e')}{' '}{cfg.config_allow.length}{' '}{t('exceções do arquivo de configuração.')}
          </p>
        )}
        <ErrorNote error={save.error} />
        <div className="flex justify-end">
          {save.isSuccess && !dirty && <span className="mr-3 self-center text-xs text-good-ink">{t('Regras salvas e em vigor.')}</span>}
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!dirty}>
            {t('Salvar regras')}
          </Button>
        </div>
      </form>
    </Card>
  )
}

const verdictText = { allowed: t('Liberado'), blocked: t('Bloqueado'), isolated: t('Barrado (dispositivo isolado)') }

function TestCard() {
  const devices = useDevices().data ?? []
  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const test = useMutation({ mutationFn: () => api<DomainTest>(`/api/filter/test${qs({ name, client })}`) })
  const r = test.data
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <FlaskConical className="size-4 text-accent" aria-hidden />{t('O que acontece com este domínio?')}
        </span>
      }
      subtitle={t('Mostra a regra que decide, sem fazer consulta nenhuma')}
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          if (name.trim()) test.mutate()
        }}
      >
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={t('ads.exemplo.com')} aria-label={t('Domínio')} />
        <div className="flex gap-2">
          <Select
            label={t('Dispositivo')}
            value={client}
            onChange={setClient}
            className="min-w-0 flex-1"
            options={[{ value: '', label: t('Regras globais') }, ...devices.map((d) => ({ value: d.id, label: d.display }))]}
          />
          <Button type="submit" variant="primary" loading={test.isPending}>
            {t('Testar')}
          </Button>
        </div>
      </form>
      <div className="mt-4">
        <ErrorNote error={test.error} />
        {r && (
          <div className="space-y-2 rounded-lg border border-line p-3 text-xs">
            <p className="flex items-center gap-2">
              <StatusBadge tone={r.verdict === 'allowed' ? 'good' : 'critical'}>{verdictText[r.verdict]}</StatusBadge>
              <span className="font-mono text-ink">{r.name}</span>
            </p>
            <p className="text-ink-2">
              {r.rule ? (
                <>
                  {t('Regra:')}{' '}<code className="font-mono text-ink">{r.rule}</code>{' '}
                  <span className="text-muted">
                    ({r.source === 'client' ? t('do dispositivo') : r.source === 'nrd' ? t('recém-registrado') : 'global'})
                  </span>
                </>
              ) : (
                t('Nenhuma regra casou: a consulta segue para o upstream.')
              )}
            </p>
            {r.category === 'threat' && <p className="text-critical-ink">{t('Está numa lista de ameaças: acessos geram alerta de segurança.')}</p>}
            {r.registered_days_ago !== undefined && (
              <p className="text-muted">{t('Domínio registrado há')}{' '}{fmtInt(r.registered_days_ago)}{' '}{t('dias (RDAP).')}</p>
            )}
            {r.client?.skip_global_lists && <p className="text-muted">{t('Este dispositivo não usa as listas globais.')}</p>}
          </div>
        )}
      </div>
    </Card>
  )
}
