import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Lock, LockOpen, Trash } from 'lucide-react'
import { api, qs } from '../api'
import type { ADComputer, Device, Ranked, Service, Summary } from '../types'
import { ago, fmtDateTime, fmtInt, fmtPct, modeLabel } from '../lib/format'
import { Button, ErrorNote, Field, Input, Modal, Segmented, Select, StatusBadge, Switch, Textarea, cx } from '../components/ui'
import { RankList } from '../components/charts'
import { RoamingTab } from './RoamingTab'
import { useGroups } from './Groups'
import { useADInfo } from './ActiveDirectory'
import { t } from '../lib/i18n'

type Tab = 'summary' | 'rules' | 'isolate' | 'roaming'

const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

export function DeviceModal({ device, onClose }: { device: Device | null; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>('summary')
  useEffect(() => setTab('summary'), [device?.id])
  return (
    <Modal open={!!device} onClose={onClose} wide title={device ? <DeviceTitle d={device} /> : ''}>
      {device && (
        <div className="space-y-5">
          <Segmented
            label={t('Seções')}
            value={tab}
            onChange={setTab}
            options={[
              { value: 'summary', label: t('Resumo') },
              { value: 'rules', label: t('Regras') },
              { value: 'isolate', label: device.settings.isolated ? t('Isolamento (ativo)') : t('Isolamento') },
              { value: 'roaming', label: device.settings.access_token ? t('Fora da rede (ativo)') : t('Fora da rede') },
            ]}
          />
          {tab === 'summary' && <SummaryTab d={device} onForget={onClose} />}
          {tab === 'rules' && <RulesTab d={device} />}
          {tab === 'isolate' && <IsolateTab d={device} />}
          {tab === 'roaming' && <RoamingTab d={device} />}
        </div>
      )}
    </Modal>
  )
}

function DeviceTitle({ d }: { d: Device }) {
  return (
    <span className="flex items-center gap-2">
      {d.display}
      {d.settings.isolated && <StatusBadge tone="critical">{t('Isolado')}</StatusBadge>}
    </span>
  )
}

function useSave(d: Device) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ path, method, body }: { path: string; method: string; body?: unknown }) =>
      api<Device>(`/api/clients/${encodeURIComponent(d.id)}${path}`, { method, body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['clients'] }),
  })
}

function SummaryTab({ d, onForget }: { d: Device; onForget: () => void }) {
  const save = useSave(d)
  const qc = useQueryClient()
  const [name, setName] = useState(d.settings.name ?? '')
  const [confirming, setConfirming] = useState(false)
  const sum = useQuery({
    queryKey: ['summary', '24h', d.id],
    queryFn: () => api<Summary>(`/api/stats/summary${qs({ range: '24h', client: d.id })}`),
  })
  const top = useQuery({
    queryKey: ['top', 'domains', d.id],
    queryFn: () => api<Ranked[]>(`/api/stats/top${qs({ kind: 'domains', range: '24h', client: d.id, limit: 6 })}`),
  })
  const topBlk = useQuery({
    queryKey: ['top', 'blocked', d.id],
    queryFn: () => api<Ranked[]>(`/api/stats/top${qs({ kind: 'blocked', range: '24h', client: d.id, limit: 6 })}`),
  })
  const forget = useMutation({
    mutationFn: () => api(`/api/clients/${encodeURIComponent(d.id)}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['clients'] })
      onForget()
    },
  })

  const facts: [string, string][] = [
    [t('Nome reverso (PTR)'), d.hostname || '—'],
    [t('Endereços IP'), d.ips.join(', ') || '—'],
    ['MAC', d.mac || t('desconhecido (fora da rede local ou atrás de roteador)')],
    [t('Fabricante'), d.vendor || '—'],
    [t('Visto pela primeira vez'), fmtDateTime(d.first_seen)],
    [t('Última consulta'), `${fmtDateTime(d.last_seen)} (${ago(d.last_seen)})`],
    [t('Consultas no total'), fmtInt(d.queries)],
    [t('Bloqueadas no total'), `${fmtInt(d.blocked)}${d.queries ? ` (${fmtPct((d.blocked / d.queries) * 100)})` : ''}`],
    [t('Identificador'), d.id],
  ]

  return (
    <div className="space-y-5">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          save.mutate({ path: '', method: 'PATCH', body: { name } })
        }}
      >
        <div className="min-w-56 flex-1">
          <Field label={t('Nome no painel')} hint={save.isSuccess ? t('Nome salvo.') : t('Vazio = usa o nome reverso ou o IP.')}>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder={d.hostname || d.ips[0]} />
          </Field>
        </div>
        <Button type="submit" loading={save.isPending} className="mb-[18px]">
          {t('Salvar nome')}
        </Button>
      </form>
      <ErrorNote error={save.error} />

      <dl className="grid gap-x-6 gap-y-2.5 text-xs sm:grid-cols-2">
        {facts.map(([k, v]) => (
          <div key={k}>
            <dt className="text-muted">{k}</dt>
            <dd className="mt-0.5 font-mono break-all text-ink">{v}</dd>
          </div>
        ))}
      </dl>

      <ADComputerCard host={d.hostname} />

      <div className="rounded-lg border border-line p-4">
        <p className="mb-3 text-xs font-semibold text-ink">{t('Últimas 24 horas')}</p>
        <p className="mb-4 text-xs text-ink-2">
          {fmtInt(sum.data?.counts.total ?? 0)}{' '}{t('consultas ·')}{' '}{fmtPct(sum.data?.blocked_pct ?? 0)}{' '}{t('bloqueadas')}
        </p>
        <div className="grid gap-5 sm:grid-cols-2">
          <div>
            <p className="mb-2 text-xs text-muted">{t('Mais consultados')}</p>
            <RankList color="s1" empty={t('Sem consultas.')} items={(top.data ?? []).map((r) => ({ key: r.key, label: r.key, value: r.count }))} />
          </div>
          <div>
            <p className="mb-2 text-xs text-muted">{t('Mais bloqueados')}</p>
            <RankList color="s2" empty={t('Nada bloqueado.')} items={(topBlk.data ?? []).map((r) => ({ key: r.key, label: r.key, value: r.count }))} />
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 border-t border-line pt-4">
        <p className="text-xs text-muted">{t('Esquecer apaga nome, regras e contadores. Se o aparelho consultar de novo, ele volta como novo.')}</p>
        <Button
          variant={confirming ? 'danger' : 'ghost'}
          icon={<Trash className="size-4" />}
          loading={forget.isPending}
          onClick={() => (confirming ? forget.mutate() : setConfirming(true))}
          onBlur={() => setConfirming(false)}
        >
          {confirming ? t('Confirmar: esquecer') : t('Esquecer')}
        </Button>
      </div>
      <ErrorNote error={forget.error} />
    </div>
  )
}

/** Computador do AD com o mesmo nome do aparelho (PTR ou DHCP). */
function ADComputerCard({ host }: { host?: string }) {
  const adOn = !!useADInfo().data
  const q = useQuery({
    queryKey: ['ad-computer', host],
    queryFn: () => api<{ computer: ADComputer | null }>(`/api/ad/computer${qs({ host })}`),
    enabled: adOn && !!host,
  })
  if (!adOn || !host) return null
  const c = q.data?.computer
  return (
    <div className="rounded-lg border border-line p-4 text-xs">
      <p className="mb-2 font-semibold text-ink">{t('Active Directory')}</p>
      {q.isLoading ? (
        <p className="text-muted">{t('Procurando')}{' '}{host}{' '}{t('no AD…')}</p>
      ) : c ? (
        <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
          {(
            [
              [t('Computador'), c.name],
              [t('Sistema'), [c.os, c.os_version].filter(Boolean).join(' ') || '—'],
              ['OU', c.ou],
              [t('Situação no AD'), c.enabled ? 'habilitado' : 'desabilitado'],
              [t('Último logon no domínio'), c.last_logon ? ago(c.last_logon) : '—'],
              [t('Descrição'), c.description || '—'],
            ] as const
          ).map(([k, v]) => (
            <div key={k}>
              <dt className="text-muted">{k}</dt>
              <dd className="mt-0.5 break-all text-ink">{v}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="text-muted">{t('Nenhum computador do AD com o nome')}{' '}{host}{t(': aparelho fora do domínio?')}</p>
      )}
    </div>
  )
}

function RulesTab({ d }: { d: Device }) {
  const save = useSave(d)
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<{ services: Service[]; groups: string[] }>('/api/services') })
  const [deny, setDeny] = useState((d.settings.deny ?? []).join('\n'))
  const [allow, setAllow] = useState((d.settings.allow ?? []).join('\n'))
  const [useGlobal, setUseGlobal] = useState(!d.settings.skip_global_lists)
  const [group, setGroup] = useState(d.settings.group ?? '')
  const groupsQ = useGroups()
  const denyList = lines(deny)
  const toggleService = (rule: string) =>
    setDeny(denyList.includes(rule) ? denyList.filter((r) => r !== rule).join('\n') : [...denyList, rule].join('\n'))

  const groups = services.data?.groups ?? []
  const groupName: Record<string, string> = { social: t('Redes sociais'), mensagens: t('Mensagens'), streaming: t('Streaming'), jogos: t('Jogos') }

  return (
    <form
      className="space-y-5"
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate({ path: '', method: 'PATCH', body: { deny: denyList, allow: lines(allow), skip_global_lists: !useGlobal, group } })
      }}
    >
      <Field label={t('Grupo')} hint={t('As regras e os horários do grupo valem depois das regras deste aparelho.')}>
        <Select
          label={t('Grupo')}
          value={group}
          onChange={setGroup}
          className="w-full"
          options={[{ value: '', label: t('Nenhum') }, ...(groupsQ.data ?? []).map((g) => ({ value: g.id, label: g.name }))]}
        />
      </Field>
      <div>
        <p className="mb-2 text-xs font-medium text-ink-2">{t('Bloquear serviços neste dispositivo')}</p>
        <div className="space-y-2">
          {groups.map((g) => (
            <div key={g} className="flex flex-wrap items-center gap-1.5">
              <Chip on={denyList.includes(`service:${g}`)} onClick={() => toggleService(`service:${g}`)} strong>
                {groupName[g] ?? g}{' '}{t('(todos)')}
              </Chip>
              {(services.data?.services ?? [])
                .filter((s) => s.group === g)
                .map((s) => (
                  <Chip key={s.id} on={denyList.includes(`service:${s.id}`) || denyList.includes(`service:${g}`)} onClick={() => toggleService(`service:${s.id}`)}>
                    {s.name}
                  </Chip>
                ))}
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('Bloquear (um por linha)')} hint={t('Domínio vale com os subdomínios. Aceita ||dominio^, /regex/ e service:nome.')}>
          <Textarea rows={6} value={deny} onChange={(e) => setDeny(e.target.value)} placeholder={t('tiktok.com\nservice:youtube')} />
        </Field>
        <Field label={t('Liberar (um por linha)')} hint={t('Vence os bloqueios deste dispositivo e as listas globais.')}>
          <Textarea rows={6} value={allow} onChange={(e) => setAllow(e.target.value)} placeholder={t('escola.edu.br')} />
        </Field>
      </div>
      <label className="flex items-center gap-3 text-sm text-ink">
        <Switch checked={useGlobal} onChange={setUseGlobal} label={t('Aplicar as listas globais')} />
        {t('Aplicar também as listas de bloqueio globais')}
      </label>
      <ErrorNote error={save.error} />
      <div className="flex items-center justify-end gap-3">
        {save.isSuccess && <span className="text-xs text-good-ink">{t('Regras salvas e em vigor.')}</span>}
        <Button type="submit" variant="primary" loading={save.isPending}>
          {t('Salvar regras')}
        </Button>
      </div>
    </form>
  )
}

function Chip({ on, onClick, children, strong }: { on: boolean; onClick: () => void; children: React.ReactNode; strong?: boolean }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={cx(
        'rounded-full border px-2.5 py-1 text-xs transition-colors',
        on ? 'border-s2 bg-s2/15 text-ink' : 'border-line-strong text-ink-2 hover:text-ink',
        strong && 'font-semibold',
      )}
    >
      {on && '✕ '}
      {children}
    </button>
  )
}

function IsolateTab({ d }: { d: Device }) {
  const save = useSave(d)
  const [mode, setMode] = useState(d.settings.isolate_mode || 'refused')
  const [reason, setReason] = useState(d.settings.isolate_reason ?? '')
  const [exc, setExc] = useState((d.settings.exceptions ?? []).join('\n'))
  const isolated = !!d.settings.isolated

  return (
    <div className="space-y-4">
      <div className={cx('rounded-lg border p-3 text-xs', isolated ? 'border-critical/40 bg-critical-soft text-critical-ink' : 'border-line text-ink-2')}>
        {isolated ? (
          <>
            <strong>{t('Isolado')}</strong>{' '}{t('desde')}{' '}{fmtDateTime(d.settings.isolated_at ?? d.last_seen)}
            {d.settings.isolate_reason && <> — {d.settings.isolate_reason}</>}{t('. Todas as consultas DNS deste dispositivo são barradas, exceto as exceções abaixo.')}
          </>
        ) : (
          <>
            {t('Isolar corta o DNS do dispositivo (quarentena). Útil para conter um aparelho suspeito sem tirar da rede. Ele ainda consegue acessar endereços IP diretos; para contenção completa, combine com o firewall.')}
          </>
        )}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label={t('Resposta para o dispositivo isolado')}>
          <Select
            label={t('Modo')}
            value={mode}
            onChange={setMode}
            className="w-full"
            options={Object.entries(modeLabel).map(([value, label]) => ({ value, label }))}
          />
        </Field>
        <Field label={t('Motivo (aparece no histórico)')}>
          <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t('Ex.: beacon suspeito, aguardando análise')} />
        </Field>
      </div>
      <Field label={t('Exceções durante o isolamento (um domínio por linha)')} hint={t('Ex.: o domínio de atualização do antivírus ou do EDR.')}>
        <Textarea rows={4} value={exc} onChange={(e) => setExc(e.target.value)} placeholder={t('update.antivirus.com')} />
      </Field>
      <ErrorNote error={save.error} />
      <div className="flex flex-wrap justify-end gap-2">
        {isolated && (
          <Button icon={<LockOpen className="size-4" />} loading={save.isPending} onClick={() => save.mutate({ path: '/release', method: 'POST' })}>
            {t('Liberar dispositivo')}
          </Button>
        )}
        <Button
          variant="danger"
          icon={<Lock className="size-4" />}
          loading={save.isPending}
          onClick={() => save.mutate({ path: '/isolate', method: 'POST', body: { mode, reason, exceptions: lines(exc) } })}
        >
          {isolated ? t('Atualizar isolamento') : t('Isolar agora')}
        </Button>
      </div>
    </div>
  )
}
