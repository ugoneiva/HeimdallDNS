// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import type { ComponentType } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Bitcoin, Bug, Clapperboard, Dices, ExternalLink, EyeOff, Fish, Gamepad2, Heart, Link2, MessageCircle, Pill, RefreshCw,
  Router, SearchCheck, Skull, Unplug, Users,
} from 'lucide-react'
import { api } from '../api'
import type { WebFilterState } from '../types'
import { ago, fmtInt } from '../lib/format'
import { t } from '../lib/i18n'
import { useCan } from '../lib/auth'
import { Button, Card, ErrorNote, LabeledSwitch, Segmented, StatusBadge, cx } from '../components/ui'

export function useWebFilter() {
  return useQuery({ queryKey: ['webfilter'], queryFn: () => api<WebFilterState>('/api/webfilter'), refetchInterval: 20_000 })
}

type Icon = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

/** Ícone, nome e descrição de cada categoria (traduzidos aqui; o servidor manda em português). */
export const webCategory: Record<string, { icon: Icon; name: string; desc: string }> = {
  adulto: { icon: EyeOff, name: t('Adulto'), desc: t('Pornografia e conteúdo sexual explícito.') },
  apostas: { icon: Dices, name: t('Apostas'), desc: t('Cassinos, bets e apostas esportivas.') },
  ameacas: { icon: Bug, name: t('Ameaças'), desc: t('Malware, phishing, C2 e golpes conhecidos (seleção essencial).') },
  golpes: { icon: Fish, name: t('Golpes e lojas falsas'), desc: t('Lojas falsas, fraudes e sites enganosos.') },
  pirataria: { icon: Skull, name: t('Pirataria e torrent'), desc: t('Sites de pirataria, IPTV irregular e torrent.') },
  bypass: { icon: Unplug, name: t('VPN, proxy e DNS alternativo'), desc: t('Serviços usados para contornar o filtro: DoH, VPNs, proxies e Tor.') },
  'redes-sociais': { icon: Users, name: t('Redes sociais'), desc: t('Facebook, Instagram, TikTok, X, Snapchat, Reddit e outras.') },
  mensagens: { icon: MessageCircle, name: t('Mensagens'), desc: t('WhatsApp, Telegram e Discord.') },
  streaming: { icon: Clapperboard, name: t('Vídeo e streaming'), desc: t('YouTube, Netflix, Twitch e outros.') },
  jogos: { icon: Gamepad2, name: t('Jogos'), desc: t('Jogos online, lojas e plataformas de jogos.') },
  namoro: { icon: Heart, name: t('Namoro'), desc: t('Sites e apps de relacionamento.') },
  drogas: { icon: Pill, name: t('Drogas'), desc: t('Venda e apologia de drogas.') },
  cripto: { icon: Bitcoin, name: t('Cripto e mineração'), desc: t('Mineração no navegador e golpes com criptomoedas.') },
  encurtadores: { icon: Link2, name: t('Encurtadores de link'), desc: t('bit.ly e afins (escondem o destino real do link).') },
}

export function WebFilter() {
  const qc = useQueryClient()
  const admin = useCan('admin')
  const wf = useWebFilter()
  const save = useMutation({
    mutationFn: (body: WebFilterState['settings']) => api<WebFilterState>('/api/webfilter', { method: 'PUT', body }),
    onSuccess: (d) => qc.setQueryData(['webfilter'], d),
  })
  const refresh = useMutation({
    mutationFn: () => api('/api/webfilter/refresh', { method: 'POST' }),
    onSuccess: () => setTimeout(() => qc.invalidateQueries({ queryKey: ['webfilter'] }), 4000),
  })
  const s = wf.data?.settings
  const toggle = (id: string, on: boolean) =>
    s && save.mutate({ ...s, global: on ? [...s.global, id] : s.global.filter((x) => x !== id) })

  return (
    <div className="space-y-5">
      <ErrorNote error={wf.error || save.error} />
      <div className="grid gap-5 lg:grid-cols-2">
        <Card
          title={
            <span className="flex items-center gap-2">
              <SearchCheck className="size-4 text-accent" aria-hidden />
              {t('Busca segura (SafeSearch)')}
            </span>
          }
          subtitle={t('Google, Bing e DuckDuckGo sem resultados explícitos; YouTube no modo restrito')}
        >
          {s && (
            <div className="space-y-3">
              <LabeledSwitch
                checked={s.safesearch}
                disabled={!admin || save.isPending}
                onChange={(v) => save.mutate({ ...s, safesearch: v })}
                label={t('Forçar para todos os aparelhos (também dá para ligar só num grupo)')}
              />
              <div className="flex flex-wrap items-center gap-3 text-xs text-ink-2">
                <span>{t('YouTube:')}</span>
                <Segmented
                  label={t('Modo do YouTube')}
                  value={s.youtube || 'strict'}
                  onChange={(youtube) => admin && save.mutate({ ...s, youtube })}
                  options={[
                    { value: 'strict', label: t('Restrito') },
                    { value: 'moderate', label: t('Moderado') },
                  ]}
                />
              </div>
              <p className="text-[11px] text-muted">
                {t('Funciona pelo DNS: os buscadores respondem pelos endereços "seguros" oficiais. Não precisa instalar nada nos aparelhos.')}
              </p>
            </div>
          )}
        </Card>
        <Card
          title={
            <span className="flex items-center gap-2">
              <Router className="size-4 text-accent" aria-hidden />
              {t('Para ninguém escapar do filtro')}
            </span>
          }
          subtitle={t('O filtro vale para quem usa o HeimdallDNS como DNS')}
        >
          <ol className="list-decimal space-y-1.5 pl-5 text-xs text-ink-2">
            <li>{t('Bloqueie a categoria "VPN, proxy e DNS alternativo" (DoH, VPNs e proxies conhecidos).')}</li>
            <li>{t('No roteador, bloqueie a saída das portas 53 e 853 (TCP e UDP) para qualquer destino que não seja o HeimdallDNS.')}</li>
            <li>{t('Entregue o HeimdallDNS como único DNS pelo DHCP (sem DNS secundário de fora).')}</li>
          </ol>
          <p className="mt-3 text-[11px] text-muted">
            {t('O filtro por DNS vê o domínio, não a página: bloqueia o site inteiro, não um vídeo ou um post.')}
          </p>
        </Card>
      </div>

      <Card
        pad={false}
        title={t('Categorias')}
        subtitle={t('Ligue para bloquear para todos; para um grupo ou um horário, escolha em Dispositivos → Grupos e horários. Só as categorias em uso são baixadas.')}
        actions={
          admin ? (
            <Button size="sm" variant="ghost" icon={<RefreshCw className="size-3.5" />} loading={refresh.isPending} onClick={() => refresh.mutate()}>
              {t('Atualizar listas')}
            </Button>
          ) : undefined
        }
      >
        <ul className="grid gap-px bg-line sm:grid-cols-2 xl:grid-cols-3">
          {wf.data?.categories.map((c) => {
            const meta = webCategory[c.id]
            const Icon = meta?.icon ?? EyeOff
            const used = c.global || c.groups.length > 0
            return (
              <li key={c.id} className={cx('flex flex-col gap-2 bg-surface p-4', c.global && 'bg-gradient-to-br from-critical-soft to-surface')}>
                <div className="flex items-start gap-3">
                  <span
                    className={cx(
                      'grid size-10 shrink-0 place-items-center rounded-xl border',
                      c.global ? 'border-critical/40 bg-critical-soft text-critical-ink' : 'border-line bg-surface-2 text-ink-2',
                    )}
                  >
                    <Icon className="size-5" aria-hidden />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-ink">{meta?.name ?? c.name}</p>
                    <p className="text-xs text-ink-2">{meta?.desc ?? c.description}</p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                  {c.global && <StatusBadge tone="critical">{t('bloqueada para todos')}</StatusBadge>}
                  {c.groups.map((g) => (
                    <StatusBadge key={g} tone="accent">
                      {t('grupo {nome}', { nome: g })}
                    </StatusBadge>
                  ))}
                  {used && c.status.loaded && !c.status.error && (
                    <span className="text-muted">
                      {t('{n} regras', { n: fmtInt(c.status.rules) })}
                      {c.status.updated_at ? ' · ' + t('lista de {quando}', { quando: ago(c.status.updated_at) }) : ''}
                    </span>
                  )}
                  {used && !c.status.loaded && <span className="text-muted">{t('baixando…')}</span>}
                  {c.status.error && <StatusBadge tone="warning">{t('falha ao baixar')}</StatusBadge>}
                </div>
                {c.status.error && <p className="text-[11px] break-all text-warning">{c.status.error}</p>}
                <div className="mt-auto flex items-end justify-between gap-2 pt-1">
                  <p className="text-[10px] text-muted">
                    {(c.sources ?? []).map((src, i) => (
                      <span key={src.url}>
                        {i > 0 && ' · '}
                        <a href={src.homepage} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 hover:text-ink">
                          {src.name}
                          <ExternalLink className="size-2.5" aria-hidden />
                        </a>{' '}
                        ({src.license})
                      </span>
                    ))}
                    {c.rules && c.rules.length > 0 && (
                      <span>
                        {(c.sources ?? []).length > 0 && ' · '}
                        {t('catálogo interno')}
                      </span>
                    )}
                  </p>
                  {admin && (
                    <LabeledSwitch checked={c.global} disabled={save.isPending} onChange={(v) => toggle(c.id, v)} label={t('Todos')} />
                  )}
                </div>
              </li>
            )
          })}
        </ul>
      </Card>
    </div>
  )
}
