// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, ChevronLeft, ChevronRight } from 'lucide-react'
import { api } from '../api'
import type { ListStatus } from '../types'
import { Button, ErrorNote, LabeledSwitch, cx } from '../components/ui'
import { Logo } from '../components/Logo'
import { UpstreamPicker, useUpstream } from './DNS'
import { PiholeImport } from './Maintenance'
import { listSuggestions } from './Lists'
import { t } from '../lib/i18n'

const steps = [t('Boas-vindas'), t('Saída do DNS'), t('Bloqueios'), 'Pi-hole', t('Rede'), t('Pronto')]

/** Assistente do primeiro acesso: aparece uma vez, numa instalação nova. */
export function Wizard({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [step, setStep] = useState(0)
  const finish = useMutation({
    mutationFn: () => api('/api/wizard/done', { method: 'POST' }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['auth'] })
      onClose()
    },
  })
  const next = () => setStep((s) => Math.min(s + 1, steps.length - 1))
  const back = () => setStep((s) => Math.max(s - 1, 0))

  return (
    <div role="dialog" aria-modal aria-labelledby="wizard-title" className="fixed inset-0 z-50 overflow-y-auto bg-page">
      <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-64" aria-hidden />
      <div className="relative mx-auto max-w-3xl px-4 py-8 sm:px-6">
        <div className="mb-6 flex items-center gap-3">
          <Logo className="size-8" />
          <div>
            <h1 id="wizard-title" className="text-lg font-semibold text-ink">
              {t('Configuração inicial')}
            </h1>
            <p className="text-xs text-muted">{t('Leva uns 2 minutos. Tudo pode ser mudado depois.')}</p>
          </div>
          <button className="ml-auto text-xs text-muted hover:text-ink" onClick={() => finish.mutate()}>
            {t('Pular assistente')}
          </button>
        </div>

        <ol className="mb-6 flex gap-1.5" aria-label={t('Etapas')}>
          {steps.map((s, i) => (
            <li key={s} className="flex-1" aria-current={i === step ? 'step' : undefined}>
              <span className={cx('block h-1 rounded-full', i <= step ? 'bg-accent' : 'bg-surface-3')} />
              <span className={cx('mt-1.5 hidden text-[11px] sm:block', i === step ? 'font-medium text-ink' : 'text-muted')}>{s}</span>
            </li>
          ))}
        </ol>

        <section className="rounded-xl border border-line bg-surface p-5 sm:p-6">
          {step === 0 && <Welcome />}
          {step === 1 && <UpstreamStep onSaved={next} />}
          {step === 2 && <ListsStep />}
          {step === 3 && (
            <>
              <h2 className="mb-1 text-base font-semibold text-ink">{t('Vem do Pi-hole?')}</h2>
              <p className="mb-4 text-sm text-ink-2">{t('Traga listas, regras, nomes locais e reservas de DHCP. Se não usa Pi-hole, só avance.')}</p>
              <PiholeImport />
            </>
          )}
          {step === 4 && <NetworkStep />}
          {step === 5 && <DoneStep />}
        </section>

        <ErrorNote error={finish.error} />
        <div className="mt-5 flex items-center justify-between">
          <Button variant="ghost" icon={<ChevronLeft className="size-4" />} onClick={back} disabled={step === 0}>
            {t('Voltar')}
          </Button>
          {step < steps.length - 1 ? (
            <Button variant="primary" onClick={next}>
              {step === 1 ? t('Manter e avançar') : t('Avançar')} <ChevronRight className="size-4" />
            </Button>
          ) : (
            <Button variant="primary" icon={<Check className="size-4" />} loading={finish.isPending} onClick={() => finish.mutate()}>
              {t('Ir para o painel')}
            </Button>
          )}
        </div>
      </div>
    </div>
  )
}

function Welcome() {
  return (
    <div className="space-y-3 text-sm text-ink-2">
      <h2 className="text-base font-semibold text-ink">{t('Bem-vindo ao HeimdallDNS')}</h2>
      <p>
        {t('Ele vira o DNS da sua rede: responde os aparelhos, bloqueia anúncios, rastreadores e ameaças, e mostra quem está acessando o quê.')}
      </p>
      <p>{t('Nas próximas telas você escolhe:')}</p>
      <ul className="list-disc space-y-1 pl-5">
        <li>{t('para onde as consultas vão (com criptografia);')}</li>
        <li>{t('o que bloquear;')}</li>
        <li>{t('se quer trazer a configuração de um Pi-hole;')}</li>
        <li>{t('como apontar os aparelhos para cá.')}</li>
      </ul>
    </div>
  )
}

function UpstreamStep({ onSaved }: { onSaved: () => void }) {
  const qc = useQueryClient()
  const up = useUpstream()
  const save = useMutation({
    mutationFn: ({ servers, mode }: { servers: string[]; mode: string }) => api('/api/dns/upstream', { method: 'PUT', body: { servers, mode } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['upstream'] })
      onSaved()
    },
  })
  return (
    <div>
      <h2 className="mb-1 text-base font-semibold text-ink">{t('Para onde as consultas vão')}</h2>
      <p className="mb-4 text-sm text-ink-2">
        {t('O que não está bloqueado nem no cache é perguntado a estes servidores, por conexão cifrada (o provedor de internet não vê os sites). Escolha um ou mais; com mais de um, o mais rápido responde e os outros ficam de reserva.')}
      </p>
      <ErrorNote error={up.error || save.error} />
      {up.data && (
        <UpstreamPicker initial={up.data.servers} initialMode={up.data.mode} saving={save.isPending} saveLabel={t('Salvar e avançar')}
          onSave={(servers, mode) => save.mutate({ servers, mode })} />
      )}
    </div>
  )
}

function ListsStep() {
  const qc = useQueryClient()
  const lists = useQuery({ queryKey: ['lists'], queryFn: () => api<ListStatus[]>('/api/lists') })
  const toggle = useMutation({
    mutationFn: async ({ s, on }: { s: (typeof listSuggestions)[number]; on: boolean }) => {
      const have = lists.data?.find((l) => l.url === s.url)
      if (on && !have) {
        return api('/api/lists', { method: 'POST', body: { name: s.name, url: s.url, category: s.category ?? '' } })
      }
      if (have?.id) {
        return api(`/api/lists/${have.id}`, { method: 'PATCH', body: { enabled: on } })
      }
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['lists'] }),
  })
  return (
    <div>
      <h2 className="mb-1 text-base font-semibold text-ink">{t('O que bloquear')}</h2>
      <p className="mb-4 text-sm text-ink-2">
        {t('Listas mantidas pela comunidade, atualizadas todo dia. Dá para trocar, somar outras e criar regras próprias em Listas e regras.')}
      </p>
      <ErrorNote error={lists.error || toggle.error} />
      <div className="space-y-3">
        {listSuggestions.map((s) => {
          const have = lists.data?.find((l) => l.url === s.url)
          const on = !!have && have.enabled
          return (
            <div key={s.url} className="rounded-lg border border-line px-3 py-2.5">
              <LabeledSwitch
                checked={on}
                disabled={toggle.isPending || !lists.data || (!!have && !have.id)}
                onChange={(v) => toggle.mutate({ s, on: v })}
                label={`${s.name} — ${s.note}${have && !have.id ? t(' (definida no arquivo de configuração)') : ''}`}
              />
            </div>
          )
        })}
      </div>
      {lists.data?.some((l) => !l.id) && (
        <p className="mt-3 text-[11px] text-muted">{t('Listas do arquivo de configuração também estão ativas (aparecem em Listas e regras).')}</p>
      )}
    </div>
  )
}

function NetworkStep() {
  const host = location.hostname
  // Aberto no próprio servidor (localhost), o endereço não serve para o roteador.
  const loopback = host === 'localhost' || host.startsWith('127.') || host === '[::1]'
  const isIP = !loopback && (/^[\d.]+$/.test(host) || host.includes(':'))
  return (
    <div className="space-y-3 text-sm text-ink-2">
      <h2 className="text-base font-semibold text-ink">{t('Apontar a rede para cá')}</h2>
      <p>
        {t('Os aparelhos precisam usar este servidor como DNS. O jeito mais simples é no')}{' '}<strong>{t('roteador')}</strong>{t(': no DHCP dele, troque o servidor DNS pelo IP deste servidor')}{isIP ? (
          <>
            {' '}(<strong className="font-mono text-ink">{host}</strong>)
          </>
        ) : null}
        {t('. Os aparelhos pegam a mudança ao reconectar no Wi-Fi.')}
      </p>
      <ul className="list-disc space-y-1 pl-5">
        <li>{t('Quer que o próprio HeimdallDNS seja o DHCP? Ligue a seção')}{' '}<code className="font-mono">dhcp</code>{' '}{t('na configuração e desligue o do roteador.')}</li>
        <li>{t('Celulares fora de casa: em Dispositivos → aparelho → Fora da rede há o perfil de DNS criptografado (DoH/DoT).')}</li>
        <li>{t('Para não ficar sem internet se este servidor parar, use dois (alta disponibilidade) ou deixe o roteador como DNS secundário.')}</li>
      </ul>
    </div>
  )
}

function DoneStep() {
  return (
    <div className="space-y-3 text-sm text-ink-2">
      <h2 className="text-base font-semibold text-ink">{t('Pronto')}</h2>
      <p>{t('Algumas recomendações para deixar tudo redondo:')}</p>
      <ul className="list-disc space-y-1 pl-5">
        <li>
          <strong>{t('Ligue a verificação em duas etapas')}</strong>{' '}{t('em Configurações: protege o painel e é obrigatória para alterar o Active Directory.')}
        </li>
        <li>
          <strong>{t('Backup:')}</strong>{' '}{t('as cópias automáticas ficam no servidor; baixe uma cifrada em Configurações e guarde fora dele.')}
        </li>
        <li>
          <strong>{t('Segurança:')}</strong>{' '}{t('a aba Segurança mostra ameaças, malware com DGA e túneis por DNS, e pode isolar um aparelho sozinha.')}
        </li>
      </ul>
    </div>
  )
}
