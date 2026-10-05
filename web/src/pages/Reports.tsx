// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, FileText, Send } from 'lucide-react'
import { api } from '../api'
import { ago } from '../lib/format'
import { t } from '../lib/i18n'
import { useCan } from '../lib/auth'
import { Button, Card, ErrorNote, LabeledSwitch, Segmented, Select } from '../components/ui'

type ReportSettings = { enabled: boolean; frequency: 'weekly' | 'monthly'; hour: number; keep: number }
type Saved = { name: string; size: number; created: string }
type ReportsState = { settings: ReportSettings; reports: Saved[] }

const kb = (n: number) => (n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`)

/** Relatório em PDF: gerar na hora, baixar os anteriores e agendar o envio. */
export function ReportsCard() {
  const qc = useQueryClient()
  const admin = useCan('admin')
  const q = useQuery({ queryKey: ['reports'], queryFn: () => api<ReportsState>('/api/reports') })
  const [s, setS] = useState<ReportSettings | null>(null)
  const [days, setDays] = useState('7')
  useEffect(() => {
    if (q.data) setS(q.data.settings)
  }, [q.data])
  const save = useMutation({
    mutationFn: (body: ReportSettings) => api<ReportsState>('/api/reports/settings', { method: 'PUT', body }),
    onSuccess: (d) => qc.setQueryData(['reports'], d),
  })
  const send = useMutation({
    mutationFn: () => api<{ name: string }>('/api/reports/send', { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }),
  })
  const update = (p: Partial<ReportSettings>) => {
    if (!s) return
    const next = { ...s, ...p }
    setS(next)
    save.mutate(next)
  }
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <FileText className="size-4 text-accent" aria-hidden />
          {t('Relatórios')}
        </span>
      }
      subtitle={t('Resumo em PDF: consultas por dia, o que foi bloqueado, aparelhos mais ativos e alertas')}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Segmented
          label={t('Período do relatório')}
          value={days}
          onChange={setDays}
          options={[
            { value: '7', label: t('7 dias') },
            { value: '30', label: t('30 dias') },
          ]}
        />
        <a
          href={`/api/reports/generate?days=${days}&today=1`}
          onClick={() => setTimeout(() => qc.invalidateQueries({ queryKey: ['reports'] }), 2500)}
          className="inline-flex h-9 items-center gap-2 rounded-lg bg-accent px-3 text-sm font-medium text-accent-ink hover:brightness-110"
        >
          <Download className="size-4" aria-hidden />
          {t('Gerar PDF agora')}
        </a>
      </div>

      {admin && s && (
        <div className="mt-4 space-y-3 border-t border-line pt-4">
          <LabeledSwitch checked={s.enabled} disabled={save.isPending} onChange={(v) => update({ enabled: v })} label={t('Enviar automaticamente pelos canais de notificação')} />
          <div className="flex flex-wrap items-center gap-3 text-xs text-ink-2">
            <Segmented
              label={t('Frequência')}
              value={s.frequency}
              onChange={(v) => update({ frequency: v })}
              options={[
                { value: 'weekly', label: t('Semanal (segunda-feira)') },
                { value: 'monthly', label: t('Mensal (dia 1)') },
              ]}
            />
            <span>{t('às')}</span>
            <div className="w-24">
              <Select
                label={t('Hora do envio')}
                value={String(s.hour)}
                onChange={(v) => update({ hour: Number(v) })}
                options={Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${String(h).padStart(2, '0')}:00` }))}
              />
            </div>
          </div>
          <p className="text-[11px] text-muted">
            {t('Vai para os canais com "Relatório periódico" ligado em Notificações: o e-mail leva o PDF anexo; Telegram, Teams e webhook recebem o resumo.')}
          </p>
          <Button size="sm" icon={<Send className="size-3.5" />} loading={send.isPending} onClick={() => send.mutate()}>
            {t('Enviar o último período agora')}
          </Button>
          {send.isSuccess && <p className="text-xs text-good">{t('Enviado para a fila de notificações.')}</p>}
        </div>
      )}
      <ErrorNote error={q.error || save.error || send.error} />

      {(q.data?.reports.length ?? 0) > 0 && (
        <ul className="mt-4 divide-y divide-line border-t border-line">
          {q.data!.reports.slice(0, 8).map((r) => (
            <li key={r.name} className="flex items-center gap-3 py-2 text-xs">
              <FileText className="size-4 shrink-0 text-ink-2" aria-hidden />
              <span className="min-w-0 flex-1 truncate font-mono text-ink">{r.name.replace('heimdalldns-relatorio-', '').replace('.pdf', '')}</span>
              <span className="text-muted">
                {kb(r.size)} · {ago(r.created)}
              </span>
              <a href={`/api/reports/file/${encodeURIComponent(r.name)}`} className="text-accent hover:underline" aria-label={t('Baixar {nome}', { nome: r.name })}>
                <Download className="size-4" aria-hidden />
              </a>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}
