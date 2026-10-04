// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useQuery } from '@tanstack/react-query'
import { CircleAlert, Copy } from 'lucide-react'
import { api } from '../api'
import type { HAStatus } from '../types'
import { ago } from '../lib/format'
import { cx } from './ui'
import { t } from '../lib/i18n'

export function useHA() {
  return useQuery({ queryKey: ['ha'], queryFn: () => api<HAStatus>('/api/ha'), refetchInterval: 5000 })
}

/** Faixa no topo da réplica: a configuração é feita no principal. */
export function HABanner() {
  const { data } = useHA()
  if (data?.role !== 'replica' || !data.replica) return null
  const r = data.replica
  const bad = !!r.error
  return (
    <div
      role="status"
      className={cx(
        'mb-5 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border px-4 py-2.5 text-xs',
        bad ? 'border-critical/40 bg-critical-soft text-critical-ink' : 'border-line bg-surface-2 text-ink-2',
      )}
    >
      {bad ? <CircleAlert className="size-4" aria-hidden /> : <Copy className="size-4 text-accent" aria-hidden />}
      <span>
        <strong className="text-ink">{t('Réplica')}</strong>{' '}{t('de')}{' '}
        <a href={r.primary_url} className="font-mono text-accent hover:underline">
          {r.primary_url}
        </a>
        {t(': a configuração é feita no principal.')}
      </span>
      <span className="ml-auto">
        {bad ? t('Sem contato com o principal: continuo atendendo com a última configuração.') : t('Sincronizado {quando}.', { quando: ago(r.last_sync) })}
      </span>
    </div>
  )
}
