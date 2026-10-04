// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useRef, useState } from 'react'

export type SSEState = 'connecting' | 'open' | 'error'

/**
 * Assina um fluxo SSE. Os handlers ficam num ref, então trocar o handler não
 * reconecta; trocar a URL reconecta. O EventSource reconecta sozinho se cair.
 */
export function useSSE(url: string | null, handlers: Record<string, (data: unknown) => void>): SSEState {
  const ref = useRef(handlers)
  ref.current = handlers
  const [state, setState] = useState<SSEState>('connecting')

  useEffect(() => {
    if (!url) return
    setState('connecting')
    const es = new EventSource(url, { withCredentials: true })
    es.onopen = () => setState('open')
    es.onerror = () => setState(es.readyState === EventSource.CLOSED ? 'error' : 'connecting')
    const names = Object.keys(ref.current)
    const listeners = names.map((name) => {
      const fn = (ev: MessageEvent) => {
        try {
          ref.current[name]?.(JSON.parse(ev.data))
        } catch {
          /* evento malformado: ignora */
        }
      }
      es.addEventListener(name, fn)
      return [name, fn] as const
    })
    return () => {
      listeners.forEach(([n, fn]) => es.removeEventListener(n, fn))
      es.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url])

  return state
}
