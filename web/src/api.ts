// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Cliente da API. O painel usa a sessão por cookie (mesma origem), então não
// guarda token nenhum no navegador.

export class ApiError extends Error {
  status: number
  data: Record<string, unknown> | null
  constructor(status: number, message: string, data: Record<string, unknown> | null = null) {
    super(message)
    this.status = status
    this.data = data
  }
}

// Avisa o App quando a sessão cai (401), para voltar à tela de login.
export const authEvents = new EventTarget()

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? 'GET',
    credentials: 'same-origin',
    headers: init.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  if (res.status === 204) return undefined as T
  let data: unknown = null
  const text = await res.text()
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error ?? `Erro ${res.status}`
    if (res.status === 401 && !path.startsWith('/api/auth/')) authEvents.dispatchEvent(new Event('expired'))
    throw new ApiError(res.status, msg, data as Record<string, unknown> | null)
  }
  return data as T
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

async function fail(res: Response): Promise<never> {
  let msg = `Erro ${res.status}`
  try {
    msg = ((await res.json()) as { error?: string }).error ?? msg
  } catch {
    /* corpo sem JSON */
  }
  if (res.status === 401 && !res.url.includes('/api/auth/') && !res.url.includes('/api/restore')) {
    authEvents.dispatchEvent(new Event('expired'))
  }
  throw new ApiError(res.status, msg)
}

// upload envia um formulário multipart (arquivos). Os campos de texto devem
// vir antes do arquivo: o servidor lê na ordem.
export async function upload<T = unknown>(path: string, form: FormData): Promise<T> {
  const res = await fetch(path, { method: 'POST', credentials: 'same-origin', body: form })
  if (!res.ok) return fail(res)
  return (await res.json()) as T
}

// download faz o POST e entrega o arquivo ao navegador para salvar.
export async function download(path: string, body: unknown, fallbackName: string): Promise<void> {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) return fail(res)
  const name = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') ?? '')?.[1] ?? fallbackName
  const url = URL.createObjectURL(await res.blob())
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}
