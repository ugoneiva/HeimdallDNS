// Cliente da API. O painel usa a sessão por cookie (mesma origem), então não
// guarda token nenhum no navegador.

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
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
    throw new ApiError(res.status, msg)
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
