// Tipos espelhando as respostas da API do HeimdallDNS.

export type Counts = {
  total: number
  forwarded: number
  cached: number
  blocked: number
  isolated: number
  local: number
  refused: number
  errors: number
}

export type UpstreamStat = {
  address: string
  latency_ms: number
  ok: number
  fail: number
  healthy: boolean
}

export type Status = {
  version: string
  uptime_s: number
  queries: Counts & { total: number }
  cache: { entries: number; hits: number; misses: number }
  upstreams: UpstreamStat[]
  rules: { block: number; allow: number }
  clients: number
  history: { dropped_events: number; dropped_rows: number } | null
}

export type Settings = {
  name?: string
  isolated?: boolean
  isolate_mode?: string
  isolate_reason?: string
  isolated_at?: string
  exceptions?: string[]
  allow?: string[]
  deny?: string[]
  skip_global_lists?: boolean
  access_token?: string
}

export type Device = {
  id: string
  display: string
  mac?: string
  vendor?: string
  hostname?: string
  ips: string[]
  first_seen: string
  last_seen: string
  queries: number
  blocked: number
  settings: Settings
}

export type QueryEntry = {
  id?: number
  time: string
  client_ip: string
  client_id?: string
  client_name?: string
  name: string
  type: string
  status: string
  rcode: string
  rule?: string
  category?: string
  upstream?: string
  duration_ms: number
}

export type Summary = {
  from: string
  to: string
  counts: Counts
  blocked_pct: number
  cached_pct: number
  avg_forward_ms: number
  active_clients: number
}

export type Bucket = Counts & { time: string; avg_forward_ms: number }

export type Timeseries = { step_s: number; points: Bucket[] }

export type Ranked = { key: string; name?: string; count: number; blocked?: number }

export type Second = { t: number; total: number; blocked: number; cached: number }

export type ListStatus = {
  id?: number
  name: string
  url: string
  enabled: boolean
  fixed: boolean
  category: '' | 'threat'
  rules: number
  invalid: number
  updated_at?: string
  error?: string
}

export type Rules = {
  config_allow: string[]
  config_deny: string[]
  allow: string[]
  deny: string[]
}

export type Service = { id: string; name: string; group: string; domains: string[] }

export type AuthState = { setup_required: boolean; authenticated: boolean; version: string }

export type DomainTest = {
  name: string
  verdict: 'allowed' | 'blocked' | 'isolated'
  rule: string
  source: '' | 'global' | 'client' | 'nrd'
  category?: string
  registered_days_ago?: number
  global: { verdict: string; rule: string }
  client?: { id: string; name: string; isolated: boolean; verdict: string; rule: string; skip_global_lists: boolean }
}

export type SecurityEvent = {
  id: number
  first_seen: string
  last_seen: string
  count: number
  kind: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  client_id?: string
  client_ip?: string
  client_name?: string
  domain?: string
  summary: string
  details?: Record<string, unknown>
  status: 'open' | 'ack'
}

export type SecuritySummary = {
  open: Partial<Record<SecurityEvent['severity'], number>>
  open_total: number
  last_24h: Record<string, number>
}

export type SecuritySettings = {
  dga: boolean
  tunnel: boolean
  nrd: boolean
  nrd_action: 'alert' | 'block'
  nrd_max_days: number
  new_device: boolean
  auto_isolate: string[]
  ignore_domains: string[]
}

export type DeviceAccess = {
  public_host: string
  doh: boolean
  dot: boolean
  token?: string
  doh_url?: string
  dot_host?: string
}
