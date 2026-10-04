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

export type AuthState = { setup_required: boolean; authenticated: boolean; version: string; mode?: 'dns' | 'console' }

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

export type DHCPLease = {
  ip: string
  mac: string
  hostname?: string
  expires: string
  active: boolean
  reserved: boolean
  client_id?: string
  client_name?: string
}

export type DHCPReservation = { mac: string; ip: string; name?: string }

export type DHCPState = {
  enabled: boolean
  config?: {
    interface: string
    range_start: string
    range_end: string
    subnet: string
    server_ip: string
    routers: string[] | null
    dns: string[]
    domain: string
    lease_time: string
  }
  leases?: DHCPLease[]
  reservations?: DHCPReservation[]
}

export type HAStatus = {
  role: '' | 'primary' | 'replica'
  version?: string
  replicas?: { addr: string; last_seen: string; version: string }[]
  replica?: { primary_url: string; version: string; last_sync?: string; error?: string }
}

export type TenantState = {
  id: string
  name: string
  url: string
  insecure_tls: boolean
  online: boolean
  error?: string
  last_ok?: string
  checked?: string
  version?: string
  uptime_s: number
  clients: number
  rules: number
  queries_24h: number
  blocked_pct: number
  active_devices: number
  open_alerts: Partial<Record<'critical' | 'high' | 'medium' | 'low', number>>
  open_total: number
  upstreams_ok: number
  upstreams: number
  ha_role: string
}

export type ConsoleAlert = {
  tenant_id: string
  tenant_name: string
  id: number
  kind: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  summary: string
  client_name?: string
  client_ip?: string
  domain?: string
  count: number
  last_seen: string
}
