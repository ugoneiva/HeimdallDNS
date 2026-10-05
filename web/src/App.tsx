// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { useEffect, useState, type ComponentType } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { BookUser, ShieldHalf, Gauge, Globe, Waypoints, ListFilter, Network, Radar as RadarIcon, ScrollText, Settings as SettingsIcon } from 'lucide-react'
import { api, authEvents } from './api'
import type { AuthState } from './types'
import { cx } from './components/ui'
import { Logo } from './components/Logo'
import { ErrorBoundary } from './components/ErrorBoundary'
import { HornIcon, RuneBand } from './components/art'
import { AboutLine } from './components/About'
import { HABanner } from './components/HABanner'
import { Login } from './pages/Login'
import { Overview } from './pages/Overview'
import { Devices } from './pages/Devices'
import { QueryLog } from './pages/QueryLog'
import { Lists } from './pages/Lists'
import { Settings } from './pages/Settings'
import { Security, useSecuritySummary } from './pages/Security'
import { DHCP, useDHCP } from './pages/DHCP'
import { ConsoleApp } from './pages/Console'
import { ActiveDirectory, useADInfo } from './pages/ActiveDirectory'
import { DNS } from './pages/DNS'
import { Wizard } from './pages/Wizard'
import { NetworkMap } from './pages/NetworkMap'
import { WebFilter } from './pages/WebFilter'
import { MFACard } from './pages/Settings'
import { PasskeysCard } from './pages/Account'
import { roleLabel, useAuth } from './lib/auth'
import { t } from './lib/i18n'

type Page = 'overview' | 'devices' | 'map' | 'webfilter' | 'security' | 'queries' | 'lists' | 'dns' | 'dhcp' | 'ad' | 'settings'

const nav: { page: Page; path: string; label: string; icon: ComponentType<{ className?: string }> }[] = [
  { page: 'overview', path: '', label: t('Visão geral'), icon: Gauge },
  { page: 'devices', path: 'dispositivos', label: t('Dispositivos'), icon: RadarIcon },
  { page: 'map', path: 'mapa', label: t('Mapa da rede'), icon: Waypoints },
  { page: 'security', path: 'seguranca', label: t('Segurança'), icon: HornIcon },
  { page: 'queries', path: 'consultas', label: t('Consultas'), icon: ScrollText },
  { page: 'webfilter', path: 'filtro-web', label: t('Filtro web'), icon: ShieldHalf },
  { page: 'lists', path: 'listas', label: t('Listas e regras'), icon: ListFilter },
  { page: 'dns', path: 'dns', label: t('DNS'), icon: Globe },
  { page: 'dhcp', path: 'dhcp', label: t('DHCP'), icon: Network },
  { page: 'ad', path: 'ad', label: t('Active Directory'), icon: BookUser },
  { page: 'settings', path: 'configuracoes', label: t('Configurações'), icon: SettingsIcon },
]

function parseHash(): { page: Page; arg: string | null } {
  const [path, arg] = location.hash.replace(/^#\/?/, '').split('/')
  const n = nav.find((x) => x.path === (path ?? ''))
  return { page: n?.page ?? 'overview', arg: arg ? decodeURIComponent(arg) : null }
}

function go(page: Page, arg?: string | null) {
  const n = nav.find((x) => x.page === page)!
  location.hash = `#/${n.path}${arg ? `/${encodeURIComponent(arg)}` : ''}`
}

function useRoute() {
  const [r, setR] = useState(parseHash)
  useEffect(() => {
    const on = () => setR(parseHash())
    addEventListener('hashchange', on)
    return () => removeEventListener('hashchange', on)
  }, [])
  return r
}

export default function App() {
  const qc = useQueryClient()
  const auth = useQuery({ queryKey: ['auth'], queryFn: () => api<AuthState>('/api/auth/state'), retry: 1 })
  useEffect(() => {
    const on = () => qc.invalidateQueries({ queryKey: ['auth'] })
    authEvents.addEventListener('expired', on)
    return () => authEvents.removeEventListener('expired', on)
  }, [qc])

  if (auth.isLoading) return null
  if (auth.error || !auth.data) {
    return (
      <div className="grid min-h-full place-items-center p-6 text-center text-sm text-ink-2">
        {t('Não foi possível falar com o servidor HeimdallDNS. Ele está rodando?')}
      </div>
    )
  }
  if (!auth.data.authenticated) {
    return (
      <Login setup={auth.data.setup_required} adLogin={auth.data.ad_login} onDone={() => qc.resetQueries()} />
    )
  }
  const logout = async () => {
    await api('/api/auth/logout', { method: 'POST' }).catch(() => {})
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'auth' })
    await qc.resetQueries({ queryKey: ['auth'] })
  }
  if (auth.data.user?.mfa_required) {
    return <EnrollMFA onLogout={logout} />
  }
  if (auth.data.mode === 'console') {
    return <ConsoleApp version={auth.data.version} onLogout={logout} />
  }
  return (
    <>
    {auth.data.wizard && <Wizard onClose={() => {}} />}
    <Shell
      version={auth.data.version}
      onLogout={async () => {
        await api('/api/auth/logout', { method: 'POST' }).catch(() => {})
        // Limpa os dados da sessão e busca de novo o estado de login.
        qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'auth' })
        await qc.resetQueries({ queryKey: ['auth'] })
      }}
    />
    </>
  )
}

function Shell({ version, onLogout }: { version: string; onLogout: () => void }) {
  const { page, arg } = useRoute()
  const current = nav.find((n) => n.page === page)!
  const sec = useSecuritySummary()
  const openAlerts = sec.data?.open_total ?? 0
  const urgent = (sec.data?.open.critical ?? 0) + (sec.data?.open.high ?? 0) > 0
  const dhcpOn = useDHCP().data?.enabled ?? false
  const adOn = !!useADInfo().data
  const items = nav.filter((n) => (n.page !== 'dhcp' || dhcpOn) && (n.page !== 'ad' || adOn))

  return (
    <div className="min-h-full lg:grid lg:grid-cols-[232px_1fr]">
      <aside className="sticky top-0 z-20 border-b border-line bg-surface/95 backdrop-blur lg:h-screen lg:border-r lg:border-b-0">
        <div className="flex items-center gap-2.5 px-4 py-3 lg:px-5 lg:pt-5 lg:pb-2">
          <Logo className="size-8 lg:size-10" />
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-wide text-ink">{t('HeimdallDNS')}</p>
            <p className="text-[11px] text-muted">{t('guardião da sua rede')}</p>
          </div>
        </div>
        <RuneBand text="HEIMDALL · BIFROST" className="mb-3 hidden h-3 w-40 px-5 text-accent opacity-40 lg:block" />
        <nav aria-label={t('Seções')} className="flex gap-1 overflow-x-auto px-2 pb-2 lg:flex-col lg:px-3 lg:pb-0">
          {items.map((n) => {
            const Icon = n.icon
            const active = n.page === page
            return (
              <a
                key={n.page}
                href={`#/${n.path}`}
                aria-current={active ? 'page' : undefined}
                className={cx(
                  'flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-sm whitespace-nowrap transition-colors',
                  active ? 'bg-accent-soft font-medium text-accent' : 'text-ink-2 hover:bg-surface-2 hover:text-ink',
                )}
              >
                <Icon className={cx('size-4', n.page === 'security' && urgent && 'text-critical')} />
                {n.label}
                {n.page === 'security' && openAlerts > 0 && (
                  <span
                    className={cx(
                      'ml-auto rounded-full px-1.5 text-[10px] leading-4 font-semibold',
                      urgent ? 'bg-critical text-white' : 'bg-surface-3 text-ink-2',
                    )}
                    aria-label={t('{n} alertas abertos', { n: openAlerts })}
                  >
                    {openAlerts > 99 ? '99+' : openAlerts}
                  </span>
                )}
              </a>
            )
          })}
        </nav>
        <AboutLine version={version} className="absolute right-5 bottom-4 left-5 hidden text-[11px] leading-relaxed text-muted lg:block" />
      </aside>

      <main className="relative min-w-0">
        <div className="bg-grid pointer-events-none absolute inset-x-0 top-0 h-64" aria-hidden />
        <div className="relative mx-auto max-w-7xl px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
          <HABanner />
          <PageHeader page={page} icon={current.icon} label={current.label} />
          <ReadOnlyNote page={page} />
          <ErrorBoundary resetKey={page}>
          {page === 'overview' && <Overview onOpenDevice={(id) => go('devices', id)} onOpenSecurity={() => go('security')} />}
          {page === 'map' && <NetworkMap />}
          {page === 'devices' && <Devices openId={arg} onOpen={(id) => go('devices', id)} />}
          {page === 'security' && <Security onOpenDevice={(id) => go('devices', id)} />}
          {page === 'queries' && <QueryLog />}
          {page === 'webfilter' && <WebFilter />}
          {page === 'lists' && <Lists />}
          {page === 'dns' && <DNS />}
          {page === 'dhcp' && <DHCP onOpenDevice={(id) => go('devices', id)} />}
          {page === 'ad' && <ActiveDirectory />}
          {page === 'settings' && <Settings onLogout={onLogout} />}
          </ErrorBoundary>
        </div>
      </main>
    </div>
  )
}

// Páginas que exigem um papel para alterar algo (o servidor confere de novo).
const needs: Partial<Record<Page, 'operator' | 'admin'>> = {
  devices: 'operator', security: 'operator', queries: 'operator', dhcp: 'operator', lists: 'admin', dns: 'admin', webfilter: 'admin',
}

function ReadOnlyNote({ page }: { page: Page }) {
  const role = useAuth().data?.role
  const need = needs[page]
  if (!role || !need || role === 'admin' || (need === 'operator' && role === 'operator')) return null
  return (
    <p className="mb-4 rounded-lg border border-line bg-surface px-3 py-2 text-xs text-ink-2">
      {t('Seu papel é')}{' '}<strong className="text-ink">{roleLabel[role]}</strong>{t(': aqui você vê tudo, mas as alterações são de quem é')}{' '}
      {need === 'admin' ? 'administrador' : t('operador ou administrador')}.
    </p>
  )
}

/** Contas do AD cadastram o MFA no primeiro acesso, antes de usar o painel. */
function EnrollMFA({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="relative grid min-h-full place-items-center px-4 py-10">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />
      <div className="relative w-full max-w-lg space-y-4">
        <div className="flex items-center gap-3">
          <Logo className="size-9" />
          <div>
            <h1 className="text-lg font-semibold text-ink">{t('Proteja sua conta')}</h1>
            <p className="text-xs text-ink-2">{t('Contas do Active Directory usam a verificação em duas etapas. Leva um minuto.')}</p>
          </div>
        </div>
        <MFACard />
        <PasskeysCard />
        <button className="text-xs text-muted hover:text-ink" onClick={onLogout}>
          {t('Sair')}
        </button>
      </div>
    </div>
  )
}

// Subtítulos das páginas: dizem para que serve cada tela.
const subtitles: Partial<Record<Page, string>> = {
  overview: t('O que o guardião vê agora'),
  devices: t('Quem está na sua rede, e quem pode atravessar'),
  map: t('Com quem cada aparelho fala'),
  security: t('O Gjallarhorn soa quando há perigo'),
  queries: t('Cada pergunta feita ao DNS, ao vivo'),
  webfilter: t('Categorias que não atravessam a Bifröst'),
  lists: t('O que não atravessa a ponte'),
  dns: t('A saída pela Bifröst e os nomes da sua rede'),
  dhcp: t('Endereços entregues aos aparelhos'),
  ad: t('Usuários, grupos e DNS do domínio'),
  settings: t('Contas, backup e preferências'),
}

function PageHeader({ page, icon: Icon, label }: { page: Page; icon: ComponentType<{ className?: string }>; label: string }) {
  return (
    <div className="mb-5 flex items-center gap-3">
      <span className="grid size-10 place-items-center rounded-xl border border-accent/30 bg-gradient-to-br from-accent-soft to-transparent text-accent shadow-[0_0_24px_-8px_var(--accent)]">
        <Icon className="size-5" />
      </span>
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{label}</h1>
        {subtitles[page] && <p className="text-xs text-muted">{subtitles[page]}</p>}
      </div>
    </div>
  )
}
