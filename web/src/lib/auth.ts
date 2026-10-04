import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { AuthState, Role } from '../types'
import { t } from './i18n'

export function useAuth() {
  return useQuery({ queryKey: ['auth'], queryFn: () => api<AuthState>('/api/auth/state'), retry: 1 })
}

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** Diz se a conta logada tem ao menos o papel pedido (o servidor confere de novo). */
export function useCan(need: Role): boolean {
  const role = useAuth().data?.role
  return !!role && rank[role] >= rank[need]
}

export const roleLabel: Record<Role, string> = { admin: t('Administrador'), operator: t('Operador'), viewer: t('Leitura') }
export const roleNote: Record<Role, string> = {
  admin: t('Tudo, inclusive usuários, backup e configuração'),
  operator: t('Opera dispositivos, alertas e reservas; não muda a configuração'),
  viewer: t('Só vê'),
}
