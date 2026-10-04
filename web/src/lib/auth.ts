import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { AuthState, Role } from '../types'

export function useAuth() {
  return useQuery({ queryKey: ['auth'], queryFn: () => api<AuthState>('/api/auth/state'), retry: 1 })
}

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** Diz se a conta logada tem ao menos o papel pedido (o servidor confere de novo). */
export function useCan(need: Role): boolean {
  const role = useAuth().data?.role
  return !!role && rank[role] >= rank[need]
}

export const roleLabel: Record<Role, string> = { admin: 'Administrador', operator: 'Operador', viewer: 'Leitura' }
export const roleNote: Record<Role, string> = {
  admin: 'Tudo, inclusive usuários, backup e configuração',
  operator: 'Opera dispositivos, alertas e reservas; não muda a configuração',
  viewer: 'Só vê',
}
