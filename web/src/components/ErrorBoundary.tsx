import { Component, type ReactNode } from 'react'
import { t } from '../lib/i18n'
import { Button } from './ui'

/** Se uma tela quebrar, mostra o erro e um botão de recarregar (sem tela em branco). */
export class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state: { error: Error | null } = { error: null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null })
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div role="alert" className="rounded-xl border border-critical/40 bg-critical-soft p-5 text-sm text-critical-ink">
        <p className="mb-1 font-semibold">{t('Algo deu errado nesta tela.')}</p>
        <p className="mb-4 font-mono text-xs break-all">{this.state.error.message}</p>
        <Button onClick={() => location.reload()}>{t('Recarregar')}</Button>
      </div>
    )
  }
}
