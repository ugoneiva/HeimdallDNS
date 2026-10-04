// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { t } from '../lib/i18n'

// A AGPL pede que quem usa o programa pela rede possa obter o código-fonte.
export const SOURCE_URL = 'https://github.com/ugoneiva/HeimdallDNS'

/** Versão, licença e link do código-fonte. */
export function AboutLine({ version, className }: { version: string; className?: string }) {
  return (
    <p className={className}>
      {t('versão')} {version} · © 2026 JLW Security ·{' '}
      <a className="underline-offset-2 hover:text-ink hover:underline" href={SOURCE_URL} target="_blank" rel="noreferrer">
        {t('código-fonte')}
      </a>{' '}
      (<a className="underline-offset-2 hover:text-ink hover:underline" href="https://www.gnu.org/licenses/agpl-3.0.html" target="_blank" rel="noreferrer">
        AGPL-3.0
      </a>
      )
    </p>
  )
}
