// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { Languages } from 'lucide-react'
import { lang, setLang, t } from '../lib/i18n'
import { Segmented } from './ui'

/** Idioma do painel (troca e recarrega). */
export function LangPicker() {
  return (
    <Segmented
      label={t('Idioma')}
      value={lang}
      onChange={setLang}
      options={[
        { value: 'pt', label: <span className="flex items-center gap-1.5"><Languages className="size-3.5" aria-hidden />Português</span> },
        { value: 'en', label: 'English' },
      ]}
    />
  )
}
