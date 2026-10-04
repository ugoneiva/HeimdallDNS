// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Idioma do painel. O texto em português é a chave: t('Salvar') devolve a
// tradução do idioma escolhido ou, se faltar, o próprio português (nunca uma
// chave crua). Trocar o idioma recarrega a página, então t() é uma função
// simples, usável em qualquer lugar (inclusive fora de componentes).
import { en } from '../i18n/en'

export type Lang = 'pt' | 'en'

const KEY = 'heimdall.lang'

function detect(): Lang {
  try {
    const saved = localStorage.getItem(KEY)
    if (saved === 'pt' || saved === 'en') return saved
  } catch {
    /* sem armazenamento: segue o navegador */
  }
  return navigator.language.toLowerCase().startsWith('pt') ? 'pt' : 'en'
}

export const lang: Lang = detect()
export const locale = lang === 'pt' ? 'pt-BR' : 'en-US'
document.documentElement.lang = locale

export function setLang(l: Lang) {
  try {
    localStorage.setItem(KEY, l)
  } catch {
    /* ignora */
  }
  location.reload()
}

const dict: Record<string, string> = lang === 'en' ? en : {}

/** Traduz; {nome} no texto é trocado por vars.nome. */
export function t(pt: string, vars?: Record<string, string | number>): string {
  let s = dict[pt] ?? pt
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v))
  return s
}

/** Mensagens que vêm do servidor (em português): traduz as conhecidas. */
export function tServer(msg: string): string {
  if (lang === 'pt') return msg
  if (dict[msg]) return dict[msg]
  // Mensagens com um pedaço variável no fim: "prefixo: detalhe".
  const i = msg.indexOf(': ')
  if (i > 0 && dict[msg.slice(0, i)]) return dict[msg.slice(0, i)] + msg.slice(i)
  return msg
}
