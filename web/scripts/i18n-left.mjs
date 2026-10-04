// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Lista textos em português ainda fora de t('…') (para revisão).
import { readFileSync } from 'node:fs'
import { parseAst } from 'rolldown/parseAst'
const human = (s) => /[A-Za-zÀ-ú]{2,}/.test(s) && (/\s/.test(s.trim()) || /[À-ú]/.test(s) || /^[A-ZÀ-Ú][a-zà-ú]/.test(s.trim()))
const SKIP_ATTR = new Set(['className', 'href', 'type', 'autoComplete', 'inputMode', 'accept', 'key', 'variant', 'tone', 'size', 'd', 'viewBox', 'fill', 'stroke', 'download'])
for (const file of process.argv.slice(2)) {
  const src = readFileSync(file, 'utf8')
  const ast = parseAst(src, { lang: file.endsWith('.tsx') ? 'tsx' : 'ts' })
  const walk = (n, parent, attr) => {
    if (!n || typeof n !== 'object') return
    if (Array.isArray(n)) return n.forEach((x) => walk(x, parent, attr))
    if (typeof n.type !== 'string') return
    if (n.type === 'ImportDeclaration') return
    if (n.type === 'CallExpression' && (n.callee?.name === 't' || n.callee?.name === 'cx' || n.callee?.name === 'api' || n.callee?.name === 'qs')) return
    if (n.type === 'JSXAttribute') attr = n.name?.name
    if (attr && SKIP_ATTR.has(attr)) return
    if ((n.type === 'Literal' && typeof n.value === 'string' && human(n.value)) ||
        (n.type === 'TemplateLiteral' && n.quasis.some((q) => /[A-Za-zÀ-ú]{3,}/.test(q.value.raw) && /\s|[À-ú]/.test(q.value.raw)))) {
      if (parent?.type === 'BinaryExpression' || (parent?.type === 'Property' && parent.key === n)) return
      const line = src.slice(0, n.start).split('\n').length
      console.log(`${file}:${line}: ${src.slice(n.start, n.end).slice(0, 100).replace(/\n/g, '⏎')}`)
      return
    }
    for (const [k, v] of Object.entries(n)) if (k !== 'start' && k !== 'end' && v && typeof v === 'object') walk(v, n, attr)
  }
  walk(ast.body, null, undefined)
}
