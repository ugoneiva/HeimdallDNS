// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Marca os textos do painel com t('…') (uso único na criação do i18n; fica
// para os arquivos novos). Uso: node scripts/i18n-wrap.mjs src/pages/X.tsx …
// Só mexe em: texto de JSX, atributos de texto e textos em condicionais
// dentro do JSX. Lista os templates com variáveis para revisão manual.
import { readFileSync, writeFileSync } from 'node:fs'
import { relative, dirname } from 'node:path'
import { parseAst } from 'rolldown/parseAst'

const TEXT_ATTRS = new Set(['label', 'placeholder', 'title', 'hint', 'subtitle', 'aria-label', 'alt', 'saveLabel'])
const TEXT_PROPS = new Set(['label', 'note', 'title', 'hint', 'summary'])
const human = (s) => /[A-Za-zÀ-ú]{2,}/.test(s) && (/\s/.test(s.trim()) || /[À-ú]/.test(s) || /^[A-ZÀ-Ú]/.test(s.trim()))
const q = (s) => "'" + s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'"

for (const file of process.argv.slice(2)) {
  const src = readFileSync(file, 'utf8')
  const ast = parseAst(src, { lang: file.endsWith('.tsx') ? 'tsx' : 'ts' })
  const edits = []
  const review = []

  const walk = (node, parent, attr) => {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) {
      for (const n of node) walk(n, parent, attr)
      return
    }
    if (typeof node.type !== 'string') return
    let curAttr = attr
    if (node.type === 'JSXAttribute') {
      const name = node.name?.name?.name ?? node.name?.name
      curAttr = name
      const v = node.value
      if (v && v.type === 'Literal' && typeof v.value === 'string' && TEXT_ATTRS.has(name) && /[A-Za-zÀ-ú]/.test(v.value)) {
        edits.push([v.start, v.end, `{t(${q(v.value)})}`])
        return
      }
    }
    if (node.type === 'JSXText') {
      if (inCode) return // exemplos de configuração e comandos ficam como estão
      const raw = src.slice(node.start, node.end)
      const core = raw.replace(/\s+/g, ' ').trim()
      if (/[A-Za-zÀ-ú]/.test(core)) {
        const lead = raw.match(/^\s*/)[0]
        const trail = raw.match(/\s*$/)[0]
        const pre = lead && !lead.includes('\n') ? "{' '}" : lead
        const post = trail && !trail.includes('\n') ? "{' '}" : trail
        edits.push([node.start, node.end, `${pre}{t(${q(core)})}${post}`])
      }
      return
    }
    if (node.type === 'Literal' && typeof node.value === 'string' && human(node.value)) {
      const inText = curAttr === undefined || TEXT_ATTRS.has(curAttr)
      const ok =
        parent &&
        inText &&
        ((parent.type === 'ConditionalExpression' && node !== parent.test) ||
          (parent.type === 'LogicalExpression' && node === parent.right) ||
          parent.type === 'JSXExpressionContainer')
      const prop = parent && parent.type === 'Property' && node === parent.value && TEXT_PROPS.has(parent.key?.name)
      const err = parent && parent.type === 'NewExpression' && parent.callee?.name === 'Error'
      if ((ok && insideJSX) || prop || err) edits.push([node.start, node.end, `t(${q(node.value)})`])
    }
    if (node.type === 'TemplateLiteral' && insideJSX && node.quasis.some((x) => /[A-Za-zÀ-ú]{3,}/.test(x.value.raw))) {
      const line = src.slice(0, node.start).split('\n').length
      review.push(`${file}:${line}: ${src.slice(node.start, node.end).slice(0, 90)}`)
    }
    const wasInside = insideJSX
    const wasCode = inCode
    if (node.type === 'JSXElement' || node.type === 'JSXFragment') insideJSX = true
    if (node.type === 'JSXElement' && ['pre', 'code'].includes(node.openingElement?.name?.name)) inCode = true
    for (const [k, v] of Object.entries(node)) {
      if (k === 'parent' || k === 'start' || k === 'end') continue
      if (v && typeof v === 'object') walk(v, node, curAttr)
    }
    insideJSX = wasInside
    inCode = wasCode
  }
  let insideJSX = false
  let inCode = false
  walk(ast.body, null, undefined)

  if (edits.length === 0) continue
  if (!/import \{[^}]*\bt\b[^}]*\} from '[^']*lib\/i18n'/.test(src)) {
    let rel = relative(dirname(file), 'src/lib/i18n').replaceAll('\\', '/')
    if (!rel.startsWith('.')) rel = './' + rel
    const imports = ast.body.filter((n) => n.type === 'ImportDeclaration')
    const at = imports.length ? imports[imports.length - 1].end : 0
    edits.push([at, at, `\nimport { t } from '${rel}'`])
  }
  edits.sort((a, b) => b[0] - a[0])
  let out = src
  for (const [s, e, r] of edits) out = out.slice(0, s) + r + out.slice(e)
  writeFileSync(file, out)
  console.log(`${file}: ${edits.length} textos`)
  for (const r of review) console.log('  revisar ' + r)
}
