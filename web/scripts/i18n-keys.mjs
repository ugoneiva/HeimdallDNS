// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Lista as chaves de t('…') e, com --missing, só as que faltam em i18n/en.ts.
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseAst } from 'rolldown/parseAst'
import { en } from '../src/i18n/en.ts'

const files = []
const walkDir = (d) => {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    if (e.isDirectory()) walkDir(join(d, e.name))
    else if (/\.(tsx?|mts)$/.test(e.name) && !e.name.endsWith('.d.ts') && d !== 'src/i18n') files.push(join(d, e.name))
  }
}
walkDir('src')
const keys = new Set()
for (const f of files) {
  const src = readFileSync(f, 'utf8')
  const ast = parseAst(src, { lang: f.endsWith('x') ? 'tsx' : 'ts' })
  const walk = (n) => {
    if (!n || typeof n !== 'object') return
    if (Array.isArray(n)) return n.forEach(walk)
    if (n.type === 'CallExpression' && n.callee?.name === 't' && n.arguments[0]?.type === 'Literal') keys.add(n.arguments[0].value)
    for (const [k, v] of Object.entries(n)) if (k !== 'start' && k !== 'end' && v && typeof v === 'object') walk(v)
  }
  walk(ast.body)
}
const missing = process.argv.includes('--missing')
const out = [...keys].filter((k) => !missing || !(k in en)).sort()
for (const k of out) console.log(JSON.stringify(k))
if (missing && out.length) {
  console.error(`${out.length} textos sem tradução para o inglês`)
  process.exit(1)
}
