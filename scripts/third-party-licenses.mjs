// Gera THIRD_PARTY_LICENSES.md com as licenças de tudo o que vai embutido no
// binário: as bibliotecas Go e as do painel (só as de produção).
// Uso: node scripts/third-party-licenses.mjs  (precisa de "npm ci" em web/)
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const licenseFile = (dir) =>
  readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.(md|txt))?$/i.test(f) || /^licen[cs]e-mit/i.test(f))

const out = ['# Licenças de terceiros', '',
  'O HeimdallDNS é distribuído sob a licença MIT (arquivo LICENSE). O binário inclui as bibliotecas abaixo, cada uma com a licença própria.', '']

// Go: só os módulos usados pelo binário.
const goMods = execFileSync('go', ['list', '-deps', '-f', '{{if .Module}}{{.Module.Path}}\t{{.Module.Version}}\t{{.Module.Dir}}{{end}}', './cmd/heimdalldns'], { encoding: 'utf8' })
const seen = new Set()
const entries = []
for (const line of goMods.split('\n')) {
  const [path, version, dir] = line.split('\t')
  if (!path || path.startsWith('github.com/ugoneiva/') || seen.has(path)) continue
  seen.add(path)
  const f = dir && licenseFile(dir)
  entries.push({ name: path, version, text: f ? readFileSync(join(dir, f), 'utf8') : '(licença não encontrada no módulo)' })
}

// Painel: dependências de produção (o que vai no pacote JS embutido).
const tree = JSON.parse(execFileSync('npm', ['ls', '--omit=dev', '--all', '--json', '--long'], { cwd: 'web', encoding: 'utf8' }))
const walk = (deps) => {
  for (const [name, d] of Object.entries(deps ?? {})) {
    if (!d.path || seen.has(name) || name.startsWith('@types/')) continue
    seen.add(name)
    const f = existsSync(d.path) && licenseFile(d.path)
    entries.push({ name, version: d.version, text: f ? readFileSync(join(d.path, f), 'utf8') : `Licença: ${d.license ?? '?'}` })
    walk(d.dependencies)
  }
}
walk(tree.dependencies)

entries.sort((a, b) => a.name.localeCompare(b.name))
for (const e of entries) {
  out.push(`## ${e.name} ${e.version ?? ''}`.trim(), '', '```', e.text.trim(), '```', '')
}
writeFileSync('THIRD_PARTY_LICENSES.md', out.join('\n'))
console.log(`${entries.length} componentes`)
