import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Clock, Plus, Trash, Users } from 'lucide-react'
import { api } from '../api'
import type { DeviceGroup, GroupSchedule } from '../types'
import { useCan } from '../lib/auth'
import { Button, Card, ErrorNote, Field, Input, LabeledSwitch, Modal, StatusBadge, Textarea, cx } from '../components/ui'
import { t } from '../lib/i18n'

export function useGroups() {
  return useQuery({ queryKey: ['groups'], queryFn: () => api<DeviceGroup[]>('/api/groups'), refetchInterval: 30_000 })
}

const dayNames = [t('Dom'), t('Seg'), t('Ter'), t('Qua'), t('Qui'), t('Sex'), t('Sáb')]
const lines = (s: string) =>
  s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

function describe(s: GroupSchedule): string {
  const days = !s.days?.length || s.days.length === 7 ? t('todo dia') : s.days.map((d) => dayNames[d]).join(', ')
  const hours = s.start === s.end ? t('o dia inteiro') : `${s.start}–${s.end}`
  return `${days}, ${hours}`
}

export function GroupsCard() {
  const qc = useQueryClient()
  const admin = useCan('admin')
  const groups = useGroups()
  const [editing, setEditing] = useState<DeviceGroup | null>(null)
  const save = useMutation({
    mutationFn: (all: DeviceGroup[]) =>
      api<DeviceGroup[]>('/api/groups', {
        method: 'PUT',
        // O servidor não aceita os campos calculados (membros e ativos).
        body: { groups: all.map(({ members: _m, active: _a, ...g }) => g) },
      }),
    onSuccess: (d) => {
      qc.setQueryData(['groups'], d)
      qc.invalidateQueries({ queryKey: ['clients'] })
      setEditing(null)
    },
  })
  const list = groups.data ?? []
  const upsert = (g: DeviceGroup) => save.mutate(g.id ? list.map((x) => (x.id === g.id ? g : x)) : [...list, g])
  return (
    <Card
      title={t('Grupos e horários')}
      subtitle={t('Regras para vários aparelhos de uma vez: Crianças, Visitantes, Financeiro…')}
      actions={
        admin ? (
          <Button size="sm" variant="primary" icon={<Plus className="size-3.5" />} onClick={() => setEditing({ id: '', name: '', schedules: [], members: [], active: [] })}>
            {t('Novo grupo')}
          </Button>
        ) : undefined
      }
    >
      <ErrorNote error={groups.error || save.error} />
      {list.length === 0 ? (
        <p className="text-xs text-muted">
          {t('Nenhum grupo. Crie um, defina o que bloquear (sempre ou em horários) e escolha o grupo na janela de cada aparelho.')}
        </p>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((g) => (
            <li key={g.id} className="rounded-lg border border-line p-3">
              <div className="mb-1.5 flex items-center gap-2">
                <Users className="size-4 text-muted" aria-hidden />
                <span className="flex-1 font-medium text-ink">{g.name}</span>
                <span className="text-xs text-muted">{g.members.length}{' '}{t('aparelho(s)')}</span>
              </div>
              {g.description && <p className="mb-1.5 text-xs text-ink-2">{g.description}</p>}
              <p className="text-xs text-ink-2">
                {(g.deny?.length ?? 0) > 0 ? t('Sempre bloqueia: {regras}', { regras: g.deny!.join(', ') }) : t('Sem bloqueio fixo')}
                {g.skip_global_lists ? t(' · sem as listas globais') : ''}
              </p>
              {(g.schedules ?? []).length > 0 && (
                <ul className="mt-2 space-y-1">
                  {g.schedules!.map((s) => (
                    <li key={s.name} className="flex items-center gap-1.5 text-xs text-ink-2">
                      <Clock className="size-3.5 shrink-0 text-muted" aria-hidden />
                      <span className="flex-1">
                        <strong className="text-ink">{s.name}</strong> · {describe(s)} · {s.block_all ? t('pausa total') : (s.deny ?? []).join(', ')}
                      </span>
                      {s.disabled ? (
                        <StatusBadge tone="neutral">{t('desligado')}</StatusBadge>
                      ) : g.active.includes(s.name) ? (
                        <StatusBadge tone="warning">{t('valendo agora')}</StatusBadge>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
              {admin && (
                <div className="mt-2 flex justify-end">
                  <Button size="sm" variant="ghost" onClick={() => setEditing(g)}>
                    {t('Editar')}
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <GroupEditor
        group={editing}
        onClose={() => setEditing(null)}
        onSave={upsert}
        onDelete={(g) => save.mutate(list.filter((x) => x.id !== g.id))}
        saving={save.isPending}
        error={save.error}
      />
    </Card>
  )
}

const emptySchedule = (): GroupSchedule => ({ name: '', start: '22:00', end: '07:00', days: [], deny: ['service:social'] })

function GroupEditor({ group, onClose, onSave, onDelete, saving, error }: {
  group: DeviceGroup | null
  onClose: () => void
  onSave: (g: DeviceGroup) => void
  onDelete: (g: DeviceGroup) => void
  saving: boolean
  error: unknown
}) {
  const [g, setG] = useState<DeviceGroup | null>(group)
  const [deny, setDeny] = useState('')
  const [confirmDel, setConfirmDel] = useState(false)
  useEffect(() => {
    setG(group)
    setDeny((group?.deny ?? []).join('\n'))
    setConfirmDel(false)
  }, [group])
  if (!g) return null
  const setSched = (i: number, s: GroupSchedule) => setG({ ...g, schedules: (g.schedules ?? []).map((x, j) => (j === i ? s : x)) })
  return (
    <Modal open={!!group} onClose={onClose} title={g.id ? t('Grupo {nome}', { nome: g.name }) : t('Novo grupo')} wide>
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          onSave({ ...g, deny: lines(deny) })
        }}
      >
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('Nome')}>
            <Input value={g.name} onChange={(e) => setG({ ...g, name: e.target.value })} required placeholder={t('Crianças')} />
          </Field>
          <Field label={t('Descrição')}>
            <Input value={g.description ?? ''} onChange={(e) => setG({ ...g, description: e.target.value })} />
          </Field>
        </div>
        <Field label={t('Sempre bloquear (um por linha)')} hint={t('Domínio (com subdomínios), service:tiktok, service:social, /regex/…')}>
          <Textarea rows={3} value={deny} onChange={(e) => setDeny(e.target.value)} placeholder={t('service:jogos\napostas.com')} />
        </Field>
        <LabeledSwitch
          checked={!g.skip_global_lists}
          onChange={(v) => setG({ ...g, skip_global_lists: !v })}
          label={t('Aplicar também as listas de bloqueio globais')}
        />

        <div>
          <div className="mb-2 flex items-center">
            <p className="flex-1 text-xs font-semibold text-ink">{t('Horários')}</p>
            <Button size="sm" variant="ghost" icon={<Plus className="size-3.5" />} onClick={() => setG({ ...g, schedules: [...(g.schedules ?? []), emptySchedule()] })}>
              {t('Adicionar horário')}
            </Button>
          </div>
          <div className="space-y-3">
            {(g.schedules ?? []).map((s, i) => (
              <ScheduleEditor
                key={i}
                s={s}
                onChange={(ns) => setSched(i, ns)}
                onRemove={() => setG({ ...g, schedules: (g.schedules ?? []).filter((_, j) => j !== i) })}
              />
            ))}
            {(g.schedules ?? []).length === 0 && <p className="text-xs text-muted">{t('Sem horários: as regras acima valem o tempo todo.')}</p>}
          </div>
        </div>

        <ErrorNote error={error} />
        <div className="flex items-center justify-between gap-2">
          {g.id ? (
            <Button
              variant={confirmDel ? 'danger' : 'ghost'}
              icon={<Trash className="size-4" />}
              onClick={() => (confirmDel ? onDelete(g) : setConfirmDel(true))}
            >
              {confirmDel ? t('Confirmar: os aparelhos ficam sem grupo') : t('Excluir grupo')}
            </Button>
          ) : (
            <span />
          )}
          <Button type="submit" variant="primary" loading={saving}>
            {t('Salvar')}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

function ScheduleEditor({ s, onChange, onRemove }: { s: GroupSchedule; onChange: (s: GroupSchedule) => void; onRemove: () => void }) {
  const days = s.days ?? []
  const toggleDay = (d: number) => onChange({ ...s, days: days.includes(d) ? days.filter((x) => x !== d) : [...days, d].sort() })
  return (
    <div className={cx('space-y-3 rounded-lg border border-line p-3', s.disabled && 'opacity-60')}>
      <div className="grid gap-2 sm:grid-cols-[1fr_110px_110px_auto]">
        <Input value={s.name} onChange={(e) => onChange({ ...s, name: e.target.value })} placeholder={t('nome (ex.: noite)')} aria-label={t('Nome do horário')} required />
        <Input type="time" value={s.start} onChange={(e) => onChange({ ...s, start: e.target.value })} aria-label={t('Início')} required />
        <Input type="time" value={s.end} onChange={(e) => onChange({ ...s, end: e.target.value })} aria-label={t('Fim')} required />
        <Button variant="ghost" aria-label={t('Remover horário')} icon={<Trash className="size-4" />} onClick={onRemove} />
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {dayNames.map((n, d) => (
          <button
            key={n}
            type="button"
            aria-pressed={days.includes(d)}
            onClick={() => toggleDay(d)}
            className={cx(
              'rounded-full border px-2.5 py-1 text-xs',
              days.includes(d) ? 'border-accent bg-accent-soft text-ink' : 'border-line-strong text-ink-2',
            )}
          >
            {n}
          </button>
        ))}
        <span className="text-[11px] text-muted">{days.length === 0 ? t('nenhum marcado = todo dia') : ''}{' '}{t('· fim antes do início passa da meia-noite')}</span>
      </div>
      <LabeledSwitch checked={!!s.block_all} onChange={(v) => onChange({ ...s, block_all: v })} label={t('Pausa total: bloqueia toda a internet nesse horário (menos os liberados abaixo)')} />
      <div className="grid gap-3 sm:grid-cols-2">
        {!s.block_all && (
          <Field label={t('Bloquear nesse horário')}>
            <Textarea rows={2} value={(s.deny ?? []).join('\n')} onChange={(e) => onChange({ ...s, deny: lines(e.target.value) })} placeholder={t('service:social')} />
          </Field>
        )}
        <Field label={t('Liberar nesse horário')}>
          <Textarea rows={2} value={(s.allow ?? []).join('\n')} onChange={(e) => onChange({ ...s, allow: lines(e.target.value) })} placeholder={t('escola.edu.br')} />
        </Field>
      </div>
      <LabeledSwitch checked={!s.disabled} onChange={(v) => onChange({ ...s, disabled: !v })} label={t('Horário ligado')} />
    </div>
  )
}
