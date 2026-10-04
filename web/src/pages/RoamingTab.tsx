import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, Download, KeyRound, RefreshCw, Trash } from 'lucide-react'
import { api } from '../api'
import type { Device, DeviceAccess } from '../types'
import { Button, ErrorNote } from '../components/ui'

function CopyField({ label, value }: { label: string; value: string }) {
  const [done, setDone] = useState(false)
  return (
    <div>
      <p className="mb-1 text-xs font-medium text-ink-2">{label}</p>
      <div className="flex gap-2">
        <code className="min-w-0 flex-1 truncate rounded-lg border border-line-strong bg-surface-2 px-3 py-2 font-mono text-xs text-ink" title={value}>
          {value}
        </code>
        <Button
          size="sm"
          className="h-auto"
          icon={done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value)
              setDone(true)
              setTimeout(() => setDone(false), 1500)
            } catch {
              /* sem acesso à área de transferência: o texto continua selecionável */
            }
          }}
        >
          {done ? 'Copiado' : 'Copiar'}
        </Button>
      </div>
    </div>
  )
}

export function RoamingTab({ d }: { d: Device }) {
  const qc = useQueryClient()
  const key = ['access', d.id]
  const access = useQuery({ queryKey: key, queryFn: () => api<DeviceAccess>(`/api/clients/${encodeURIComponent(d.id)}/access`) })
  const mut = useMutation({
    mutationFn: (method: 'POST' | 'DELETE') => api<DeviceAccess>(`/api/clients/${encodeURIComponent(d.id)}/token`, { method }),
    onSuccess: (a) => {
      qc.setQueryData(key, a)
      qc.invalidateQueries({ queryKey: ['clients'] })
    },
  })
  const [confirmRevoke, setConfirmRevoke] = useState(false)
  const a = access.data
  if (!a) return <p className="text-xs text-muted">Carregando…</p>

  if (!a.doh && !a.dot) {
    return (
      <div className="space-y-3 text-xs leading-relaxed text-ink-2">
        <p>
          O DNS criptografado (DoH/DoT) ainda não está ligado neste servidor. Com ele, este aparelho continua com as regras dele mesmo
          fora da rede (4G, hotel, casa).
        </p>
        <p>Para ligar, use um nome público apontando para o servidor e um certificado, no heimdalldns.yaml:</p>
        <pre className="overflow-x-auto rounded-lg bg-surface-2 p-3 font-mono text-[11px] text-ink">{`dns:
  public_host: dns.suaempresa.com.br
  doh_listen: ":443"
  dot_listen: [":853"]
  acme: true            # certificado automático (Let's Encrypt)
  acme_email: ti@suaempresa.com.br`}</pre>
        <p>Para o DoT por aparelho (Android), crie também o registro DNS curinga *.dns.suaempresa.com.br.</p>
      </div>
    )
  }

  if (!a.token) {
    return (
      <div className="space-y-4">
        <p className="text-xs leading-relaxed text-ink-2">
          Gere um acesso exclusivo para este aparelho. Ele passa a usar o HeimdallDNS de qualquer lugar, com as regras, o isolamento e os
          alertas dele. Quem tiver o endereço consegue usar o DNS como este aparelho: trate como uma senha.
        </p>
        <ErrorNote error={mut.error} />
        <Button variant="primary" icon={<KeyRound className="size-4" />} loading={mut.isPending} onClick={() => mut.mutate('POST')}>
          Gerar acesso para fora da rede
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <div className="space-y-3">
        {a.doh_url && <CopyField label="DNS por HTTPS (DoH)" value={a.doh_url} />}
        {a.dot_host && <CopyField label="DNS por TLS (DoT) — nome do host" value={a.dot_host} />}
      </div>

      <div className="space-y-2.5 rounded-lg border border-line p-4 text-xs leading-relaxed text-ink-2">
        <p className="font-semibold text-ink">Como configurar</p>
        {a.dot_host && (
          <p>
            <strong className="text-ink">Android 9 ou mais novo:</strong> Configurações → Rede e internet → DNS privado → Nome do host do
            provedor de DNS particular → <code className="font-mono text-ink">{a.dot_host}</code>
          </p>
        )}
        {a.doh_url && (
          <>
            <p>
              <strong className="text-ink">iPhone, iPad e Mac:</strong> baixe o perfil abaixo no próprio aparelho e instale em Ajustes →
              Perfil Baixado. O sistema avisa que o perfil não é verificado; é esperado.
            </p>
            <p>
              <strong className="text-ink">Windows 11:</strong> Configurações → Rede e Internet → (sua conexão) → Atribuição de servidor DNS
              → Manual → Criptografia de DNS por HTTPS: <em>Ativado (modelo manual)</em> com o endereço DoH acima.
            </p>
            <p>
              <strong className="text-ink">Chrome, Edge e Firefox:</strong> Configurações → Privacidade → DNS seguro → Personalizado → o
              endereço DoH acima (vale só para o navegador).
            </p>
          </>
        )}
      </div>

      <ErrorNote error={mut.error} />
      <div className="flex flex-wrap gap-2">
        {a.doh_url && (
          <a
            href={`/api/clients/${encodeURIComponent(d.id)}/mobileconfig`}
            download
            className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-accent px-3.5 text-sm font-medium text-accent-ink hover:brightness-110"
          >
            <Download className="size-4" aria-hidden />
            Perfil para iPhone/Mac
          </a>
        )}
        <Button icon={<RefreshCw className="size-4" />} loading={mut.isPending && mut.variables === 'POST'} onClick={() => mut.mutate('POST')}>
          Trocar endereço
        </Button>
        <Button
          variant={confirmRevoke ? 'danger' : 'ghost'}
          icon={<Trash className="size-4" />}
          loading={mut.isPending && mut.variables === 'DELETE'}
          onBlur={() => setConfirmRevoke(false)}
          onClick={() => (confirmRevoke ? mut.mutate('DELETE') : setConfirmRevoke(true))}
        >
          {confirmRevoke ? 'Confirmar: revogar' : 'Revogar acesso'}
        </Button>
      </div>
      <p className="text-[11px] text-muted">
        Trocar ou revogar invalida o endereço antigo na hora; o aparelho precisa ser configurado de novo.
      </p>
    </div>
  )
}
