# HeimdallDNS

Servidor DNS com filtro de bloqueio, no estilo do Pi-hole, escrito em Go, com funções mais avançadas: radar de dispositivos, isolamento por cliente e dashboard em tempo real.

> **Estado:** em desenvolvimento. O motor DNS (etapa 1 do MVP) está pronto; o radar de clientes, a API e o dashboard vêm a seguir.

## O que já funciona

- **DNS em UDP e TCP**, com controle de acesso por rede (por padrão só as redes privadas, para não virar resolvedor aberto).
- **Upstreams criptografados**: DoH, DoT, DoQ e DNSCrypt, além do DNS comum (via [`dnsproxy`](https://github.com/AdguardTeam/dnsproxy)).
  - Modos `fastest` (menor latência medida, com failover), `parallel` e `failover`.
  - Teste de saúde periódico com a latência de cada upstream.
- **Cache em memória (LRU):**
  - respeita o TTL de cada registro e guarda também as respostas negativas (RFC 2308);
  - serve a resposta vencida enquanto renova (RFC 8767);
  - consultas iguais simultâneas viram uma ida só ao upstream.
- **Listas de bloqueio** nos formatos hosts, domínios e Adblock (`||dominio^`, exceções `@@`, `/regex/`):
  - download automático com cópia local, então o serviço sobe sem rede;
  - atualização periódica ou por `SIGHUP`;
  - troca das regras sem travar as consultas.
- **Regras próprias** (`deny` / `allow`) e **registros locais** (A/AAAA).
- **Modos de bloqueio:** `null` (0.0.0.0 / ::), `nxdomain`, `refused` e `drop`. As respostas bloqueadas levam o Extended DNS Error 15 (*Blocked*, RFC 8914).

## Desempenho medido

Num notebook de 20 núcleos:

| Medida | Resultado |
|---|---|
| Decisão de bloqueio | ~50 ns por consulta, sem alocação (500 mil domínios) |
| Carga das listas StevenBlack + HaGeZi Pro (~300 mil regras) | 109 ms |
| Memória com essas listas | ~47 MB |
| Consultas servidas do cache | ~120 mil/s, 0 falhas |
| Resposta do cache / bloqueio | ~35 µs |

## Uso rápido

```sh
make build
./bin/heimdalldns -config heimdalldns.example.yaml -listen 127.0.0.1:25353 -data-dir ./data
dig @127.0.0.1 -p 25353 doubleclick.net
```

Opções da linha de comando:

| Opção | Efeito |
|---|---|
| `-config` | Arquivo YAML (padrão `/etc/heimdalldns/heimdalldns.yaml`) |
| `-listen` | Endereços DNS, separados por vírgula; substitui `dns.listen` |
| `-data-dir` | Diretório de dados; substitui `data_dir` |
| `-version` | Mostra a versão |

A configuração comentada está em [`heimdalldns.example.yaml`](heimdalldns.example.yaml).

## Instalação como serviço

```sh
make build
sudo install -m 755 bin/heimdalldns /usr/local/bin/
sudo install -D -m 644 heimdalldns.example.yaml /etc/heimdalldns/heimdalldns.yaml
sudo install -m 644 deploy/heimdalldns.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now heimdalldns
```

A unit roda o serviço sem root (`DynamicUser`), só com a permissão de abrir a porta 53. `systemctl reload heimdalldns` baixa as listas de novo.

## Estrutura

```
cmd/heimdalldns     ponto de entrada
internal/config     configuração YAML e validação
internal/server     atendimento DNS: acesso, locais, filtro, cache, upstream
internal/filter     leitura das listas, regras e atualização
internal/cache      cache LRU com TTL, negativo e serve-stale
internal/upstream   DoH/DoT/DoQ, escolha do melhor e saúde
deploy/             unit do systemd
```

## Próximas etapas

1. **Radar de clientes:**
   - descoberta de dispositivos (IP, PTR, MAC pela tabela ARP, fabricante);
   - isolamento com um clique (REFUSED/NXDOMAIN/drop);
   - regras por cliente.
2. **Histórico:** SQLite com gravação em lote e resumos por minuto.
3. **API REST e log ao vivo** (SSE).
4. **Dashboard:** React + Vite + Tailwind + shadcn/ui, embutido no binário.
