# HeimdallDNS

Servidor DNS com filtro de bloqueio, no estilo do Pi-hole, escrito em Go, com funções mais avançadas: radar de dispositivos, isolamento por cliente e dashboard em tempo real.

> **Estado:** em desenvolvimento. O motor DNS e o radar de dispositivos estão prontos; o histórico, o log ao vivo e o dashboard vêm a seguir.

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

### Radar de dispositivos

- **Descoberta automática:**
  - cada IP que consulta vira um dispositivo, com primeira e última vez visto, consultas e bloqueios;
  - nome reverso (PTR) perguntado ao roteador;
  - **MAC** pela tabela ARP/NDP e **fabricante** pela base OUI (baixada do Wireshark);
  - MAC aleatório de celular reconhecido como "MAC privado".
- **Identidade pelo MAC:**
  - se o DHCP troca o IP, o dispositivo continua o mesmo, com nome, regras e histórico;
  - os vários endereços IPv6 de um aparelho entram juntos;
  - um IP reaproveitado por outro aparelho vira um dispositivo novo.
- **Isolar (kill switch):**
  - corta o DNS do dispositivo com REFUSED, NXDOMAIN, `null` ou drop;
  - aceita exceções (por exemplo o domínio de atualização do antivírus) e um motivo registrado;
  - vale também para os registros locais.
- **Regras por dispositivo:**
  - bloqueios e exceções próprios, que valem antes das listas globais;
  - opção de não aplicar as listas globais naquele dispositivo;
  - catálogo de serviços: `service:tiktok`, `service:youtube`, ou grupos como `service:social`, `service:streaming`, `service:mensagens`, `service:jogos`.
- **Persistência:** tudo fica em SQLite (Go puro, sem CGO) e sobrevive a reinícios.

### API e linha de comando

API REST em `127.0.0.1:8053`, com token. Por padrão o token é gerado em `<data_dir>/api.token`.

```sh
heimdalldns clients                                   # lista os dispositivos
heimdalldns name 192.168.0.23 "TV da sala"
heimdalldns rules "TV da sala" -deny service:social,service:tiktok
heimdalldns isolate "TV da sala" -mode refused -reason "beacon suspeito" -except windowsupdate.com
heimdalldns release "TV da sala"
heimdalldns status
```

`<ref>` aceita id, IP, MAC ou nome. Em produção, rode com `sudo` (o token fica no diretório de dados do serviço).

| Rota | Função |
|---|---|
| `GET /api/status` | contadores, cache, upstreams, regras |
| `GET /api/clients` · `GET /api/clients/{ref}` | dispositivos |
| `PATCH /api/clients/{ref}` | `name`, `allow`, `deny`, `skip_global_lists` |
| `POST /api/clients/{ref}/isolate` | `mode`, `reason`, `exceptions` |
| `POST /api/clients/{ref}/release` | tira do isolamento |
| `DELETE /api/clients/{ref}` | esquece o dispositivo |
| `GET /api/services` | catálogo de serviços |
| `GET /api/lists` · `POST /api/lists/refresh` | listas de bloqueio |

## Desempenho medido

Num notebook de 20 núcleos:

| Medida | Resultado |
|---|---|
| Decisão de bloqueio | ~50 ns por consulta, sem alocação (500 mil domínios) |
| Carga das listas StevenBlack + HaGeZi Pro (~300 mil regras) | 109 ms |
| Memória com essas listas e o radar | ~60 MB |
| Consultas servidas do cache, com o radar ligado | ~200 mil/s, 0 falhas (log de consultas desligado) |
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
internal/clients    radar: descoberta, MAC/fabricante, PTR, isolamento e regras
internal/store      SQLite (clientes; depois o histórico)
internal/api        API REST com token
deploy/             unit do systemd
```

## Próximas etapas

1. **Histórico:** SQLite com gravação em lote e resumos por minuto.
2. **Log ao vivo (SSE)** e rotas de estatísticas para os gráficos.
3. **Dashboard:** React + Vite + Tailwind + shadcn/ui, embutido no binário.
