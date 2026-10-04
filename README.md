# HeimdallDNS

Servidor DNS com filtro de bloqueio, no estilo do Pi-hole, escrito em Go, com funções mais avançadas: radar de dispositivos, isolamento por cliente e dashboard em tempo real.

> **Estado:** em desenvolvimento. MVP completo: motor DNS, radar de dispositivos, histórico, log ao vivo e painel web.

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

### Histórico e tempo real

- **Gravação sem travar o DNS:**
  - cada consulta vai para um agregador por um canal sem bloqueio;
  - as linhas são gravadas no SQLite em lote, uma vez por segundo;
  - se o disco não acompanhar, só as linhas detalhadas são descartadas (e contadas em `/api/status`); os resumos nunca perdem contagem.
- **Resumos:**
  - por minuto e por dispositivo (total, encaminhadas, cache, bloqueadas, isoladas, erros, latência);
  - domínios mais consultados e mais bloqueados por hora.
  - Os gráficos leem os resumos e respondem em milissegundos mesmo com milhões de consultas.
- **Retenção separada:** as consultas detalhadas ficam 7 dias, os resumos 90 dias; a limpeza roda de hora em hora.
- **Tempo real (SSE):**
  - log ao vivo com filtros por dispositivo, status, tipo e texto, que descarta o excedente para um navegador lento em vez de atrasar o DNS;
  - tráfego segundo a segundo.

### Painel web

Embutido no próprio binário, em `http://127.0.0.1:8053` por padrão. Tema escuro (padrão) e claro.

- **Visão geral:**
  - tráfego ao vivo segundo a segundo;
  - consultas, % bloqueado, % cache, latência média e dispositivos ativos;
  - gráfico do período, com visão em tabela;
  - domínios mais consultados e mais bloqueados, dispositivos mais ativos;
  - latência e saúde de cada upstream.
- **Dispositivos:**
  - radar dos ativos e tabela com busca e filtros;
  - interruptor **Acesso** que isola na hora;
  - janela de detalhes com resumo de 24 h, regras por dispositivo (com botões por serviço: TikTok, YouTube, redes sociais…), isolamento com modo, motivo e exceções, renomear e esquecer.
- **Consultas:**
  - log **ao vivo** (SSE) com filtros por dispositivo, resultado, tipo e texto;
  - pausar e retomar;
  - **Bloquear/Liberar** o domínio direto da linha;
  - modo **Histórico** com paginação.
- **Listas e regras:**
  - listas de bloqueio (adicionar, ativar/desativar, remover, sugestões de listas conhecidas);
  - regras próprias globais;
  - teste **"o que acontece com este domínio?"**, global ou por dispositivo, mostrando a regra que decide.
- **Configurações:** tema, troca de senha, informações do servidor e sair.

**Primeiro acesso:**
1. Ao abrir o painel sem senha definida, ele pede um **código de configuração** que o serviço imprime no log (`journalctl -u heimdalldns | grep codigo`). Assim, ninguém da rede define a senha antes do dono.
2. A senha fica guardada com bcrypt.
3. A sessão é um cookie `HttpOnly`/`SameSite=Strict`, válido por 7 dias, guardado no banco só como hash.
4. As alterações exigem a mesma origem do painel, e as tentativas de senha têm limite por IP.

Esqueceu a senha? `sudo heimdalldns passwd`.

As listas e regras criadas pelo painel ficam no banco e se somam às do arquivo de configuração. As do arquivo aparecem no painel só para leitura.

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
| `GET /api/lists` · `POST /api/lists` · `PATCH`/`DELETE /api/lists/{id}` · `POST /api/lists/refresh` | listas de bloqueio |
| `GET /api/rules` · `PUT /api/rules` · `POST /api/rules/quick` | regras próprias globais; `quick` bloqueia/libera um domínio |
| `GET /api/filter/test?name=&client=` | qual regra decide um domínio (global ou para um dispositivo) |
| `POST /api/auth/password` | troca a senha do painel (com o token, não pede a atual) |
| `GET /api/queries` | histórico: `range`/`from`/`to`, `client`, `status`, `type`, `q`, `limit`, `before` (paginação) |
| `GET /api/queries/live` | **SSE** do log ao vivo, com os mesmos filtros (evento `query`; `dropped` se o navegador não acompanhar) |
| `GET /api/stats/summary` | totais do período, % bloqueado, % cache, latência média, dispositivos ativos |
| `GET /api/stats/timeseries` | série para os gráficos (`step` automático: 1 min a 1 dia) |
| `GET /api/stats/top` | `kind=domains`, `blocked` ou `clients` |
| `GET /api/stats/realtime` · `GET /api/stats/live` | tráfego por segundo (JSON e **SSE**, evento `tick`) |

No filtro `status`, `blocked` inclui os isolados, `allowed` junta encaminhadas, cache e locais, e `cached` inclui as respostas vencidas servidas. O `range` aceita `30m`, `24h`, `7d` etc. Nas rotas `/live`, o token também pode ir na URL (`?token=`), porque o `EventSource` do navegador não envia cabeçalhos.

## Desempenho medido

Num notebook de 20 núcleos:

| Medida | Resultado |
|---|---|
| Decisão de bloqueio | ~50 ns por consulta, sem alocação (500 mil domínios) |
| Carga das listas StevenBlack + HaGeZi Pro (~300 mil regras) | 109 ms |
| Memória com essas listas e o radar | ~60 MB |
| Consultas servidas do cache, com o radar ligado | ~200 mil/s, 0 falhas (log de consultas desligado) |
| Idem, gravando **cada consulta** no histórico (1 milhão em 6,7 s) | ~149 mil/s, 0 consultas perdidas |
| Resumo e rankings com 1,2 milhão de consultas no banco | ~5 ms |
| Busca por texto no histórico detalhado (1,2 milhão de linhas) | ~0,5 s |
| Espaço em disco do histórico detalhado | ~120 bytes por consulta |
| Primeira consulta depois de ligar | ~20 ms (as conexões DoH/DoT já abrem no início) |
| Com a lista HaGeZi Threat Intelligence (48 MB, ~2,57 milhões de regras no total) | carga em ~0,8 s, ~92 MB de memória |
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
internal/querylog   agregador, resumos, log ao vivo e tráfego por segundo
internal/store      SQLite: clientes, consultas, resumos, retenção
internal/api        API REST, login do painel e arquivos do painel
internal/webui      painel compilado, embutido no binário (gerado por "make web")
web/                código do painel: React + Vite + Tailwind + TanStack + Recharts
deploy/             unit do systemd
```

## Desenvolvimento do painel

```sh
make web       # instala as dependências e compila o painel para internal/webui/dist
make web-dev   # painel com recarga automática; a API vem de um heimdalldns em 127.0.0.1:8053
```

O painel compilado vai no repositório, então `make build` (ou `go install`) funciona sem Node.

## Próximas etapas

1. Recursos de segurança: domínios recém-registrados, detecção de DGA e túnel DNS, exportação para o Wazuh.
2. Servidor DoH/DoT próprio (proteção fora da rede) e DHCP opcional.
3. Dois nós com sincronização (HA) e console multi-tenant para MSP.
