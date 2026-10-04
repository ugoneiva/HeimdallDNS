# HeimdallDNS

Servidor DNS com filtro de bloqueio, no estilo do Pi-hole, escrito em Go, com funções mais avançadas: radar de dispositivos, isolamento por cliente e dashboard em tempo real.

> **Estado:** em desenvolvimento. MVP completo (motor DNS, radar, histórico, log ao vivo, painel web), detecções de segurança com exportação para o Wazuh, DNS criptografado (DoT/DoH) para aparelhos dentro e fora da rede DHCP opcional, alta disponibilidade (principal e réplicas) e console multi-tenant para MSP.

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

### Segurança

| Detecção | Como funciona | Gravidade |
|---|---|---|
| **Domínio malicioso bloqueado** | Listas marcadas como `category: threat` (por exemplo, HaGeZi Threat Intelligence): o bloqueio vira alerta | Alta |
| **Malware com DGA** | Um dispositivo consulta 10 ou mais domínios com cara de gerados por algoritmo que **não existem** (NXDOMAIN) em 10 min: o padrão de malware procurando o servidor de comando | Alta |
| **Túnel DNS** | Em 5 min, 50 ou mais subdomínios únicos de média ≥ 20 caracteres sob o mesmo domínio, ou rajada de TXT | Alta (crítica com os dois) |
| **Domínio recém-registrado** | Data de registro consultada por **RDAP direto no registro do TLD** (mapa oficial da IANA), uma vez por domínio, com cache. Modo alerta ou bloqueio | Média (alta se tiver menos de 7 dias) |
| **Dispositivo novo** | Aparelho desconhecido na rede. Avisa só depois de procurar o MAC, para um aparelho conhecido que trocou de IP não parecer novo | Baixa |

Como as detecções se comportam:
- **Deduplicação:** o mesmo alerta (tipo, dispositivo e domínio) em 1 hora soma na contagem em vez de criar linhas.
- **Isolamento automático** (opcional, por tipo): contém o dispositivo na hora. O alerta registra que o isolamento foi automático.
- **Exceções:** domínios ignorados podem ser cadastrados pelo painel. CDNs, nuvens e serviços de reputação por DNS (antivírus, listas de spam) já são ignorados no túnel DNS.
- **Exportação:** JSON por linha (`export.file`) e/ou syslog RFC 5424 (`export.syslog`), opcionalmente com as consultas. Regras do Wazuh prontas em [`deploy/wazuh/`](deploy/wazuh/README.md).

Limites conhecidos:
- **DGA:** a detecção é heurística, não pega DGA "de dicionário" (que junta palavras reais) e depende dos NXDOMAIN.
- **Domínio recém-registrado:** no modo bloqueio, o **primeiro** acesso a um domínio ainda desconhecido passa enquanto a data é consultada.
- **TLDs sem RDAP:** ficam sem idade.

### DNS criptografado e aparelhos fora da rede

O HeimdallDNS atende **DoT** (RFC 7858, porta 853) e **DoH** (RFC 8484, GET e POST, HTTP/2), além do DNS comum.

Com isso, cada aparelho pode ganhar no painel um **endereço próprio** (Dispositivos → Fora da rede). Usando esse endereço, o aparelho continua com **as regras, o isolamento e os alertas dele** em qualquer rede: 4G, hotel, casa.

| Onde | Como o aparelho se identifica |
|---|---|
| DoH | `https://dns.suaempresa.com.br/dns-query/<token>` |
| DoT (DNS privado do Android) | `<token>.dns.suaempresa.com.br` (nome do host; precisa do registro DNS curinga `*.dns.suaempresa.com.br`) |
| iPhone, iPad, Mac | perfil `.mobileconfig` gerado pelo painel, que liga o DoH com um toque |

Regras de acesso:
- **Sem token:** valem as mesmas redes permitidas do DNS comum.
- **Com token válido:** o aparelho é aceito de qualquer IP. O IP público não entra na lista de IPs do aparelho, porque atrás de um NAT ele é de muita gente.
- **Trocar ou revogar o token** invalida o endereço antigo na hora.

Certificado:
- **Em arquivo** (`dns.tls_cert`/`tls_key`): recarregado sozinho quando o certbot renova.
- **Automático** (`dns.acme: true`): Let's Encrypt pelo desafio TLS-ALPN-01 na porta 443, emitindo também `<token>.host` para os tokens válidos.

### DHCP (opcional)

Servidor DHCPv4 embutido, **desligado por padrão**. Antes de ligar, desligue o DHCP do roteador: dois servidores DHCP na mesma rede brigam.

- **Configuração entregue:** cada aparelho recebe IP, máscara, roteador, este servidor como DNS, domínio e prazo.
- **Endereços:** o aparelho tende a voltar ao mesmo IP. Há reservas por MAC (inclusive fora da faixa), feitas pelo painel ou pelo botão "Fixar IP" na concessão.
- **Mensagens tratadas:** DISCOVER, REQUEST (com NAK para pedido indevido e silêncio quando o cliente escolheu outro servidor), renovação, RELEASE, DECLINE (o IP em conflito fica fora por 10 min) e INFORM.
- **Radar:** MAC e nome vêm direto da concessão. Aparelhos que **nunca consultam o DNS** também aparecem (com zero consultas), o que denuncia DNS fixo em outro servidor, um jeito de escapar do filtro.
- **DNS local:** `notebook-da-ana.lan` resolve sozinho, com reverso (PTR).

A porta 67 exige `CAP_NET_BIND_SERVICE` e `CAP_NET_RAW`; veja a unit em `deploy/`.

### Alta disponibilidade

Dois (ou mais) HeimdallDNS: um **principal** e **réplicas**. Entregue todos como servidores DNS; se um cair, os aparelhos usam o outro.

- **Sincronização:**
  - a réplica faz *long-poll* no principal, então uma mudança chega em cerca de 1 s (medido: um isolamento passou a valer no DNS da réplica em 196 ms);
  - sincroniza listas e regras do painel, configurações de segurança, dispositivos (nome, regras, isolamento, token de fora da rede) e a senha do painel;
  - o mesmo aparelho tem **o mesmo id** nos dois nós: a réplica adota o id do principal, casando por MAC ou IP.
- **Fica em cada nó:** histórico, contadores, alertas e sessões do painel. O DHCP deve rodar num nó só.
- **Réplica só leitura:** ela recusa alterações de configuração, apontando o principal. Pode reconhecer os próprios alertas e atualizar as próprias listas.
- **Principal fora do ar:** a réplica continua atendendo com a última configuração e volta a sincronizar sozinha. O painel mostra o estado dos dois lados.
- **Segurança:** o snapshot inclui o hash da senha e os tokens dos aparelhos. Use um `sync_token` forte e HTTPS na API (ou uma rede de gerência).

### Console de MSP (vários clientes)

```sh
heimdalldns console -listen 127.0.0.1:8070 -data-dir /var/lib/heimdalldns-console [-tls-cert … -tls-key …]
```

- **Painel próprio:** o mesmo binário, com login próprio. No primeiro acesso, o código de configuração sai no log, como no painel normal.
- **Clientes:** cada cliente é um HeimdallDNS cadastrado pela URL da API e pelo token dele (`api.token`). O console testa a conexão antes de salvar.
- **Leitura a cada 30 s**, com um cartão por cliente:
  - no ar ou fora do ar (com o erro e o último contato);
  - consultas e % bloqueado em 24 h;
  - dispositivos ativos;
  - alertas abertos por gravidade;
  - upstreams sem resposta;
  - versão, tempo ligado e papel na alta disponibilidade.
- **Alertas de todos os clientes numa fila só**, os mais graves primeiro, com **reconhecer** repassado ao cliente.

O console guarda o token da API de todos os clientes: rode-o numa rede de gerência (a VPN de cada cliente) e com HTTPS.

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
| `POST`/`DELETE /api/clients/{ref}/token` · `GET …/access` · `GET …/mobileconfig` | endereço fora da rede do aparelho e perfil da Apple |
| `GET /api/ha` · `GET /api/sync/snapshot` | estado da alta disponibilidade; snapshot para as réplicas (token `ha.sync_token`, long-poll) |
| `GET /api/dhcp` · `POST /api/dhcp/reservations` · `DELETE /api/dhcp/reservations/{mac}` | concessões, configuração e reservas do DHCP |
| `GET /api/security/events` · `GET /api/security/summary` | alertas (filtros `status`, `kind`, `client`, `range`) e contagens |
| `POST /api/security/events/{id}/ack` · `…/reopen` | reconhece ou reabre (`{id}` = `all` reconhece todos) |
| `GET`/`PUT /api/security/settings` · `POST /api/security/ignore` | detecções, isolamento automático e domínios ignorados |
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
internal/detect     detecções de DGA, túnel DNS e listas de ameaças
internal/nrd        idade dos domínios via RDAP (bootstrap da IANA)
internal/security   alertas: deduplicação, isolamento automático, configurações
internal/export     exportação JSON/syslog para SIEM
internal/dnsname    domínio registrável (Public Suffix List, só regras ICANN)
internal/tlsconf    certificado do DoT/DoH: arquivo com recarga ou ACME
internal/dhcp       servidor DHCPv4: concessões, reservas, DNS local
internal/ha         alta disponibilidade: snapshot, long-poll e aplicação na réplica
internal/console    console de MSP: leitura dos clientes e fila única de alertas
internal/api        API REST, login do painel e arquivos do painel
internal/webui      painel compilado, embutido no binário (gerado por "make web")
web/                código do painel: React + Vite + Tailwind + TanStack + Recharts
deploy/             unit do systemd e regras do Wazuh
```

## Desenvolvimento do painel

```sh
make web       # instala as dependências e compila o painel para internal/webui/dist
make web-dev   # painel com recarga automática; a API vem de um heimdalldns em 127.0.0.1:8053
```

O painel compilado vai no repositório, então `make build` (ou `go install`) funciona sem Node.

## Próximas etapas

1. Pacotes de instalação (.deb, .rpm, AUR, imagem Docker) e versão 0.1.
