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
- **Active Directory** (opcional): usuários, grupos, DNS do AD e auditoria; veja abaixo.
- **DNS:** upstreams (predefinições cifradas ou próprios, trocados na hora, com latência e saúde de cada um) e registros locais A/AAAA/CNAME.
- **Configurações:** tema, a própria senha e verificação em duas etapas; para administradores, também usuários, tokens de API, backup e restauração, migração do Pi-hole e auditoria.

**Primeiro acesso:**
1. Ao abrir o painel sem nenhuma conta, ele pede um **código de configuração** que o serviço imprime no log (`journalctl -u heimdalldns | grep codigo`). Assim, ninguém da rede cria o administrador antes do dono.
2. As senhas ficam guardadas com bcrypt.
3. A sessão é um cookie `HttpOnly`/`SameSite=Strict`, válido por 7 dias, guardado no banco só como hash.
4. As alterações exigem a mesma origem do painel, e as tentativas de senha têm limite por IP.

**Usuários e papéis:** cada pessoa entra com a própria conta. Em **Configurações → Usuários**, o administrador cria contas e escolhe o papel:

| Papel | Pode |
|---|---|
| Administrador | tudo: configuração, listas, DNS, usuários, tokens, backup, Active Directory |
| Operador | ver tudo e operar: isolar e liberar aparelhos, regras por aparelho, reconhecer alertas, bloquear/liberar pelo log, reservas de DHCP |
| Leitura | só ver |

- **O servidor confere o papel em toda requisição.** A tela só esconde o que a pessoa não pode fazer.
- **Mudanças que derrubam as sessões da conta:** mudar o papel, desativar, redefinir a senha ou zerar o MFA.
- **O último administrador ativo nunca sai:** não pode ser rebaixado, desativado nem excluído.
- **Login recusado:** a mensagem é a mesma para usuário inexistente e senha errada, para não revelar quais contas existem.
- **Atualização de versão antiga:** a senha única de antes vira o usuário `admin`, com o mesmo MFA.

**Verificação em duas etapas (MFA):** por conta, em **Configurações**. Leia o QR code num app autenticador (TOTP, RFC 6238) e confirme com um código. Depois disso:
- o login pede o código só para quem tem MFA;
- um código não vale duas vezes;
- desligar pede a senha e um código.

O MFA é obrigatório para alterar o Active Directory pelo painel.

**Tokens de API:** em **Configurações → Tokens de API**, para integrações como Grafana, scripts e automação.
- Cada token tem nome, papel e validade (30 dias, 90 dias, 1 ano ou sem vencer).
- O token aparece uma vez só; o banco guarda o hash, e a lista mostra só o começo dele.
- Uso: `Authorization: Bearer hdns_…`.
- O token do serviço (`<data_dir>/api.token`) continua sendo o da CLI, do console de MSP e da alta disponibilidade.

**Auditoria:** fica registrado:
- toda alteração (por quem, de onde e com que resultado);
- todo login, aceito ou recusado;
- toda tentativa barrada pelo papel.

A lista aparece em **Configurações → Auditoria** e vai para o SIEM com a exportação ligada (regras do Wazuh 112430 a 112440, inclusive detecção de força bruta).

Esqueceu a senha? `sudo heimdalldns passwd -user nome` (padrão: `admin`). Perdeu o autenticador? Um administrador zera o MFA em **Usuários**, ou `sudo heimdalldns mfa-off -user nome`. Para listar as contas: `sudo heimdalldns users`.

As listas e regras criadas pelo painel ficam no banco e se somam às do arquivo de configuração. As do arquivo aparecem no painel só para leitura.

### Grupos de dispositivos e horários

Em **Dispositivos → Grupos e horários**, crie grupos como Crianças, Visitantes ou Financeiro. Cada grupo tem:
- **Regras fixas:** domínios, serviços (`service:tiktok`, `service:social`…) e regex;
- **Horários:** dias da semana e faixa de horário.
  - A faixa pode passar da meia-noite (22:00 às 07:00).
  - Cada horário tem regras próprias ou **pausa total**, que bloqueia toda a internet menos o que for liberado (ex.: o site da escola em horário de aula).
- **Listas globais:** aplicadas ou não.

Na janela de cada aparelho, escolha o grupo. A ordem numa consulta:
1. regras do próprio aparelho;
2. horários ativos do grupo;
3. regras do grupo;
4. listas globais.

O log mostra a regra que decidiu (ex.: `horário noite: service:tiktok`). Os horários seguem o fuso do servidor e valem na hora, sem reiniciar.

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


**Limite de consultas por cliente** (`dns.rate_limit`): padrão de 100 consultas/s por IP, com rajada de 1000. Acima disso:
- a resposta é REFUSED, com o status "limitada" no log;
- sai um alerta `query_flood` por minuto (regra Wazuh 112418), e o alerta pode isolar o aparelho sozinho.

Pega aparelho infectado ou em loop sem afetar os outros. O loopback nunca é limitado; libere em `exempt` o roteador, se ele repassa a rede inteira por um IP só. O custo é de ~18 ns por consulta.

**DNSSEC:** o HeimdallDNS é um encaminhador; quem valida as assinaturas é o upstream.
- **Teste:** a cada partida e a cada 6 h, cada upstream é testado. O domínio `dnssec-failed.org`, com assinatura quebrada de propósito, tem que dar SERVFAIL, e um domínio assinado tem que voltar validado (bit AD).
- **Resultado:** aparece na tela DNS.
- **`upstream.require_dnssec: true`:** usa só os upstreams que validam. Se nenhum validar, usa todos e avisa no log.

Cloudflare, Quad9 e Google validam.
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

- **Modelos de política**, aplicados em vários clientes de uma vez:
  - listas de bloqueio (acrescentadas se faltarem);
  - regras (somadas às do cliente);
  - grupos de dispositivos (criados ou atualizados pelo nome);
  - upstreams e opções de segurança (por exemplo, isolar sozinho quem acessar domínio de ameaça).

  Aplicar só acrescenta: listas e regras próprias de cada cliente continuam. O resultado aparece por cliente, com o que mudou ou o erro. Réplicas recusam (aplique no principal), e cada aplicação entra na auditoria do console.

O console guarda o token da API de todos os clientes: rode-o numa rede de gerência (a VPN de cada cliente) e com HTTPS.

### Active Directory (opcional)

Gerencia o AD pelo painel: compatível principalmente com o **AD do Windows Server** e também com o **Samba AD** (testado contra um controlador Samba 4.25 de laboratório).

- **Usuários:** busca, situação (ativo, desabilitado, bloqueado, privilegiado), último logon; criar, habilitar/desabilitar, desbloquear, redefinir senha (com "trocar no próximo logon") e excluir.
- **Grupos:** membros de qualquer grupo; colocar e tirar usuários **só dos grupos liberados**.
- **DNS do AD:** zonas integradas (DomainDnsZones, ForestDnsZones e as antigas em System) e seus registros; criar e apagar **A, AAAA, CNAME e PTR**, gravados direto nos objetos `dnsNode` do AD (o mesmo formato que o console DNS do Windows usa).
- **Dispositivos:** a janela do aparelho mostra o computador do AD com o mesmo nome (sistema, OU, último logon no domínio).
- **Auditoria:** toda alteração, aceita ou recusada, fica registrada (quem, de onde, o quê) e vai para o SIEM com a exportação ligada. Senhas nunca são registradas.

**Travas, por padrão do mais seguro:**
- começa **só leitura**; alterações exigem `ad.write: true` **e** MFA ligado no painel;
- usuários só são alterados dentro das OUs de `ad.user_ous`; grupos só os de `ad.managed_groups`; DNS só nas zonas de `ad.dns_zones`;
- contas e grupos privilegiados (Domain Admins, Enterprise Admins, Administrators, Schema Admins, operadores, `krbtgt`, contas com `adminCount=1`…) **nunca** são alterados, mesmo que estejam na lista;
- a raiz da zona, os registros de serviço (`_ldap`, `_kerberos`…), `DomainDnsZones`/`ForestDnsZones` e os nomes dos controladores de domínio nunca são alterados; `_msdcs` é sempre só leitura;
- conexão só por **LDAPS** (`ldaps://`, porta 636) ou StartTLS: senha não trafega aberta.

**Preparando no Windows:**
1. **Conta de serviço** dedicada (ex.: `svc-heimdall`), sem ser Domain Admin. Dê permissão só onde precisa, pelo *Delegation of Control Wizard* (Usuários e Computadores do AD → botão direito na OU → Delegar controle): "Criar, excluir e gerenciar contas de usuário", "Redefinir senhas" e "Modificar a associação de um grupo" na OU liberada. Para o DNS, adicione a conta ao grupo `DnsAdmins` ou dê permissão de escrita na zona (console DNS → Propriedades da zona → Segurança).
2. **LDAPS:** o controlador precisa de um certificado de servidor (AD CS ou outro emissor); sem ele a porta 636 não responde. Aponte `ad.ca_file` para a CA que emitiu o certificado.
3. **Tempo do DNS:** o serviço DNS do Windows relê o AD periodicamente; um registro novo pode levar alguns minutos para responder (no Samba é imediato).

A senha da conta de serviço fica num arquivo à parte (`ad.bind_password_file`, permissão 600), nunca no YAML.

**Entrar no painel com a conta do AD** (`ad.login`):
- **Senha:** a pessoa usa o usuário e a senha do domínio (`joao`, `joao@empresa.local` ou `EMPRESA\joao`). O HeimdallDNS confere fazendo bind com a própria conta dela; senha vazia é sempre recusada, porque viraria um bind anônimo.
- **Papel:** vem dos grupos do AD, inclusive grupos dentro de grupos, e é recalculado a cada login. A ordem é `admin_groups`, depois `operator_groups`, depois `viewer_groups`. Quem não está em nenhum desses grupos não entra.
- **MFA:** com `require_mfa: true` (padrão), a conta cadastra o MFA no primeiro acesso, antes de ver qualquer dado.
- **Conta local com o mesmo nome:** nunca é usada pelo AD.

### API e linha de comando

API REST em `127.0.0.1:8053`, com token. Por padrão o token é gerado em `<data_dir>/api.token`.

```sh
heimdalldns clients                                   # lista os dispositivos
heimdalldns name 192.168.0.23 "TV da sala"
heimdalldns rules "TV da sala" -deny service:social,service:tiktok
heimdalldns isolate "TV da sala" -mode refused -reason "beacon suspeito" -except windowsupdate.com
heimdalldns release "TV da sala"
heimdalldns status
heimdalldns backup -encrypt -o copia.tar.gz.age       # backup cifrado na hora
heimdalldns restore copia.tar.gz.age -restart         # restaura e reinicia
```

`<ref>` aceita id, IP, MAC ou nome. Em produção, rode com `sudo` (o token fica no diretório de dados do serviço).

| Rota | Função |
|---|---|
| `GET/PUT /api/dns/upstream` · `DELETE` | upstreams em uso (`servers`, `mode`); `DELETE` volta aos do arquivo |
| `GET/PUT /api/dns/local` | registros locais (`records`: `name`, `type` A/AAAA/CNAME, `value`) |
| `POST /api/backup` | gera e baixa um backup (`full`, `passphrase`) |
| `GET/POST /api/backups` · `GET /api/backups/{nome}` | cópias automáticas: lista, gera agora, baixa |
| `GET/POST/DELETE /api/restore` · `POST /api/restart` | restauração em duas etapas (multipart `passphrase` + `file`) e reinício |
| `POST /api/import/pihole` · `POST /api/import/pihole/{id}/apply` | prévia do Teleporter (multipart `file`) e aplicação das partes escolhidas |
| `GET/POST /api/users` · `PATCH/DELETE /api/users/{id}` | contas do painel: criar, papel, desativar, redefinir senha, zerar MFA (`reset_mfa`) |
| `GET/POST /api/tokens` · `DELETE /api/tokens/{id}` | tokens de API (`name`, `role`, `expires_days`); o token só volta na criação |
| `GET /api/audit` | auditoria: alterações, logins e tentativas barradas (`range`, `limit`) |
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

## Instalação

### Por pacote (recomendado)

Cada versão publica pacotes para **amd64, arm64 e armv7** (Raspberry Pi 3/4/5):

```sh
# Debian, Ubuntu, Raspberry Pi OS
sudo apt install ./heimdalldns_0.1.0_amd64.deb
# Fedora, RHEL, Rocky, Alma
sudo dnf install ./heimdalldns-0.1.0-1.x86_64.rpm
# Arch
sudo pacman -U heimdalldns-0.1.0-1-x86_64.pkg.tar.zst

sudo systemctl enable --now heimdalldns
journalctl -u heimdalldns | grep codigo     # código do primeiro acesso
```

Depois, abra `https://<ip-do-servidor>:8053`. O pacote instala:

| Arquivo | O que é |
|---|---|
| `/usr/bin/heimdalldns` | o binário (estático, sem dependências) |
| `/etc/heimdalldns/heimdalldns.yaml` | configuração mínima, **preservada nas atualizações** |
| `/usr/lib/systemd/system/heimdalldns.service` | o serviço, sem root, só com a permissão da porta 53 |
| `/usr/share/doc/heimdalldns/` | README e a configuração completa comentada |
| `/usr/share/heimdalldns/wazuh/` | regras para o Wazuh |

- **Atualização:** o pacote reinicia o serviço sozinho se ele estiver rodando.
- **Remoção:** os dados ficam em `/var/lib/private/heimdalldns`.
- **Porta 53 ocupada:** no Ubuntu, Debian e Fedora, o `systemd-resolved` ocupa `127.0.0.53:53`. Desligue o ouvinte dele (`DNSStubListener=no` em `/etc/systemd/resolved.conf`) ou ponha só o IP da rede em `dns.listen`. Se esquecer, o HeimdallDNS explica isso no erro.

Cada versão também traz `checksums.txt` assinado (cosign, sem chave, pela identidade do GitHub Actions) e SBOM (SPDX) de cada arquivo.

### Docker

```sh
docker run -d --name heimdalldns --network host -v heimdalldns:/data \
  --restart unless-stopped ghcr.io/ugoneiva/heimdalldns:latest
```

- **`--network host`:** sem ela, o radar vê o IP do Docker em vez do IP de cada aparelho.
- **Usuário:** a imagem roda sem root e sem shell (distroless).
- **Configuração própria:** monte por cima de `/etc/heimdalldns/heimdalldns.yaml`.

### Manual

```sh
make build
sudo install -m 755 bin/heimdalldns /usr/bin/
sudo install -D -m 644 packaging/heimdalldns.yaml /etc/heimdalldns/heimdalldns.yaml
sudo install -m 644 deploy/heimdalldns.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now heimdalldns
```

`systemctl reload heimdalldns` baixa as listas de novo.

### Primeiro acesso

1. O painel pede o código de configuração impresso no log e a senha nova.
2. Em seguida abre um **assistente**, que aparece só numa instalação nova:
   - para onde as consultas vão (Cloudflare, Quad9, Google, AdGuard ou servidores próprios; sempre cifrado);
   - quais listas de bloqueio usar;
   - importar um Pi-hole;
   - como apontar a rede para o HeimdallDNS.

**HTTPS do painel:** com `api.tls_cert: auto` (padrão do pacote), o HeimdallDNS gera um certificado autoassinado em `<data_dir>/panel.crt` para o nome da máquina e os IPs dela, e renova antes de vencer. O navegador pede para aceitar o certificado uma vez. Com certificado próprio, informe `tls_cert` e `tls_key`.

### Migrar do Pi-hole

No Pi-hole, gere o backup em **Settings → Teleporter → Export**: a v6 gera um `.zip`, a v5 um `.tar.gz`. No HeimdallDNS, use **Configurações → Migrar do Pi-hole** ou o próprio assistente.

O painel mostra uma prévia, e você escolhe o que trazer:

| Do Pi-hole | Vira aqui |
|---|---|
| Adlists | listas de bloqueio, inclusive as desativadas |
| Domínios exatos (allow/deny) | regras próprias: aqui, um domínio vale também para os subdomínios |
| Regex | `(\.|^)x\.com$` vira `x.com`; as demais vão como regex RE2. Opções do Pi-hole (`;querytype=`) ficam de fora, com aviso |
| Local DNS (A/AAAA e CNAME) | registros locais (tela DNS) |
| DHCP estático | reservas de DHCP |
| Upstreams | opcional: substituem os atuais |
| Comentários dos clientes | nomes dos aparelhos já vistos aqui |

Não têm equivalente e são avisados na prévia:
- as listas de liberação;
- os grupos do Pi-hole (aqui, use as regras por dispositivo).

### Backup e restauração

- **Cópias automáticas diárias** em `<data_dir>/backups`, as 7 mais novas: banco sem o histórico de consultas, mais o arquivo de configuração. Ajuste em `backup:`.
- **Backup na hora:**
  - pelo painel, em **Configurações → Backup**;
  - pela CLI, com `sudo heimdalldns backup -encrypt` (`-full` inclui o histórico).

  A senha cifra o arquivo no formato [age](https://age-encryption.org); dá para abrir também com `age -d`. Use sempre senha: o backup leva o hash da senha do painel e os tokens dos aparelhos. As sessões abertas nunca vão no backup.
- **Restauração:**
  - pelo painel;
  - pela CLI, com `sudo heimdalldns restore arquivo.tar.gz.age -restart`.

  Passo a passo:
  1. O servidor confere o arquivo (integridade e versão do banco).
  2. O arquivo fica pronto e vale no reinício. O reinício é feito pelo próprio processo, sem precisar do systemd.
  3. O banco anterior fica guardado como `heimdall.db.antes-<data>`.
  4. O arquivo de configuração do backup não é aplicado sozinho: ele fica em `/etc`, que o serviço não pode alterar.

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
internal/backup     backup (tar.gz, cifra age), restauração em duas etapas, cópias automáticas
internal/pihole     leitura do Teleporter do Pi-hole (v5 e v6)
internal/console    console de MSP: leitura dos clientes, fila de alertas e modelos de política
internal/ad         Active Directory: LDAPS, usuários, grupos e DNS (dnsNode) com travas
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


**Idiomas:** o painel está em português e inglês.
- **Escolha:** em Configurações → Aparência ou na tela de login. O padrão segue o idioma do navegador.
- **Chaves:** os textos passam por `t('…')`, com o português como chave. A tradução fica em `web/src/i18n/en.ts`, e as datas e números seguem o idioma escolhido.
- **Texto novo:** marque com `t('…')`. O `node scripts/i18n-wrap.mjs arquivo.tsx` marca automaticamente, e o `npm run i18n` lista o que falta traduzir (falha se faltar algo).
## Próximas etapas

1. Publicar a versão 0.1 (tag `v0.1.0`; o workflow gera pacotes, imagem e assinaturas).

## Licença

O HeimdallDNS é software livre, sob a [licença MIT](LICENSE): pode usar, copiar, modificar, distribuir e vender, inclusive em produtos fechados, desde que mantenha o aviso de autoria.

As bibliotecas embutidas no binário (Go e o painel) são todas de licenças abertas e compatíveis (BSD, MIT, Apache-2.0, ISC, Unlicense). Os textos delas estão em [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md), que vai junto em todos os pacotes. Depois de mudar dependências, rode `make licenses`.
