# HeimdallDNS no Wazuh

> As regras seguem o formato dos eventos e as armadilhas conhecidas do Wazuh (campos estáticos, ordem das regras irmãs), mas **ainda não foram passadas pelo `wazuh-logtest` num manager real**. Faça isso antes de usar em produção (passo 3).

## 1. Ligar a exportação no HeimdallDNS

```yaml
export:
  file: /var/log/heimdalldns/events.json   # lido pelo agente do Wazuh
  # syslog: udp://IP-DO-MANAGER:514        # ou direto no manager, sem agente
  queries: none                            # none, blocked ou all (além dos alertas)
```

O arquivo gira sozinho ao passar de 50 MB (mantém um `.1`). O usuário do Wazuh precisa conseguir ler o arquivo; com a unit do systemd (`DynamicUser`), crie o diretório com `LogsDirectory=heimdalldns` ou ajuste as permissões.

## 2. Agente: ler o arquivo

Em `/var/ossec/etc/ossec.conf` do agente (na máquina do HeimdallDNS):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/heimdalldns/events.json</location>
</localfile>
```

Para syslog direto no manager, a seção `<remote>` precisa aceitar o IP do HeimdallDNS (`<allowed-ips>`). O Wazuh decodifica o JSON depois do cabeçalho syslog.

## 3. Manager: regras

```sh
cp heimdalldns_rules.xml /var/ossec/etc/rules/
/var/ossec/bin/wazuh-logtest   # cole uma linha do events.json e confira a regra
systemctl restart wazuh-manager
```

| ID | Nível | Quando |
|---|---|---|
| 112402 | 3 | consulta bloqueada (só com `queries: blocked`/`all`) |
| 112411 | 10 | acesso bloqueado por lista de ameaças (MITRE T1071.004) |
| 112412 | 12 | possível malware com DGA (T1568.002) |
| 112413 | 12 | possível túnel/exfiltração por DNS (T1071.004, T1048) |
| 112414 | 14 | túnel com muitos subdomínios **e** rajada de TXT |
| 112415 | 7 | domínio recém-registrado (T1583.001) |
| 112416 | 10 | domínio registrado há menos de 7 dias |
| 112417 | 4 | dispositivo novo na rede |
| 112420 | 14 | o HeimdallDNS isolou o dispositivo automaticamente |
| 112430 | 3 | operação administrativa registrada na auditoria |
| 112431 | 8 | alteração no Active Directory feita pelo HeimdallDNS (T1098) |
| 112432 | 10 | AD: usuário criado/excluído ou senha redefinida (T1136.002, T1098) |
| 112433 | 6 | operação administrativa recusada (travas, permissão, senha do backup, política de senha do AD) |
| 112434 | 8 | restauração de backup, reinício pelo painel ou importação do Pi-hole |
| 112435 | 8 | servidores DNS de saída (upstreams) trocados: confira se foi você |
| 112436 | 5 | backup baixado (leva hash da senha e tokens) |
| 112437 | 6 | login recusado no painel (senha, MFA, conta desativada ou sem grupo do AD) |
| 112438 | 10 | 6 logins recusados do mesmo IP em 2 min: força bruta (MITRE T1110) |
| 112440 | 7 | ação barrada pelo papel (conta ou token fora do escopo; MITRE T1078) |
| 112439 | 8 | conta do painel criada, alterada (papel, senha, MFA, desativação) ou excluída; token de API criado |


## Exemplo de evento

```json
{"timestamp":"2026-10-04T14:20:31Z","app":"heimdalldns","event_type":"security","event_id":42,
 "kind":"dga","severity":"high","summary":"Notebook do financeiro consultou 12 domínios com cara de gerados…",
 "domain":"","srcip":"192.168.0.23","client":{"id":"37aa59f0","name":"Notebook do financeiro","ip":"192.168.0.23"},
 "count":1,"response":"isolated","details":{"distinct":12,"examples":["qmklcwprgtbn.com","…"]}}
```
