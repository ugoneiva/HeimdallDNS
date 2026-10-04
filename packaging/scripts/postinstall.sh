#!/bin/sh
# Depois de instalar ou atualizar o pacote.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	if systemctl is-active --quiet heimdalldns; then
		systemctl restart heimdalldns || true
		exit 0
	fi
fi
cat <<'MSG'

HeimdallDNS instalado.

  1. Confira /etc/heimdalldns/heimdalldns.yaml (a porta 53 não pode estar
     ocupada pelo systemd-resolved; veja o comentário no arquivo).
  2. sudo systemctl enable --now heimdalldns
  3. Abra https://<ip-deste-servidor>:8053 e informe o código de configuração:
     journalctl -u heimdalldns | grep codigo

MSG
