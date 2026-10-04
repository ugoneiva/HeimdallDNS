#!/bin/sh
# Antes de remover (não roda na atualização do .deb/.rpm).
set -e
case "$1" in
	upgrade|1) exit 0 ;; # deb: upgrade; rpm: ainda resta uma versão instalada
esac
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl disable --now heimdalldns >/dev/null 2>&1 || true
fi
