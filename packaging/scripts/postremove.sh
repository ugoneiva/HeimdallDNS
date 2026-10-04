#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
# Os dados ficam em /var/lib/heimdalldns (o systemd guarda em /var/lib/private
# com DynamicUser). Para apagar tudo: rm -rf /var/lib/private/heimdalldns
