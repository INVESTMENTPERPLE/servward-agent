#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Alta de un servidor Linux en NtfyControl: broker + agente + ntfyctl,
# con topics ÚNICOS, en una sola pasada.
#
#   sudo bash deploy/add_server_linux.sh <nombre> [token]
#
#   <nombre>  identificador corto → define topics cmd-<nombre> / resp-<nombre>
#   [token]   token compartido; si se omite, se genera uno y se muestra al final
#
# Requiere tener el repo (con server.py y agent_linux.py ACTUALIZADOS) en esta
# máquina. Distro con apt + systemd.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
[ "$EUID" -eq 0 ] || { echo "Ejecuta con sudo:  sudo bash deploy/add_server_linux.sh [nombre] [token]"; exit 1; }

NAME="${1:-$(hostname -s 2>/dev/null || hostname)}"; TOKEN="${2:-}"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$REPO/server.py" ] && [ -f "$REPO/agent_linux.py" ] || { echo "No encuentro server.py/agent_linux.py en $REPO"; exit 1; }

# Idempotente: si ya existe el env, es una ACTUALIZACIÓN → conservar token y topics.
ENVF=/etc/ntfy/ntfy.env
unit_env() { systemctl show "$1" -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }
if [ -f "$ENVF" ]; then
  echo "==> Ya configurado: actualizo código y conservo token/topics."
  TOKEN="$(grep -E '^NTFY_TOKEN='       "$ENVF" | cut -d= -f2- || true)"
  CMD_TOPIC="$(grep -E '^NTFY_CMD_TOPIC='  "$ENVF" | cut -d= -f2- || true)"
  RESP_TOPIC="$(grep -E '^NTFY_RESP_TOPIC=' "$ENVF" | cut -d= -f2- || true)"
  # Modelo viejo: los topics estaban en el unit, no en el env → léelos de ahí.
  [ -n "$TOKEN" ]      || TOKEN="$(unit_env ntfy-server NTFY_TOKEN)"
  [ -n "$CMD_TOPIC" ]  || CMD_TOPIC="$(unit_env ntfy-agent NTFY_CMD_TOPIC)"
  [ -n "$RESP_TOPIC" ] || RESP_TOPIC="$(unit_env ntfy-agent NTFY_RESP_TOPIC)"
  [ -n "$CMD_TOPIC" ]  || CMD_TOPIC="cmd-$NAME"
  [ -n "$RESP_TOPIC" ] || RESP_TOPIC="resp-$NAME"
else
  [ -n "$TOKEN" ] || TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  CMD_TOPIC="cmd-$NAME"; RESP_TOPIC="resp-$NAME"
fi

echo "==> 1/5 dependencias"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true                          # un repo de terceros roto no debe abortar
  apt-get install -y -qq python3 python3-psutil || true
fi

echo "==> 2/5 usuario + código en /opt/ntfy"
id ntfy >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin ntfy
install -d -o ntfy -g ntfy /opt/ntfy
install -o ntfy -g ntfy -m 644 "$REPO/server.py"       /opt/ntfy/server.py
install -o ntfy -g ntfy -m 644 "$REPO/agent_linux.py"  /opt/ntfy/agent_linux.py
install -m 755 "$REPO/deploy/ntfyctl" /opt/ntfy/ntfyctl
ln -sf /opt/ntfy/ntfyctl /usr/local/bin/ntfyctl

echo "==> 3/5 env /etc/ntfy/ntfy.env"
install -d -m 750 /etc/ntfy
cat > /etc/ntfy/ntfy.env <<EOF
NTFY_TOKEN=$TOKEN
NTFY_BIND=127.0.0.1
NTFY_PORT=2586
NTFY_CERT=/dev/null/nocert
NTFY_KEY=/dev/null/nokey
NTFY_SERVER=http://127.0.0.1:2586
NTFY_CMD_TOPIC=$CMD_TOPIC
NTFY_RESP_TOPIC=$RESP_TOPIC
EOF
chown root:ntfy /etc/ntfy/ntfy.env; chmod 640 /etc/ntfy/ntfy.env

echo "==> 4/5 servicios systemd"
cat > /etc/systemd/system/ntfy-server.service <<'EOF'
[Unit]
Description=NtfyControl broker (HTTP/SSE)
After=network-online.target
Wants=network-online.target
[Service]
User=ntfy
Group=ntfy
WorkingDirectory=/opt/ntfy
ExecStart=/usr/bin/python3 /opt/ntfy/server.py
EnvironmentFile=/etc/ntfy/ntfy.env
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/ntfy-agent.service <<'EOF'
[Unit]
Description=NtfyControl Linux agent
After=network-online.target ntfy-server.service
Wants=network-online.target
[Service]
User=ntfy
Group=ntfy
WorkingDirectory=/opt/ntfy
EnvironmentFile=/etc/ntfy/ntfy.env
ExecStart=/usr/bin/python3 /opt/ntfy/agent_linux.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

echo "==> 5/5 arranque"
systemctl daemon-reload
systemctl enable --now ntfy-server ntfy-agent
sleep 1
ntfyctl status || true

cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Servidor "$NAME" montado (broker + agente + ntfyctl).

En la app → Ajustes → Añadir servidor:
  Nombre     : $NAME
  Órdenes    : $CMD_TOPIC
  Respuestas : $RESP_TOPIC
  Token      : $TOKEN
  URL        : según cómo lo expongas ↓

Exponer (elige UNO):
  • Tailscale (fácil): instala tailscale; URL = http://100.x.x.x:2586
  • Cloudflare: añade un ingress al túnel → http://127.0.0.1:2586 ; URL = https://tu-host

Para los botones de Reiniciar/Parar servicios necesitas además:
  - quitar NoNewPrivileges del agente (este script ya no lo pone), y
  - un sudoers para 'ntfy' (ver /etc/sudoers.d/ntfy-agent del primer Linux).
────────────────────────────────────────────────────────────────────
EOF
