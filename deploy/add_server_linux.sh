#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Alta de un servidor Linux en Servward: broker + agente + ntfyctl,
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
  TOKEN_RO="$(grep -E '^NTFY_TOKEN_RO=' "$ENVF" | cut -d= -f2- || true)"
  [ -n "$CMD_TOPIC" ]  || CMD_TOPIC="cmd-$NAME"
  [ -n "$RESP_TOPIC" ] || RESP_TOPIC="resp-$NAME"
else
  [ -n "$TOKEN" ] || TOKEN="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  CMD_TOPIC="cmd-$NAME"; RESP_TOPIC="resp-$NAME"
fi
[ -n "${TOKEN_RO:-}" ] || TOKEN_RO="$(openssl rand -hex 32 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

echo "==> 1/5 dependencias"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq || true                          # un repo de terceros roto no debe abortar
  apt-get install -y -qq python3 python3-psutil python3-qrcode || true
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
NTFY_TOKEN_RO=$TOKEN_RO
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
Description=Servward broker (HTTP/SSE)
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
Description=Servward Linux agent
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
systemctl enable ntfy-server ntfy-agent
# restart (no solo enable --now) para que las ACTUALIZACIONES carguen el código nuevo
systemctl restart ntfy-server ntfy-agent

# ── Helper de auto-actualización (para "actualizar el agente desde la app") ──
# Script root-owned (no editable por 'ntfy') + regla sudoers acotada SOLO a él.
cat > /usr/local/sbin/servward-update <<'UPD'
#!/usr/bin/env bash
set -euo pipefail
REPO="https://github.com/INVESTMENTPERPLE/servward-agent.git"
SRC=/opt/servward-src
if [ -d "$SRC/.git" ]; then
  git -C "$SRC" remote set-url origin "$REPO"
  git -C "$SRC" fetch origin -q
  git -C "$SRC" reset --hard origin/main -q
else
  rm -rf "$SRC"; git clone --depth 1 "$REPO" "$SRC"
fi
install -o ntfy -g ntfy -m 644 "$SRC/server.py"      /opt/ntfy/server.py
install -o ntfy -g ntfy -m 644 "$SRC/agent_linux.py" /opt/ntfy/agent_linux.py
install -m 755 "$SRC/deploy/ntfyctl" /opt/ntfy/ntfyctl
systemctl restart ntfy-server ntfy-agent
UPD
chown root:root /usr/local/sbin/servward-update
chmod 700 /usr/local/sbin/servward-update
printf 'ntfy ALL=(root) NOPASSWD: /usr/local/sbin/servward-update\n' > /etc/sudoers.d/servward-update
chmod 440 /etc/sudoers.d/servward-update
visudo -cf /etc/sudoers.d/servward-update >/dev/null 2>&1 || rm -f /etc/sudoers.d/servward-update
sleep 1
ntfyctl status || true

# ── Tailscale: si está activo, la URL va incluida en el QR y en el código ────
TS_IP=""
if command -v tailscale >/dev/null 2>&1; then
  TS_IP="$(tailscale ip -4 2>/dev/null | head -1 || true)"
fi
if [ -z "$TS_IP" ]; then
  TS_IP="$(ip -4 -o addr show tailscale0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1 || true)"
fi
SRV_URL=""
if [ -n "$TS_IP" ]; then SRV_URL="http://$TS_IP:$PORT"; fi

# ── Configuración empaquetada para la app (pegar / QR) ───────────────────────
CONFIG_JSON=$(printf '{"name":"%s","url":"%s","cmd":"%s","resp":"%s","token":"%s","rotoken":"%s"}' \
  "$NAME" "$SRV_URL" "$CMD_TOPIC" "$RESP_TOPIC" "$TOKEN" "$TOKEN_RO")
CONFIG_B64=$(printf '%s' "$CONFIG_JSON" | base64 | tr -d '\n')
URL_ENC=$(printf '%s' "$SRV_URL" | sed 's/:/%3A/g; s|/|%2F|g')
DEEPLINK="servward://add?name=${NAME}&cmd=${CMD_TOPIC}&resp=${RESP_TOPIC}&token=${TOKEN}&rotoken=${TOKEN_RO}&url=${URL_ENC}"

if [ -n "$SRV_URL" ]; then
  URL_LINE="  URL        : $SRV_URL   ← Tailscale detectado ✅"
  HINT_LINE="  (Incluye nombre, topics, token y URL: conexión en un paso.)"
else
  URL_LINE="  URL        : según cómo lo expongas ↓"
  HINT_LINE="  (Incluye nombre, topics y token. Solo tendrás que añadir la URL.)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Servidor "$NAME" montado (broker + agente + ntfyctl).

CONFIGURACIÓN RÁPIDA (recomendado):
  En la app → Ajustes → «Pegar configuración» y pega este código:

  $CONFIG_B64

$HINT_LINE

O a mano → Ajustes → Añadir servidor:
  Nombre     : $NAME
  Órdenes    : $CMD_TOPIC
  Respuestas : $RESP_TOPIC
  Token      : $TOKEN
$URL_LINE

Exponer (elige UNO):
  • Tailscale (fácil): instala tailscale; URL = http://100.x.x.x:2586
  • Cloudflare: añade un ingress al túnel → http://127.0.0.1:2586 ; URL = https://tu-host

Para los botones de Reiniciar/Parar servicios necesitas además:
  - quitar NoNewPrivileges del agente (este script ya no lo pone), y
  - un sudoers para 'ntfy' (ver /etc/sudoers.d/ntfy-agent del primer Linux).
────────────────────────────────────────────────────────────────────
EOF

if [ -z "$SRV_URL" ]; then
  cat <<'EOF'
⚠️  Tailscale no detectado (vía fácil recomendada):
    1. Instálalo:  curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
    2. Re-ejecuta este instalador → el QR saldrá con la URL ya incluida
EOF
fi

# QR (escanéalo con la cámara del iPhone → abre la app y la deja configurada)
echo
echo "Escanea este QR con la cámara del iPhone:"
if ! /usr/bin/python3 - "$DEEPLINK" <<'PYQ'
import sys
try:
    import qrcode
except Exception:
    sys.exit(1)
q = qrcode.QRCode(border=2)
q.add_data(sys.argv[1])
q.print_ascii(invert=True)
PYQ
then
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t ANSIUTF8 "$DEEPLINK"
  else
    echo "(QR no disponible — usa el código de arriba. Tip:  apt-get install -y python3-qrcode)"
  fi
fi
