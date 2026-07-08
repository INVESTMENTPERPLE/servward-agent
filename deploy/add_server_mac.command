#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Alta de un Mac en Servward: broker + agente (launchd) + ntfyctl, topics
# ÚNICOS, en una sola pasada. Pensado para un Mac NUEVO.
#
#   bash deploy/add_server_mac.command <nombre> [token]
#
#   <nombre>  → topics cmd-<nombre> / resp-<nombre>
#   [token]   → si se omite, se genera y se muestra al final
#
# Requiere el repo (con server.py y agent.py actualizados) en este Mac.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
NAME="${1:-$(hostname -s 2>/dev/null || hostname)}"; TOKEN="${2:-}"
PORT=2586
PY=/usr/bin/python3
LA="$HOME/Library/LaunchAgents"; LOGDIR="$HOME/Library/Logs/ntfy"
mkdir -p "$LA" "$LOGDIR"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -f "$REPO/server.py" ] && [ -f "$REPO/agent.py" ] || { echo "Faltan server.py/agent.py en $REPO"; exit 1; }

# Idempotente: si ya existe el plist, es ACTUALIZACIÓN → conservar token/topics/whitelist.
AGENT_PLIST="$LA/com.espymelab.ntfy.agent.plist"
WHITELIST=""
if [ -f "$AGENT_PLIST" ]; then
  echo "==> Ya configurado: actualizo y conservo token/topics."
  TOKEN="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:NTFY_TOKEN' "$AGENT_PLIST" 2>/dev/null || true)"
  CMD_TOPIC="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:NTFY_CMD_TOPIC' "$AGENT_PLIST" 2>/dev/null || true)"
  RESP_TOPIC="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:NTFY_RESP_TOPIC' "$AGENT_PLIST" 2>/dev/null || true)"
  WHITELIST="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:SERVICE_WHITELIST' "$AGENT_PLIST" 2>/dev/null || true)"
  TOKEN_RO="$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:NTFY_TOKEN_RO' "$AGENT_PLIST" 2>/dev/null || true)"
  [ -n "$CMD_TOPIC" ]  || CMD_TOPIC="cmd-macmini-demo"
  [ -n "$RESP_TOPIC" ] || RESP_TOPIC="resp-iphone-demo"
fi
[ -n "$TOKEN" ]          || TOKEN="$(openssl rand -hex 32)"
[ -n "${TOKEN_RO:-}" ]   || TOKEN_RO="$(openssl rand -hex 32)"
[ -n "${CMD_TOPIC:-}" ]  || CMD_TOPIC="cmd-$NAME"
[ -n "${RESP_TOPIC:-}" ] || RESP_TOPIC="resp-$NAME"
WL_LINE=""
[ -n "$WHITELIST" ] && WL_LINE="    <key>SERVICE_WHITELIST</key><string>$WHITELIST</string>"

echo "==> dependencias python (requests, psutil)"
$PY -m pip install --user requests psutil >/dev/null 2>&1 \
  || $PY -m pip install --user --break-system-packages requests psutil >/dev/null 2>&1 \
  || echo "   ⚠️ instala 'requests' y 'psutil' a mano si el arranque falla"

mkplist() {  # label script short
  cat > "$LA/$1.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>$REPO/$2</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>NTFY_TOKEN</key><string>$TOKEN</string>
    <key>NTFY_TOKEN_RO</key><string>$TOKEN_RO</string>
    <key>NTFY_BIND</key><string>127.0.0.1</string>
    <key>NTFY_PORT</key><string>$PORT</string>
    <key>NTFY_CERT</key><string>/dev/null/nocert</string>
    <key>NTFY_KEY</key><string>/dev/null/nokey</string>
    <key>NTFY_SERVER</key><string>http://127.0.0.1:$PORT</string>
    <key>NTFY_CMD_TOPIC</key><string>$CMD_TOPIC</string>
    <key>NTFY_RESP_TOPIC</key><string>$RESP_TOPIC</string>
$WL_LINE
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOGDIR/$3.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/$3.log</string>
</dict></plist>
EOF
}

echo "==> LaunchAgents"
mkplist com.espymelab.ntfy.server server.py broker
mkplist com.espymelab.ntfy.agent  agent.py  agent

echo "==> ntfyctl"
sudo install -m 755 "$REPO/deploy/ntfyctl" /usr/local/bin/ntfyctl

UID_="$(id -u)"
for l in com.espymelab.ntfy.server com.espymelab.ntfy.agent; do
  launchctl bootout   "gui/$UID_/$l" 2>/dev/null || true
  launchctl bootstrap "gui/$UID_" "$LA/$l.plist"
done
sleep 1
ntfyctl status || true

# ── Configuración empaquetada para la app (pegar / QR) ───────────────────────
CONFIG_JSON=$(printf '{"name":"%s","cmd":"%s","resp":"%s","token":"%s","rotoken":"%s"}' \
  "$NAME" "$CMD_TOPIC" "$RESP_TOPIC" "$TOKEN" "$TOKEN_RO")
CONFIG_B64=$(printf '%s' "$CONFIG_JSON" | base64 | tr -d '\n')
DEEPLINK="servward://add?name=${NAME}&cmd=${CMD_TOPIC}&resp=${RESP_TOPIC}&token=${TOKEN}&rotoken=${TOKEN_RO}"

cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Mac "$NAME" montado (broker + agente + ntfyctl).

CONFIGURACIÓN RÁPIDA (recomendado):
  En la app → Ajustes → «Pegar configuración» y pega este código:

  $CONFIG_B64

  (Incluye nombre, topics y token. Solo tendrás que añadir la URL.)

O a mano → Ajustes → Añadir servidor:
  Nombre     : $NAME
  Órdenes    : $CMD_TOPIC
  Respuestas : $RESP_TOPIC
  Token      : $TOKEN
  URL        : según cómo lo expongas ↓

Exponer (elige UNO):
  • Tailscale (fácil): instala tailscale; URL = http://100.x.x.x:2586
  • Cloudflare: añade un ingress al túnel → http://127.0.0.1:2586
────────────────────────────────────────────────────────────────────
EOF

# QR opcional (escanéalo con la cámara del iPhone → abre la app y la configura)
if command -v qrencode >/dev/null 2>&1; then
  echo "Escanea este QR con la cámara del iPhone:"
  qrencode -t ANSIUTF8 "$DEEPLINK"
else
  echo "(Instala 'qrencode' para un QR escaneable:  brew install qrencode)"
fi
