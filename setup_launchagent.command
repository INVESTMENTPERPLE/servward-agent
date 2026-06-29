#!/usr/bin/env bash
# Instala los LaunchAgents para que server.py y agent.py arranquen
# automáticamente al iniciar sesión y se reinicien si se caen.
# Modo HTTP — el tráfico va cifrado por Cloudflare Tunnel.
set -e
cd "$(dirname "$0")"
BASE="$(pwd)"
AGENTS_DIR="$HOME/Library/LaunchAgents"
BIND="0.0.0.0"
PORT="2586"

# ── Token: generar uno aleatorio si no existe ─────────────────────────────────
TOKEN_FILE="$BASE/.ntfy_token"
if [ -f "$TOKEN_FILE" ]; then
    TOKEN=$(cat "$TOKEN_FILE")
    echo "✅  Token existente cargado"
else
    TOKEN=$(openssl rand -hex 32)
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo "✅  Token nuevo generado"
fi

# ── Detectar python3 con los paquetes instalados ──────────────────────────────
PYTHON=""
for candidate in \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3 \
    /usr/bin/python3; do
    if "$candidate" -c "import psutil, requests" 2>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "❌  No se encontró python3 con psutil y requests."
    echo "    Ejecuta: pip3 install psutil requests pillow --break-system-packages"
    exit 1
fi

echo "✅  Python: $PYTHON"
mkdir -p "$AGENTS_DIR"

# ── Plist del servidor (HTTP, sin TLS) ───────────────────────────────────────
SERVER_PLIST="$AGENTS_DIR/com.espymelab.ntfy.server.plist"
cat > "$SERVER_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.espymelab.ntfy.server</string>

    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON</string>
        <string>$BASE/server.py</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>NTFY_TOKEN</key> <string>$TOKEN</string>
        <key>NTFY_BIND</key>  <string>$BIND</string>
        <key>NTFY_PORT</key>  <string>$PORT</string>
    </dict>

    <key>RunAtLoad</key>      <true/>
    <key>KeepAlive</key>      <true/>
    <key>ThrottleInterval</key> <integer>10</integer>

    <key>StandardOutPath</key> <string>/tmp/ntfy_server.log</string>
    <key>StandardErrorPath</key><string>/tmp/ntfy_server.log</string>
</dict>
</plist>
EOF
echo "✅  Plist servidor: $SERVER_PLIST"

# ── Plist del agente ──────────────────────────────────────────────────────────
AGENT_PLIST="$AGENTS_DIR/com.espymelab.ntfy.agent.plist"
cat > "$AGENT_PLIST" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.espymelab.ntfy.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON</string>
        <string>$BASE/agent.py</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>NTFY_TOKEN</key>   <string>$TOKEN</string>
        <key>NTFY_SERVER</key>  <string>http://127.0.0.1:$PORT</string>
    </dict>

    <key>RunAtLoad</key>      <true/>
    <key>KeepAlive</key>      <true/>
    <key>ThrottleInterval</key> <integer>10</integer>

    <key>StandardOutPath</key> <string>/tmp/ntfy_agent.log</string>
    <key>StandardErrorPath</key><string>/tmp/ntfy_agent.log</string>
</dict>
</plist>
EOF
echo "✅  Plist agente: $AGENT_PLIST"

# ── Matar procesos manuales en el puerto si los hay ──────────────────────────
echo ""
echo "▶  Liberando puerto $PORT..."
lsof -ti ":$PORT" | xargs kill -9 2>/dev/null || true
sleep 1

# ── Cargar (o recargar) los servicios ────────────────────────────────────────
echo "▶  Cargando servicios…"
for label in com.espymelab.ntfy.server com.espymelab.ntfy.agent; do
    launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
done
sleep 1
launchctl bootstrap "gui/$(id -u)" "$SERVER_PLIST"
sleep 3
launchctl bootstrap "gui/$(id -u)" "$AGENT_PLIST"
sleep 2

# ── Verificar ────────────────────────────────────────────────────────────────
echo ""
OK=0
for label in com.espymelab.ntfy.server com.espymelab.ntfy.agent; do
    if launchctl print "gui/$(id -u)/$label" 2>/dev/null | grep -q "state = running"; then
        echo "✅  $label — corriendo"
        OK=$((OK+1))
    else
        echo "⚠️   $label — comprobando logs…"
    fi
done

echo ""
echo "════════════════════════════════════════════"
echo "  🔑  TU TOKEN SECRETO (cópialo a la app):"
echo ""
echo "  $TOKEN"
echo ""
echo "════════════════════════════════════════════"
echo ""
if [ $OK -eq 2 ]; then
    echo "🎉  Todo listo. Servidor y agente corren automáticamente."
else
    echo "Logs servidor: tail -10 /tmp/ntfy_server.log"
    echo "Logs agente:   tail -10 /tmp/ntfy_agent.log"
fi
echo ""
echo "Puedes cerrar esta ventana."
