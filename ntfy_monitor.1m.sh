#!/bin/bash
# <swiftbar.title>Servward Monitor</swiftbar.title>
# <swiftbar.version>1.0</swiftbar.version>
# <swiftbar.author>NFTY</swiftbar.author>
# <swiftbar.refreshTime>60</swiftbar.refreshTime>
# <swiftbar.hideAbout>true</swiftbar.hideAbout>
# <swiftbar.hideRunInTerminal>true</swiftbar.hideRunInTerminal>
# <swiftbar.hideSwiftBar>true</swiftbar.hideSwiftBar>
#
# Requiere: psutil  →  pip3 install psutil --break-system-packages
# Opcional: osx-cpu-temp → brew install osx-cpu-temp

BASE_DIR="$HOME/Developer/NFTY"
TOKEN_FILE="$BASE_DIR/.ntfy_token"
PORT=2586
CMD_TOPIC="cmd-macmini-demo"
SERVER="http://127.0.0.1:$PORT"
SELF="$0"

# ── Modo comando: recibe $1=cmd $2=args_json (llamado por SwiftBar al hacer click) ──
if [ -n "$1" ]; then
    TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null)
    [ -z "$TOKEN" ] && exit 1
    ARGS="${2:-}"
    PAYLOAD="{\"id\":\"sb_$(date +%s)\",\"cmd\":\"$1\",\"args\":{$ARGS},\"device\":\"swiftbar\",\"ts\":$(date +%s)}"
    curl -s -X POST "$SERVER/$CMD_TOPIC" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" > /dev/null 2>&1
    exit 0
fi

# ── Comprobar si el servidor está vivo ────────────────────────────────────────
SERVER_OK=false
if curl -s --max-time 1 "$SERVER/ping" > /dev/null 2>&1 || \
   curl -s --max-time 1 -o /dev/null -w "%{http_code}" \
       -H "Authorization: Bearer $(cat "$TOKEN_FILE" 2>/dev/null)" \
       "$SERVER/cmd-macmini-demo/sse" 2>/dev/null | grep -q "2"; then
    SERVER_OK=true
fi

# ── Métricas del sistema (Python + psutil) ────────────────────────────────────
METRICS=$(python3 - 2>/dev/null << 'PYEOF'
import psutil, subprocess, re

cpu  = psutil.cpu_percent(interval=0.5)
mem  = psutil.virtual_memory()
disk = psutil.disk_usage("/")

# Temperatura CPU
temp = ""
for cmd in [["osx-cpu-temp"], ["istats", "cpu", "--no-graphs"]]:
    try:
        out = subprocess.check_output(cmd, text=True, timeout=3, stderr=subprocess.DEVNULL)
        m = re.search(r"([\d.]+)\s*°?C", out)
        if m:
            temp = f"{float(m.group(1)):.0f}°C"
            break
    except Exception:
        pass

print(f"{cpu:.0f}|{mem.percent:.0f}|{disk.percent:.0f}|{temp}")
PYEOF
)

CPU=$(echo  "$METRICS" | cut -d'|' -f1)
RAM=$(echo  "$METRICS" | cut -d'|' -f2)
DISK=$(echo "$METRICS" | cut -d'|' -f3)
TEMP=$(echo "$METRICS" | cut -d'|' -f4)

# ── Colores según umbrales ─────────────────────────────────────────────────────
CPU_COL=""; RAM_COL=""; DISK_COL=""
[ "${CPU:-0}"  -ge 85 ] 2>/dev/null && CPU_COL=" color=red"
[ "${RAM:-0}"  -ge 85 ] 2>/dev/null && RAM_COL=" color=red"
[ "${DISK:-0}" -ge 90 ] 2>/dev/null && DISK_COL=" color=red"

# Dot de estado del servidor
DOT="🟢"; [ "$SERVER_OK" != "true" ] && DOT="🔴"

# ── BARRA DE MENÚ ─────────────────────────────────────────────────────────────
if [ -n "$TEMP" ]; then
    echo "${DOT} CPU:${CPU}% RAM:${RAM}% ${TEMP}"
else
    echo "${DOT} CPU:${CPU}% RAM:${RAM}%"
fi
echo "---"

# ── Sección: estado ───────────────────────────────────────────────────────────
echo "🖥  Mac Mini | size=13 color=#888888"
echo "CPU:  ${CPU:-?}%  | size=12${CPU_COL}"
echo "RAM:  ${RAM:-?}%  | size=12${RAM_COL}"
echo "Disco: ${DISK:-?}% | size=12${DISK_COL}"
[ -n "$TEMP" ] && echo "Temp: $TEMP | size=12"
echo "---"

# ── Monitor ───────────────────────────────────────────────────────────────────
echo "📊 Monitor"
echo "--Estado completo  | shell=$SELF param1=check_status  terminal=false refresh=true"
echo "--Temperaturas     | shell=$SELF param1=temperatures  terminal=false refresh=true"
echo "--Procesos (top 8) | shell=$SELF param1=last_jobs     terminal=false refresh=true"
echo "--Todos los discos | shell=$SELF param1=disks         terminal=false refresh=true"
echo "--Ping / Red       | shell=$SELF param1=ping_service  terminal=false refresh=true"
echo "--Uptime           | shell=$SELF param1=uptime        terminal=false refresh=true"
echo "--Velocidad red    | shell=$SELF param1=network_speed terminal=false refresh=true"
echo "---"

# ── Audio ─────────────────────────────────────────────────────────────────────
echo "🔊 Audio"
echo "--Silenciar        | shell=$SELF param1=mute    terminal=false refresh=false"
echo "--Activar audio    | shell=$SELF param1=unmute  terminal=false refresh=false"
echo "--Vol 50%          | shell=$SELF param1=set_volume param2='\"level\":\"50\"' terminal=false refresh=false"
echo "--Vol 75%          | shell=$SELF param1=set_volume param2='\"level\":\"75\"' terminal=false refresh=false"
echo "--Ver volumen      | shell=$SELF param1=get_volume terminal=false refresh=true"
echo "---"

# ── Sistema ───────────────────────────────────────────────────────────────────
echo "⚙️  Sistema"
echo "--Screenshot       | shell=$SELF param1=screenshot    terminal=false refresh=false"
echo "--Dormir           | shell=$SELF param1=sleep_mac     terminal=false refresh=false"
echo "--Reiniciar        | shell=$SELF param1=restart_mac   terminal=false refresh=false"
echo "--Apagar           | shell=$SELF param1=shutdown_mac  terminal=false refresh=false"
echo "---"

# ── Panel de estado ───────────────────────────────────────────────────────────
STATUS_URL="https://status.tudominio.com"   # opcional: cambia por tu panel de estado
STATUS_HTTP=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" "$STATUS_URL" 2>/dev/null)
if [[ "$STATUS_HTTP" =~ ^2 ]]; then
    STATUS_LABEL="🟢 Panel en línea"
else
    STATUS_LABEL="🔴 Panel no disponible"
fi
echo "📊 Panel de estado"
echo "--$STATUS_LABEL | href=$STATUS_URL"
echo "--Abrir panel de estado | href=$STATUS_URL"
echo "---"

# ── Info ──────────────────────────────────────────────────────────────────────
echo "🔄 Actualizar ahora | refresh=true"
echo "📡 Servidor: $SERVER | size=11 color=gray"
