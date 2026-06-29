#!/usr/bin/env bash
# (Opcional) Añade ficheros de log a los LaunchAgents del Mac para que
# `ntfyctl logs` funcione. Hace backup de los plists y recarga los servicios.
set -euo pipefail
LOGDIR="$HOME/Library/Logs/ntfy"
mkdir -p "$LOGDIR"
UID_="$(id -u)"

for entry in "com.espymelab.ntfy.server:broker" "com.espymelab.ntfy.agent:agent"; do
  label="${entry%%:*}"; short="${entry##*:}"
  P="$HOME/Library/LaunchAgents/$label.plist"
  [ -f "$P" ] || { echo "⚠️  no existe $P, salto"; continue; }
  cp "$P" "$P.bak.$(date +%Y%m%d%H%M%S)"
  /usr/libexec/PlistBuddy -c "Delete :StandardOutPath"  "$P" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Delete :StandardErrorPath" "$P" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Add :StandardOutPath  string $LOGDIR/$short.log" "$P"
  /usr/libexec/PlistBuddy -c "Add :StandardErrorPath string $LOGDIR/$short.log" "$P"
  launchctl bootout   "gui/$UID_/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$UID_" "$P"
  echo "✅ $label → $LOGDIR/$short.log"
done
echo "Listo. Prueba:  ntfyctl logs"
