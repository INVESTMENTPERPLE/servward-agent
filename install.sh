#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Servward — instalación y actualización en UN solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/servward-agent/main/install.sh | bash
#
# Descarga el código de GitHub (o lo actualiza si ya estaba), detecta tu sistema
# (Mac o Linux) y monta el broker + el agente + ntfyctl. Vuelve a ejecutar el
# MISMO comando para actualizar: conserva tu token y tus topics.
#
# Opcional: pasar un nombre  →  ... | bash -s -- minombre
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="https://github.com/INVESTMENTPERPLE/servward-agent.git"
SRC="${NTFY_SRC:-$HOME/.ntfycontrol}"
OS="$(uname -s)"
NAME="${1:-$(hostname -s 2>/dev/null || hostname)}"

command -v git >/dev/null 2>&1 || { echo "Necesitas 'git' instalado."; exit 1; }

if [ -d "$SRC/.git" ]; then
  echo "==> Actualizando código…"
  # Robusto ante instalaciones antiguas: fija el repo correcto y alinea con
  # origin/main aunque la copia haya divergido (respaldo en tag backup-predeploy).
  git -C "$SRC" remote set-url origin "$REPO_URL" 2>/dev/null || true
  git -C "$SRC" fetch origin --quiet
  git -C "$SRC" tag -f backup-predeploy HEAD >/dev/null 2>&1 || true
  git -C "$SRC" reset --hard origin/main
else
  echo "==> Descargando código…"
  git clone --depth 1 "$REPO_URL" "$SRC"
fi

echo "==> Sistema: $OS"
if [ "$OS" = "Darwin" ]; then
  bash "$SRC/deploy/add_server_mac.command" "$NAME"
else
  sudo bash "$SRC/deploy/add_server_linux.sh" "$NAME"
fi

echo
echo "Para ACTUALIZAR en el futuro, vuelve a ejecutar el mismo comando."
echo "Para gestionar:  ntfyctl status | restart | logs | info"
