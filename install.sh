#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NtfyControl — instalación y actualización en UN solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/NFTYcontrol/main/install.sh | bash
#
# Descarga el código de GitHub (o lo actualiza si ya estaba), detecta tu sistema
# (Mac o Linux) y monta el broker + el agente + ntfyctl. Vuelve a ejecutar el
# MISMO comando para actualizar: conserva tu token y tus topics.
#
# Opcional: pasar un nombre  →  ... | bash -s -- minombre
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="https://github.com/INVESTMENTPERPLE/NFTYcontrol.git"
SRC="${NTFY_SRC:-$HOME/.ntfycontrol}"
OS="$(uname -s)"
NAME="${1:-$(hostname -s 2>/dev/null || hostname)}"

command -v git >/dev/null 2>&1 || { echo "Necesitas 'git' instalado."; exit 1; }

if [ -d "$SRC/.git" ]; then
  echo "==> Actualizando código…"
  git -C "$SRC" pull --ff-only
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
