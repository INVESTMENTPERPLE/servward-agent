#!/usr/bin/env bash
# Instala ntfyctl en el Linux: lo copia a /opt/ntfy y lo enlaza en el PATH.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ntfyctl"
sudo install -m 755 "$SRC" /opt/ntfy/ntfyctl
sudo ln -sf /opt/ntfy/ntfyctl /usr/local/bin/ntfyctl
echo "✅ ntfyctl instalado. Prueba:  ntfyctl status"
