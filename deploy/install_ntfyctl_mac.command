#!/usr/bin/env bash
# Instala ntfyctl en el Mac: lo pone en el PATH. Gestiona los servicios launchd
# por su label, así que funciona con el despliegue actual sin mover nada.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ntfyctl"
sudo install -m 755 "$SRC" /usr/local/bin/ntfyctl
echo "✅ ntfyctl instalado. Prueba:  ntfyctl status"
