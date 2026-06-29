#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# Instalador del broker Servward (server.py) en un servidor Linux.
# Lo deja corriendo como servicio systemd, en HTTP sobre 127.0.0.1:2586,
# pensado para exponerse por Cloudflare Tunnel.
#
# Uso:
#   sudo bash setup_linux.sh
#
# Requisitos: Debian/Ubuntu (apt) o similar con systemd y python3.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Ejecuta con sudo:  sudo bash setup_linux.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SERVER_PY="$REPO_ROOT/server.py"

if [[ ! -f "$SERVER_PY" ]]; then
  echo "No encuentro server.py en $REPO_ROOT" >&2
  echo "Clona el repo o copia server.py junto a la carpeta linux/." >&2
  exit 1
fi

echo "==> 1/6  Dependencias (python3)"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq python3
fi

echo "==> 2/6  Usuario de servicio 'ntfy'"
if ! id ntfy >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin ntfy
fi

echo "==> 3/6  Código del broker en /opt/ntfy"
install -d -o ntfy -g ntfy /opt/ntfy
install -o ntfy -g ntfy -m 644 "$SERVER_PY" /opt/ntfy/server.py

echo "==> 4/6  Archivo de entorno en /etc/ntfy/ntfy.env"
install -d -m 750 /etc/ntfy
if [[ ! -f /etc/ntfy/ntfy.env ]]; then
  install -m 600 "$SCRIPT_DIR/ntfy.env" /etc/ntfy/ntfy.env
  echo "    -> Creado. EDÍTALO y pon tu NTFY_TOKEN:  sudo nano /etc/ntfy/ntfy.env"
else
  echo "    -> Ya existe, no lo toco."
fi
chown root:ntfy /etc/ntfy/ntfy.env
chmod 640 /etc/ntfy/ntfy.env

echo "==> 5/6  Servicio systemd"
install -m 644 "$SCRIPT_DIR/ntfy-server.service" /etc/systemd/system/ntfy-server.service
systemctl daemon-reload
systemctl enable ntfy-server.service

echo "==> 6/6  Arranque"
if grep -q "PEGA_AQUI_TU_TOKEN" /etc/ntfy/ntfy.env; then
  echo
  echo "  ⚠  Falta el token. Edita /etc/ntfy/ntfy.env y luego:"
  echo "       sudo systemctl restart ntfy-server && systemctl status ntfy-server"
else
  systemctl restart ntfy-server.service
  sleep 1
  systemctl --no-pager --full status ntfy-server.service || true
fi

echo
echo "Broker escuchando en http://127.0.0.1:2586 (solo local)."
echo "Comprueba:  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2586/"
echo "  → 404 (o 401) = está vivo;  000 / sin respuesta = caído."
echo "Ahora configura el túnel: ver linux/README.md"
