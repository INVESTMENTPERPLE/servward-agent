#!/usr/bin/env bash
# =============================================================================
#  NtfyControl — Security Setup
#  Genera certs TLS, token fuerte y configura env vars.
#  Ejecutar UNA VEZ en el Mac mini antes de arrancar server.py y agent.py.
# =============================================================================
set -euo pipefail

CERTS_DIR="$HOME/ntfy_certs"
ENV_FILE="$HOME/.ntfy_env"
RC_FILE="$HOME/.zshrc"
DAYS=3650   # cert válido 10 años

# ── Detectar IP local ─────────────────────────────────────────────────────────
LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null \
  || ipconfig getifaddr en1 2>/dev/null \
  || route -n get default 2>/dev/null | awk '/interface/{print $2}' | xargs ipconfig getifaddr \
  || echo "")

if [[ -z "$LOCAL_IP" ]]; then
  echo "⚠️  No se pudo detectar la IP local automáticamente."
  read -rp "   Introduce tu IP local (ej. 192.168.1.50): " LOCAL_IP
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NtfyControl Security Setup"
echo "  IP detectada: $LOCAL_IP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Generar token ──────────────────────────────────────────────────────────
echo "▶ Generando token seguro (64 chars hex)..."
NEW_TOKEN=$(openssl rand -hex 32)

# ── 2. Crear directorio de certs ──────────────────────────────────────────────
mkdir -p "$CERTS_DIR"
chmod 700 "$CERTS_DIR"

# ── 3. Generar clave privada RSA 2048 ─────────────────────────────────────────
echo "▶ Generando clave privada RSA-2048..."
openssl genrsa -out "$CERTS_DIR/server.key" 2048 2>/dev/null
chmod 600 "$CERTS_DIR/server.key"

# ── 4. Crear config OpenSSL con SAN para la IP ───────────────────────────────
cat > "$CERTS_DIR/openssl.cnf" << EOF
[req]
distinguished_name = req_dn
x509_extensions    = v3_req
prompt             = no

[req_dn]
CN = NtfyControl
O  = Local
C  = US

[v3_req]
subjectAltName   = IP:${LOCAL_IP}
keyUsage         = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
EOF

# ── 5. Generar certificado auto-firmado ───────────────────────────────────────
echo "▶ Generando certificado TLS (válido ${DAYS} días)..."
openssl req -new -x509 \
  -key    "$CERTS_DIR/server.key" \
  -out    "$CERTS_DIR/server.crt" \
  -days   "$DAYS" \
  -config "$CERTS_DIR/openssl.cnf" 2>/dev/null
chmod 644 "$CERTS_DIR/server.crt"

# ── 6. Calcular fingerprint SHA-256 del cert ─────────────────────────────────
FINGERPRINT=$(openssl x509 -in "$CERTS_DIR/server.crt" -fingerprint -sha256 -noout \
              | sed 's/SHA256 Fingerprint=//' | tr -d ':' | tr '[:upper:]' '[:lower:]')

# ── 7. Escribir .ntfy_env ─────────────────────────────────────────────────────
echo "▶ Escribiendo variables de entorno en $ENV_FILE..."
cat > "$ENV_FILE" << EOF
# NtfyControl environment — generado por setup_security.sh
# NO SUBIR A GIT NI COMPARTIR
export NTFY_TOKEN="${NEW_TOKEN}"
export NTFY_BIND="${LOCAL_IP}"
export NTFY_PORT="2586"
export NTFY_CERT="$CERTS_DIR/server.crt"
export NTFY_KEY="$CERTS_DIR/server.key"
EOF
chmod 600 "$ENV_FILE"

# ── 8. Añadir source a .zshrc (solo si no existe) ────────────────────────────
SOURCE_LINE="[ -f \"$ENV_FILE\" ] && source \"$ENV_FILE\""
if ! grep -qF "$ENV_FILE" "$RC_FILE" 2>/dev/null; then
  echo "" >> "$RC_FILE"
  echo "# NtfyControl security env" >> "$RC_FILE"
  echo "$SOURCE_LINE" >> "$RC_FILE"
  echo "▶ Añadida carga automática en $RC_FILE"
else
  echo "▶ Ya existe la carga en $RC_FILE (sin cambios)"
fi

# ── 9. Aplicar en la sesión actual ───────────────────────────────────────────
# shellcheck disable=SC1090
source "$ENV_FILE"

# ── Resumen ───────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅  Setup completado"
echo ""
echo "  Token    : $NEW_TOKEN"
echo "  IP       : $LOCAL_IP:2586"
echo "  Cert     : $CERTS_DIR/server.crt"
echo "  Key      : $CERTS_DIR/server.key"
echo "  SHA-256  : ${FINGERPRINT:0:16}…${FINGERPRINT: -8}"
echo ""
echo "  PRÓXIMOS PASOS:"
echo "  1) Cierra y vuelve a abrir el terminal (o ejecuta: source ~/.zshrc)"
echo "  2) Arranca el servidor:  python3 ~/Downloads/server.py"
echo "  3) Arranca el agente:    python3 ~/Downloads/agent.py"
echo "  4) En la app iOS → Ajustes:"
echo "     · Servidor : https://$LOCAL_IP:2586"
echo "     · Token    : $NEW_TOKEN"
echo "  5) Primera conexión → la app fijará el cert automáticamente (TOFU)"
echo ""
echo "  FINGERPRINT COMPLETO (guárdalo para verificación manual):"
echo "  $FINGERPRINT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
