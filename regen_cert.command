#!/usr/bin/env bash
# Regenera el certificado SSL incluyendo la IP local y la IP de Tailscale
set -e
cd "$(dirname "$0")/certs"

echo "▶ Regenerando certificado con IP local + Tailscale..."

cat > openssl.cnf << 'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
CN = Servward Server

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,digitalSignature,keyCertSign
subjectAltName         = @alt_names

[alt_names]
IP.1 = 192.168.1.50
IP.2 = 100.64.0.1
EOF

openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 3650 -nodes -config openssl.cnf

chmod 600 server.key server.crt

echo ""
echo "✅ Certificado regenerado con:"
echo "   IP.1 = 192.168.1.50  (red local)"
echo "   IP.2 = 100.64.0.1 (Tailscale)"
echo ""
echo "SHA-256 fingerprint:"
openssl x509 -noout -fingerprint -sha256 -in server.crt | sed 's/sha256 Fingerprint=//'
echo ""
echo "▶ Recargando servidor con nuevo certificado..."

launchctl bootout  gui/$(id -u)/com.espymelab.ntfy.server 2>/dev/null || true
sleep 1
launchctl bootstrap gui/$(id -u) "$HOME/Library/LaunchAgents/com.espymelab.ntfy.server.plist"
sleep 2

if launchctl print gui/$(id -u)/com.espymelab.ntfy.server 2>/dev/null | grep -q "state = running"; then
    echo "✅ Servidor corriendo con nuevo certificado"
else
    echo "⚠️  Comprueba: tail -10 /tmp/ntfy_server.log"
fi

echo ""
echo "⚠️  IMPORTANTE: En la app iOS ve a Ajustes → Restablecer confianza"
echo "   para que el iPhone acepte el nuevo certificado."
echo ""
echo "Puedes cerrar esta ventana."
