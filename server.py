#!/usr/bin/env python3
"""
NtfyControl — Pub-Sub Server (Hardened)
HTTPS · Token Bearer · Rate Limiting · IP Binding · Request Size Limit

Requisitos previos:
    source ~/.ntfy_env          (o export NTFY_TOKEN=... manualmente)
    python3 server.py
"""

import hashlib
import json
import logging
import os
import ssl
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# ── Configuración (todo desde env vars) ─────────────────────────────────────
TOKEN     = os.environ.get("NTFY_TOKEN", "").strip()
BIND_HOST = os.environ.get("NTFY_BIND",  "0.0.0.0")
PORT      = int(os.environ.get("NTFY_PORT", "2586"))
CERT_FILE = os.environ.get("NTFY_CERT",  os.path.expanduser("~/ntfy_certs/server.crt"))
KEY_FILE  = os.environ.get("NTFY_KEY",   os.path.expanduser("~/ntfy_certs/server.key"))

MAX_BODY_BYTES     = 4 * 1024 * 1024   # 4 MB — soporta screenshots
RATE_LIMIT_MAX     = 5           # intentos fallidos permitidos
RATE_LIMIT_WINDOW  = 60          # segundos de ventana

if not TOKEN:
    sys.exit(
        "\n[FATAL] Variable NTFY_TOKEN no definida.\n"
        "Ejecuta: source ~/.ntfy_env\n"
        "o:       export NTFY_TOKEN=<tu-token>\n"
    )

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ntfy-server")

# ── Almacén de topics ─────────────────────────────────────────────────────────
topics: dict[str, list] = defaultdict(list)
topics_lock = threading.Lock()

# ── Almacén de device tokens (push APNs) ─────────────────────────────────────
DEVICE_TOKEN_FILE = "/tmp/ntfy_device_tokens.json"
_dt_lock          = threading.Lock()

def _load_device_tokens() -> list:
    if os.path.isfile(DEVICE_TOKEN_FILE):
        try:
            with open(DEVICE_TOKEN_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []

def _save_device_token(token: str):
    with _dt_lock:
        tokens = _load_device_tokens()
        if token not in tokens:
            tokens.append(token)
        with open(DEVICE_TOKEN_FILE, "w") as f:
            json.dump(tokens, f)

# ── Rate limiter ──────────────────────────────────────────────────────────────
_fail_log: dict[str, list[float]] = defaultdict(list)
_fail_lock = threading.Lock()

def _is_blocked(ip: str) -> bool:
    now = time.monotonic()
    with _fail_lock:
        _fail_log[ip] = [t for t in _fail_log[ip] if now - t < RATE_LIMIT_WINDOW]
        return len(_fail_log[ip]) >= RATE_LIMIT_MAX

def _record_fail(ip: str) -> int:
    with _fail_lock:
        _fail_log[ip].append(time.monotonic())
        return len(_fail_log[ip])

# ── Comparación de token en tiempo constante ──────────────────────────────────
def _token_ok(header_value: str) -> bool:
    """Evita timing attacks comparando byte a byte en tiempo constante."""
    expected = f"Bearer {TOKEN}"
    if len(header_value) != len(expected):
        return False
    result = 0
    for a, b in zip(header_value.encode(), expected.encode()):
        result |= a ^ b
    return result == 0

# ── Handler HTTP ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        # Desactivar el buffer para que SSE llegue inmediatamente al cliente
        self.wfile = self.connection.makefile("wb", 0)

    # Silenciar el log de acceso por defecto (usamos el nuestro)
    def log_message(self, fmt, *args):
        pass

    # ── Helpers de respuesta ──────────────────────────────────────────────────
    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: int, msg: str):
        self._json(code, {"error": msg})

    # ── IP real del cliente (detrás de Cloudflare/proxy) ──────────────────────
    def _client_ip(self) -> str:
        cf = self.headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    # ── Autenticación ─────────────────────────────────────────────────────────
    def _auth(self) -> bool:
        ip    = self._client_ip()
        local = ip in ("127.0.0.1", "::1")   # agente local / origen del túnel: nunca se bloquea
        if not local and _is_blocked(ip):
            log.warning("BLOCKED  ip=%-15s (rate limit)", ip)
            self._error(429, "too many failed attempts — try again later")
            return False
        auth_header = self.headers.get("Authorization", "")
        if not _token_ok(auth_header):
            if local:
                log.warning("AUTH_FAIL ip=%-15s (local, sin bloqueo)", ip)
            else:
                count = _record_fail(ip)
                log.warning("AUTH_FAIL ip=%-15s  attempt=%d/%d", ip, count, RATE_LIMIT_MAX)
            self._error(401, "unauthorized")
            return False
        return True

    # ── OPTIONS (preflight) ───────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    # ── POST /device-token  ──  registrar token APNs ─────────────────────────
    def _handle_device_token_post(self):
        if not self._auth(): return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0 or length > 512:
            self._error(400, "invalid body"); return
        try:
            body  = self.rfile.read(length)
            data  = json.loads(body)
            token = data.get("device_token", "").strip()
        except Exception:
            self._error(400, "invalid json"); return
        if not token or len(token) > 200:
            self._error(400, "missing or invalid device_token"); return
        _save_device_token(token)
        ip = self.client_address[0]
        log.info("DEVICE_TOKEN_SAVED  from=%s  token=%.8s…", ip, token)
        self._json(200, {"ok": True})

    # ── GET /device-tokens  ──  leer tokens (solo desde localhost) ────────────
    def _handle_device_token_get(self):
        ip = self.client_address[0]
        if ip not in ("127.0.0.1", "::1"):
            self._error(403, "forbidden"); return
        tokens = _load_device_tokens()
        self._json(200, {"tokens": tokens})

    # ── POST /topic  ──  publicar ─────────────────────────────────────────────
    def do_POST(self):
        if self.path.rstrip("/") == "/device-token":
            self._handle_device_token_post(); return
        parts = [p for p in self.path.strip("/").split("/") if p]
        if len(parts) != 1:
            self._error(404, "not found"); return
        topic = parts[0]

        if not self._auth(): return

        # Límite de tamaño
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_BYTES:
            self._error(413, "payload too large"); return
        if length == 0:
            self._error(400, "empty body"); return

        try:
            body = self.rfile.read(length)
            msg  = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            self._error(400, "invalid json"); return

        envelope = json.dumps({"event": "message", "message": json.dumps(msg)}) + "\n\n"
        ip = self.client_address[0]
        log.info("PUBLISH  topic=%-22s  from=%s  bytes=%d", topic, ip, length)

        with topics_lock:
            dead = []
            for q in topics.get(topic, []):
                try:
                    q.append(envelope)
                except Exception:
                    dead.append(q)
            for q in dead:
                topics[topic].remove(q)

        self._json(200, {"ok": True})

    # ── GET /topic/sse  ──  suscribirse ───────────────────────────────────────
    def do_GET(self):
        if self.path.rstrip("/") == "/device-tokens":
            self._handle_device_token_get(); return
        parts = [p for p in self.path.strip("/").split("/") if p]
        if len(parts) != 2 or parts[1] != "sse":
            self._error(404, "not found"); return
        topic = parts[0]

        if not self._auth(): return

        ip = self.client_address[0]
        log.info("SUBSCRIBE topic=%-22s  from=%s", topic, ip)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control",    "no-cache")
        self.send_header("X-Accel-Buffering","no")
        self.end_headers()

        # Cola de mensajes para este suscriptor
        queue: list[str] = []
        with topics_lock:
            topics[topic].append(queue)

        try:
            self.wfile.write(b'data: {"event":"open"}\n\n')
            last_hb = time.monotonic()
            while True:
                now = time.monotonic()
                # Heartbeat cada 25 s para mantener la conexión viva
                if now - last_hb >= 25:
                    self.wfile.write(b": heartbeat\n\n")
                    last_hb = now
                if queue:
                    # Vaciar toda la cola de golpe (menos latencia con varios mensajes)
                    while queue:
                        self.wfile.write(f"data: {queue.pop(0)}".encode())
                else:
                    time.sleep(0.02)
        except Exception:
            pass
        finally:
            with topics_lock:
                if queue in topics.get(topic, []):
                    topics[topic].remove(queue)
            log.info("DISCONNECTED topic=%-20s  from=%s", topic, ip)


# ── Servidor multi-hilo ───────────────────────────────────────────────────────
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    server = ThreadedHTTPServer((BIND_HOST, PORT), Handler)

    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        proto = "https"
        log.info("TLS habilitado  cert=%s", CERT_FILE)
    else:
        proto = "http"
        log.warning(
            "Certs TLS no encontrados en %s — corriendo en HTTP plano.\n"
            "Ejecuta setup_security.sh para habilitar HTTPS.", CERT_FILE
        )

    token_hash = hashlib.sha256(TOKEN.encode()).hexdigest()
    log.info("Servidor escuchando en %s://%s:%d", proto, BIND_HOST, PORT)
    log.info("Token SHA-256: %s…%s", token_hash[:8], token_hash[-8:])

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Detenido.")


if __name__ == "__main__":
    main()
