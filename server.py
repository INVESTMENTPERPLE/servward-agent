#!/usr/bin/env python3
"""
Servward — Pub-Sub Server (Hardened)
HTTPS · Token Bearer · Rate Limiting · IP Binding · Request Size Limit

Requisitos previos:
    source ~/.ntfy_env          (o export NTFY_TOKEN=... manualmente)
    python3 server.py
"""

import hashlib
import json
import logging
import os
import secrets
import ssl
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import base64
import re
import struct

# ── Configuración (todo desde env vars) ─────────────────────────────────────
TOKEN     = os.environ.get("NTFY_TOKEN", "").strip()
TOKEN_RO  = os.environ.get("NTFY_TOKEN_RO", "").strip()   # token de SOLO LECTURA (opcional)
TOKEN_NEXT = os.environ.get("NTFY_TOKEN_NEXT", "").strip()  # rotación: se acepta junto al de control
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
DEVICE_TOKEN_FILE = os.environ.get("DEVICE_TOKEN_FILE",
                                   os.path.expanduser("~/.ntfy_device_tokens.json"))
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
        # 0600 y O_NOFOLLOW: no legible por otros usuarios ni redirigible por symlink.
        data = json.dumps(tokens).encode()
        fd = os.open(DEVICE_TOKEN_FILE,
                     os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

def _remove_device_token(token: str):
    with _dt_lock:
        tokens = [t for t in _load_device_tokens() if t != token]
        data = json.dumps(tokens).encode()
        fd = os.open(DEVICE_TOKEN_FILE,
                     os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

# ── Códigos de emparejamiento (en memoria, efímeros; NO se persisten) ─────────
PAIR_TTL_DEFAULT = 300
PAIR_TTL_MAX     = 1800
PAIR_TTL_MIN     = 30
PAIR_CODE_LEN    = 10
PAIR_MAX_ACTIVE  = 100
PAIR_MAX_USES    = 5
_PAIR_ALPHABET   = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"   # sin 0 O 1 I L
_pairings: dict = {}
_pair_lock = threading.Lock()

def _pair_new_code():
    return "".join(secrets.choice(_PAIR_ALPHABET) for _ in range(PAIR_CODE_LEN))

def _pair_sweep_locked():
    now = time.monotonic()
    for c in [c for c, v in _pairings.items() if v["expires"] <= now or v["uses"] <= 0]:
        del _pairings[c]

def _pair_create(payload: dict, ttl: int, uses: int) -> str:
    with _pair_lock:
        _pair_sweep_locked()
        if len(_pairings) >= PAIR_MAX_ACTIVE:
            raise RuntimeError("too many active pairing codes")
        code = _pair_new_code()
        for _ in range(5):
            if code not in _pairings:
                break
            code = _pair_new_code()
        _pairings[code] = {"expires": time.monotonic() + ttl, "uses": uses, "payload": payload}
        return code

def _pair_redeem(code):
    with _pair_lock:
        _pair_sweep_locked()
        entry = _pairings.get(code)
        if not entry:
            return None
        entry["uses"] -= 1
        payload = entry["payload"]
        if entry["uses"] <= 0:
            del _pairings[code]
        return payload

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
def _ct_eq(header_value: str, secret: str) -> bool:
    """Compara 'Bearer <secret>' byte a byte en tiempo constante (anti timing)."""
    expected = f"Bearer {secret}"
    if len(header_value) != len(expected):
        return False
    result = 0
    for a, b in zip(header_value.encode(), expected.encode()):
        result |= a ^ b
    return result == 0

def _token_scope(header_value: str):
    """'rw' si es el token de control, 'ro' si es el de solo lectura, None si no.
    Comprueba SIEMPRE ambos (sin cortocircuito) para no filtrar cuál falló."""
    ok_rw = _ct_eq(header_value, TOKEN) or (bool(TOKEN_NEXT) and _ct_eq(header_value, TOKEN_NEXT))
    ok_ro = bool(TOKEN_RO) and _ct_eq(header_value, TOKEN_RO)
    if ok_rw:
        return "rw"
    if ok_ro:
        return "ro"
    return None

def _token_ok(header_value: str) -> bool:
    return _token_scope(header_value) is not None

# ── Handler HTTP ──────────────────────────────────────────────────────────────
# ── Relé WebSocket para terminales: /term/<canal>?role=agent|app ─────────────
# El agente abre un cliente tmux en un pseudoterminal y conecta aquí como «agent»; la app
# conecta como «app». El broker copia las tramas de uno a otro sin mirarlas: los bytes del
# terminal van al móvil y las teclas del móvil van al terminal. Sin dependencias: apretón
# de manos y tramas (RFC 6455) a mano. Mismo token Bearer que el resto del broker.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TERM_CHAN_RE = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
_TERM_PENDING_MAX = 512 * 1024
term_channels: dict = {}          # canal → {"agent": _WSConn|None, "app": _WSConn|None, "pending": {rol: [bytes]}}
term_lock = threading.Lock()

class _WSConn:
    """Una conexión WebSocket ya negociada (lado servidor: recibe enmascarado, envía en claro)."""
    def __init__(self, rfile, sock, peer: str):
        self.rfile = rfile
        self.sock = sock
        self.peer = peer
        self.wlock = threading.Lock()
        self.closed = False

    def send(self, opcode: int, payload: bytes):
        n = len(payload)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([n])
        elif n < 65536:
            head += bytes([126]) + struct.pack(">H", n)
        else:
            head += bytes([127]) + struct.pack(">Q", n)
        with self.wlock:
            if self.closed:
                return
            try:
                self.sock.sendall(head + payload)
            except OSError:
                self.closed = True

    def recv(self):
        """(opcode, payload) de la siguiente trama de datos; None si se cerró. Contesta a los
        ping. Las tramas fragmentadas se reensamblan."""
        message = b""
        msg_op = None
        while True:
            h = self.rfile.read(2)
            if len(h) < 2:
                return None
            fin = h[0] & 0x80
            op = h[0] & 0x0F
            masked = h[1] & 0x80
            n = h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self.rfile.read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self.rfile.read(8))[0]
            if n > 8 * 1024 * 1024:
                return None
            key = self.rfile.read(4) if masked else b""
            data = self.rfile.read(n) if n else b""
            if len(data) < n:
                return None
            if masked:
                data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
            if op == 0x8:
                return None
            if op == 0x9:
                self.send(0xA, data)
                continue
            if op == 0xA:
                continue
            if op in (0x1, 0x2):
                msg_op = op
                message = data
            elif op == 0x0:
                message += data
            else:
                continue
            if fin:
                return (msg_op or 0x2, message)

    def close(self):
        if self.closed:
            return
        try:
            self.send(0x8, b"")
        except Exception:
            pass
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


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
        peer = self.client_address[0]
        # Solo confiamos en las cabeceras de proxy si la conexión llega del túnel
        # local (Cloudflare -> 127.0.0.1). Desde Tailscale/LAN el peer es la IP
        # real del cliente: NO honramos las cabeceras, para que no se puedan
        # falsear y evadir el rate-limit ni el bypass "local".
        if peer in ("127.0.0.1", "::1"):
            cf = self.headers.get("CF-Connecting-IP")
            if cf:
                return cf.strip()
            xff = self.headers.get("X-Forwarded-For")
            if xff:
                return xff.split(",")[0].strip()
        return peer

    # ── Autenticación ─────────────────────────────────────────────────────────
    def _auth(self) -> bool:
        ip    = self._client_ip()
        local = ip in ("127.0.0.1", "::1")   # agente local / origen del túnel: nunca se bloquea
        if not local and _is_blocked(ip):
            log.warning("BLOCKED  ip=%-15s (rate limit)", ip)
            self._error(429, "too many failed attempts — try again later")
            return False
        auth_header = self.headers.get("Authorization", "")
        scope = _token_scope(auth_header)
        if scope is None:
            if local:
                log.warning("AUTH_FAIL ip=%-15s (local, sin bloqueo)", ip)
            else:
                count = _record_fail(ip)
                log.warning("AUTH_FAIL ip=%-15s  attempt=%d/%d", ip, count, RATE_LIMIT_MAX)
            self._error(401, "unauthorized")
            return False
        self.auth_scope = scope
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
        # Requiere el token bearer: cloudflared reenvía el tráfico público a
        # 127.0.0.1, así que el filtro por peer NO basta para protegerlo.
        if not self._auth(): return
        ip = self.client_address[0]
        if ip not in ("127.0.0.1", "::1"):
            self._error(403, "forbidden"); return
        tokens = _load_device_tokens()
        self._json(200, {"tokens": tokens})

    # ── POST /pair  ──  crear un código de emparejamiento (requiere token rw) ──
    def _handle_pair_post(self):
        if not self._auth(): return
        if getattr(self, "auth_scope", "") != "rw":
            self._error(403, "read-only token cannot create pairings"); return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0 or length > 4096:
            self._error(400, "invalid body"); return
        try:
            data = json.loads(self.rfile.read(length))
            assert isinstance(data, dict)
        except Exception:
            self._error(400, "invalid json"); return
        scope = str(data.get("scope") or "rw").strip().lower()
        if scope not in ("rw", "ro"):
            self._error(400, "invalid scope"); return
        if scope == "ro" and not TOKEN_RO:
            self._error(400, "read-only token not configured on server"); return
        share_token = TOKEN_RO if scope == "ro" else TOKEN
        def clean(key, maxlen):
            v = data.get(key, "")
            return v.strip()[:maxlen] if isinstance(v, str) else ""
        payload = {"name": clean("name", 100), "url": clean("url", 300),
                   "cmd": clean("cmd", 100), "resp": clean("resp", 100),
                   "cf": clean("cf", 400), "token": share_token,
                   "ro": "1" if scope == "ro" else "0"}
        try:    ttl = int(data.get("ttl", PAIR_TTL_DEFAULT))
        except Exception: ttl = PAIR_TTL_DEFAULT
        ttl = max(PAIR_TTL_MIN, min(ttl, PAIR_TTL_MAX))
        try:    uses = int(data.get("uses", 1))
        except Exception: uses = 1
        uses = max(1, min(uses, PAIR_MAX_USES))
        try:
            code = _pair_create(payload, ttl, uses)
        except RuntimeError:
            self._error(429, "too many active pairing codes — try later"); return
        log.info("PAIR_CREATE scope=%s ttl=%ds uses=%d code=%.3s…", scope, ttl, uses, code)
        self._json(200, {"code": code, "expires_in": ttl, "uses": uses})

    # ── POST /redeem  ──  canjear un código (SIN token) ──────────────────────
    def _handle_redeem_post(self):
        ip = self._client_ip()
        if _is_blocked(ip):
            self._error(429, "too many attempts — try again later"); return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0 or length > 256:
            self._error(400, "invalid body"); return
        try:
            code = json.loads(self.rfile.read(length)).get("code", "")
        except Exception:
            self._error(400, "invalid json"); return
        code = code.strip().upper() if isinstance(code, str) else ""
        if len(code) != PAIR_CODE_LEN or any(ch not in _PAIR_ALPHABET for ch in code):
            _record_fail(ip)
            self._error(404, "invalid or expired code"); return
        payload = _pair_redeem(code)
        if payload is None:
            _record_fail(ip)
            self._error(404, "invalid or expired code"); return
        log.info("REDEEM_OK ip=%s name=%.20s ro=%s", ip, payload.get("name", ""), payload.get("ro"))
        self._json(200, payload)

    # ── POST /topic  ──  publicar ─────────────────────────────────────────────
    def do_POST(self):
        _p = self.path.rstrip("/")
        if _p == "/device-token":
            self._handle_device_token_post(); return
        if _p == "/pair":
            self._handle_pair_post(); return
        if _p == "/redeem":
            self._handle_redeem_post(); return
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

        # El broker es la ÚNICA fuente de verdad del scope: lo fija según qué token
        # autenticó el POST y DESCARTA cualquier 'scope' que enviara el cliente.
        if isinstance(msg, dict):
            msg["scope"] = getattr(self, "auth_scope", "rw")

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

    # ── DELETE /device-token  ──  quitar un token APNs caducado (410)
    def do_DELETE(self):
        if self.path.rstrip("/") != "/device-token":
            self._error(404, "not found"); return
        if not self._auth(): return
        length = int(self.headers.get("Content-Length", 0))
        if length == 0 or length > 512:
            self._error(400, "invalid body"); return
        try:
            token = json.loads(self.rfile.read(length)).get("device_token", "").strip()
        except Exception:
            self._error(400, "invalid json"); return
        if token:
            _remove_device_token(token)
            log.info("DEVICE_TOKEN_REMOVED  token=%.8s…", token)
        self._json(200, {"ok": True})

    # ── GET /topic/sse  ──  suscribirse ───────────────────────────────────────
    def _handle_term_ws(self, chan: str, role: str):
        """Negocia el WebSocket y releva tramas con el otro extremo del canal."""
        if role not in ("agent", "app") or not _TERM_CHAN_RE.match(chan):
            self._error(400, "bad channel"); return
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self._error(426, "websocket required"); return
        if not self._auth():
            return
        if getattr(self, "auth_scope", "") != "rw":
            self._error(403, "read-only token"); return
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self._error(400, "missing key"); return
        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        self.connection.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n")
        self.close_connection = True
        ip = self.client_address[0]
        conn = _WSConn(self.rfile, self.connection, ip)
        other = "app" if role == "agent" else "agent"
        with term_lock:
            ch = term_channels.setdefault(chan, {"agent": None, "app": None, "pending": {"agent": [], "app": []}})
            old = ch.get(role)
            ch[role] = conn
            # Lo que el otro lado mandó antes de que llegáramos, ahora.
            backlog = ch["pending"][role]
            ch["pending"][role] = []
        if old is not None:
            old.close()
        log.info("TERM_WS  chan=%s role=%s from=%s  connected", chan[:12], role, ip)
        for data in backlog:
            conn.send(0x2, data)
        try:
            while True:
                frame = conn.recv()
                if frame is None:
                    break
                op, data = frame
                with term_lock:
                    peer = term_channels.get(chan, {}).get(other)
                    if peer is None:
                        pend = term_channels.get(chan, {}).get("pending", {}).get(other)
                        if pend is not None and sum(len(p) for p in pend) < _TERM_PENDING_MAX:
                            pend.append(data)
                        continue
                peer.send(op, data)
        except Exception as e:
            log.debug("TERM_WS chan=%s role=%s error %s", chan[:12], role, e)
        finally:
            conn.close()
            with term_lock:
                ch = term_channels.get(chan)
                peer = None
                if ch and ch.get(role) is conn:
                    ch[role] = None
                    peer = ch.get(other)
                    ch[other] = None
                    term_channels.pop(chan, None)
            if peer is not None:
                peer.close()                       # se va uno, se va el otro: el tmux se desengancha
            log.info("TERM_WS  chan=%s role=%s from=%s  closed", chan[:12], role, ip)

    def do_GET(self):
        if self.path.rstrip("/") == "/device-tokens":
            self._handle_device_token_get(); return
        if self.path.startswith("/term/"):
            rest = self.path[len("/term/"):]
            chan, _, query = rest.partition("?")
            role = ""
            for kv in query.split("&"):
                k, _, v = kv.partition("=")
                if k == "role":
                    role = v
            self._handle_term_ws(chan.strip("/"), role); return
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
    if TOKEN_RO:
        ro_hash = hashlib.sha256(TOKEN_RO.encode()).hexdigest()
        log.info("Token RO SHA-256: %s…%s (solo lectura)", ro_hash[:8], ro_hash[-8:])
    if TOKEN_NEXT:
        log.info("Token NEXT activo (rotación en curso): se acepta el viejo y el nuevo")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Detenido.")


if __name__ == "__main__":
    main()
