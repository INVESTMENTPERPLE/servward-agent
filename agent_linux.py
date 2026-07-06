#!/usr/bin/env python3
"""
Servward — Agente para Linux
Escucha comandos del broker (SSE) y los ejecuta en el servidor Linux.
Mismo protocolo que agent.py (macOS), pero con comandos Linux.

Independiente del Mac: usa sus propios topics (cmd-linux-prod / resp-linux-prod).

Config por variables de entorno:
    NTFY_TOKEN        token bearer (mismo que el broker)
    NTFY_SERVER       URL del broker         (def: http://127.0.0.1:2586)
    NTFY_CMD_TOPIC    topic de órdenes       (def: cmd-linux-prod)
    NTFY_RESP_TOPIC   topic de respuestas    (def: resp-linux-prod)
    NTFY_DEVICE_NAME  nombre informativo     (def: hostname)
    ALLOW_POWER       "1" para permitir reboot/poweroff (def: desactivado)
    SCRIPTS_DIR       carpeta de scripts permitidos (def: /opt/ntfy/scripts)
"""

import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

try:
    import psutil
except ImportError:
    sys.exit("[FATAL] Falta psutil. Instala: sudo apt-get install -y python3-psutil")

# ── Configuración ───────────────────────────────────────────────────────────
TOKEN       = os.environ.get("NTFY_TOKEN", "").strip()
NTFY_BASE   = os.environ.get("NTFY_SERVER", "http://127.0.0.1:2586").strip().rstrip("/")
CMD_TOPIC   = os.environ.get("NTFY_CMD_TOPIC",  "cmd-linux-prod").strip()
RESP_TOPIC  = os.environ.get("NTFY_RESP_TOPIC", "resp-linux-prod").strip()
DEVICE_NAME = os.environ.get("NTFY_DEVICE_NAME", socket.gethostname()).strip()
ALLOW_POWER = os.environ.get("ALLOW_POWER", "0").strip() == "1"
SCRIPTS_DIR = os.environ.get("SCRIPTS_DIR", "/opt/ntfy/scripts").strip()
SERVICE_WHITELIST = [s.strip() for s in os.environ.get(
    "SERVICE_WHITELIST", "cloudflared,ntfy-server,ntfy-agent,nginx,ssh,docker").split(",") if s.strip()]
RECONNECT_S = 5
REQ_TIMEOUT = 30

if not TOKEN:
    sys.exit("[FATAL] NTFY_TOKEN no definido.")

AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"}
SSL_CTX = ssl.create_default_context()  # verificación del sistema (Cloudflare) si es https

def log(msg: str):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}", flush=True)

def _run(cmd, timeout=10) -> str:
    return subprocess.check_output(cmd, text=True, timeout=timeout,
                                   stderr=subprocess.DEVNULL).strip()

# ── Comandos ────────────────────────────────────────────────────────────────

def cmd_check_status(_args: dict) -> dict:
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot = psutil.boot_time()
    up_s = int(time.time() - boot)
    return {
        "hostname": platform.node(),
        "os":       f"{platform.system()} {platform.release()}",
        "platform": "linux",
        "cpu_pct":  f"{psutil.cpu_percent(interval=0.5):.0f}",
        "ram_pct":  f"{mem.percent:.0f}",
        "disk_pct": f"{disk.percent:.0f}",
        "uptime":   _fmt_uptime(up_s),
        "load":     ", ".join(f"{x:.2f}" for x in os.getloadavg()),
    }

def cmd_ping_service(_args: dict) -> dict:
    # Comprobación TCP (sin privilegios; ICMP requeriría root/cap_net_raw)
    for host, port, name in [("1.1.1.1", 443, "Cloudflare"), ("8.8.8.8", 443, "Google")]:
        t0 = time.time()
        try:
            with socket.create_connection((host, port), timeout=3):
                ms = (time.time() - t0) * 1000
                return {"conectividad": "ok", "via": f"{name} ({host})", "latencia": f"{ms:.0f} ms"}
        except Exception:
            continue
    return {"conectividad": "sin salida a internet"}

def cmd_network_speed(_args: dict) -> dict:
    # Preferir el CLI oficial de Ookla si está instalado (medición real).
    if shutil.which("speedtest"):
        try:
            env = dict(os.environ, HOME="/tmp")
            out = subprocess.run(
                ["speedtest", "--format=json", "--accept-license", "--accept-gdpr"],
                capture_output=True, text=True, timeout=90, env=env)
            data = json.loads(out.stdout)
            dl   = data["download"]["bandwidth"] * 8 / 1e6   # bytes/s → Mbps
            ul   = data["upload"]["bandwidth"]   * 8 / 1e6
            res  = {"bajada": f"{dl:.0f} Mbps", "subida": f"{ul:.0f} Mbps"}
            ping = data.get("ping", {}).get("latency")
            if ping is not None:
                res["ping"] = f"{ping:.0f} ms"
            srv = data.get("server", {}).get("name")
            if srv:
                res["servidor"] = srv
            return res
        except Exception as e:
            return {"error": f"speedtest falló ({e})"}
    # Respaldo: estimación con varias descargas en paralelo desde Cloudflare.
    return _speed_fallback()

def _speed_fallback() -> dict:
    import threading
    url      = "https://speed.cloudflare.com/__down?bytes=25000000"  # 25 MB por petición
    streams  = 4
    warmup   = 1.5    # s de calentamiento (no se cuentan)
    measure  = 6.0    # s de medición
    counters = [0] * streams
    counting = {"on": False}
    errors   = []
    stop     = threading.Event()

    def worker(i):
        try:
            while not stop.is_set():
                req = urllib.request.Request(url, headers={"User-Agent": "ntfy-agent"})
                with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as r:
                    while not stop.is_set():
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        if counting["on"]:
                            counters[i] += len(chunk)
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in threads:
        t.start()
    time.sleep(warmup)
    t0 = time.time(); counting["on"] = True
    time.sleep(measure)
    counting["on"] = False
    dt = time.time() - t0
    stop.set()

    total = sum(counters)
    if total == 0:
        return {"error": f"sin datos ({errors[0] if errors else 'sin excepción'})"}
    mbps = (total * 8 / 1e6) / dt
    return {"bajada": f"{mbps:.0f} Mbps",
            "metodo": f"{streams} conexiones · {dt:.0f}s",
            "descargado": f"{total/1e6:.0f} MB"}

def cmd_uptime(_args: dict) -> dict:
    up_s = int(time.time() - psutil.boot_time())
    return {"uptime": _fmt_uptime(up_s),
            "desde": time.strftime("%Y-%m-%d %H:%M", time.localtime(psutil.boot_time()))}

def cmd_disks(_args: dict) -> dict:
    out = {}
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            out[p.mountpoint] = f"{_gb(u.used)}/{_gb(u.total)} GB ({u.percent:.0f}%)"
        except Exception:
            continue
    return out or {"discos": "sin datos"}

def cmd_temperatures(_args: dict) -> dict:
    try:
        temps = psutil.sensors_temperatures()
    except Exception:
        temps = {}
    if not temps:
        return {"temperatura": "no disponible en este servidor"}
    out = {}
    for chip, entries in temps.items():
        for e in entries:
            if e.current:
                out[f"{chip}/{e.label or 'temp'}"] = f"{e.current:.1f}°C"
    return out or {"temperatura": "no disponible"}

def cmd_processes(_args: dict) -> dict:
    procs = []
    for p in psutil.process_iter(["name", "cpu_percent", "memory_percent"]):
        procs.append(p.info)
    procs.sort(key=lambda x: (x.get("cpu_percent") or 0), reverse=True)
    top = procs[:8]
    lines = [f"{p['name'][:20]:20} cpu {p.get('cpu_percent') or 0:>4.0f}%  ram {p.get('memory_percent') or 0:>4.1f}%"
             for p in top]
    return {"top_procesos": "\n".join(lines)}

def cmd_services(_args: dict) -> dict:
    """Estado de servicios systemd clave (las 'más cosas' del Linux)."""
    units = ["cloudflared", "ntfy-server", "docker", "nginx", "ssh"]
    out = {}
    for u in units:
        try:
            st = _run(["systemctl", "is-active", u], timeout=4)
        except Exception:
            st = "no-encontrado"
        out[u] = st
    return out

def cmd_docker(_args: dict) -> dict:
    if not shutil.which("docker"):
        return {"docker": "no instalado"}
    try:
        out = _run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"], timeout=8)
        if not out:
            return {"docker": "(sin contenedores)"}
        result = {}
        for line in out.splitlines():
            if "\t" in line:
                name, status = line.split("\t", 1)
                result[name] = status
        return result or {"docker": "(sin contenedores)"}
    except Exception as e:
        return {"docker": f"sin permiso o error ({e})"}

def cmd_service_action(args: dict) -> dict:
    name   = args.get("name", "").strip()
    action = args.get("action", "status").strip()
    if name not in SERVICE_WHITELIST:
        return {"error": f"servicio no permitido: {name}"}
    if action == "status":
        try:
            return {"servicio": name, "estado": _run(["systemctl", "is-active", name], timeout=5)}
        except Exception:
            return {"servicio": name, "estado": "inactivo"}
    if action not in ("start", "stop", "restart"):
        return {"error": f"acción inválida: {action}"}
    try:
        r = subprocess.run(["sudo", "-n", "systemctl", action, name],
                           capture_output=True, text=True, timeout=25)
        if r.returncode == 0:
            return {"servicio": name, "accion": action, "resultado": "ok"}
        err = (r.stderr or r.stdout).strip()
        if "password is required" in err or "no tty" in err.lower() or "not allowed" in err.lower():
            return {"error": "el agente no tiene permiso sudo (ver configuración de servicios)"}
        return {"error": err[:200] or f"fallo (código {r.returncode})"}
    except Exception as e:
        return {"error": str(e)}

def cmd_docker_action(args: dict) -> dict:
    name   = args.get("name", "").strip()
    action = args.get("action", "").strip()
    if not shutil.which("docker"):
        return {"docker": "no instalado"}
    if not name:
        return {"error": "falta 'name'"}
    if action not in ("start", "stop", "restart"):
        return {"error": f"acción inválida: {action}"}
    try:
        r = subprocess.run(["docker", action, name], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return {"contenedor": name, "accion": action, "resultado": "ok"}
        return {"error": (r.stderr or r.stdout).strip()[:200] or f"fallo (código {r.returncode})"}
    except Exception as e:
        return {"error": str(e)}

def cmd_kill_process(args: dict) -> dict:
    name = args.get("name", "").strip()
    if not name:
        return {"error": "falta 'name'"}
    try:
        subprocess.run(["pkill", "-f", name], timeout=5, check=False)
        return {"resultado": f"señal enviada a procesos '{name}'"}
    except Exception as e:
        return {"error": str(e)}

def cmd_run_script(args: dict) -> dict:
    name = args.get("script", "").strip()
    if not name or "/" in name or name.startswith("."):
        return {"error": "nombre de script inválido"}
    path = os.path.join(SCRIPTS_DIR, name)
    if not os.path.isfile(path):
        return {"error": f"no existe {path}"}
    try:
        out = subprocess.run(["bash", path], capture_output=True, text=True, timeout=60)
        return {"salida": (out.stdout or out.stderr)[-1500:] or "(sin salida)",
                "code": str(out.returncode)}
    except Exception as e:
        return {"error": str(e)}

def cmd_restart(_args: dict) -> dict:
    if not ALLOW_POWER:
        return {"bloqueado": "reinicio desactivado (pon ALLOW_POWER=1 para permitirlo)"}
    subprocess.Popen(["systemctl", "reboot"])
    return {"status": "Reiniciando…"}

def cmd_shutdown(_args: dict) -> dict:
    if not ALLOW_POWER:
        return {"bloqueado": "apagado desactivado (pon ALLOW_POWER=1 para permitirlo)"}
    subprocess.Popen(["systemctl", "poweroff"])
    return {"status": "Apagando…"}

def _not_supported(_args: dict) -> dict:
    return {"info": "comando no soportado en Linux"}

# ── Helpers ─────────────────────────────────────────────────────────────────
def _gb(n) -> str:  return f"{n / (1024**3):.0f}"
def _fmt_uptime(s: int) -> str:
    d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, _ = divmod(s, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    parts.append(f"{m}m")
    return " ".join(parts)

# ── Mapa de comandos (mismos nombres que la app) ────────────────────────────
COMMAND_MAP = {
    "check_status":  cmd_check_status,
    "ping_service":  cmd_ping_service,
    "uptime":        cmd_uptime,
    "disks":         cmd_disks,
    "temperatures":  cmd_temperatures,
    "last_jobs":     cmd_processes,      # en Linux: top de procesos
    "network_speed": lambda a: cmd_network_speed(a),
    "restart_mac":   cmd_restart,        # reinicia el Linux (si ALLOW_POWER=1)
    "shutdown_mac":  cmd_shutdown,       # apaga el Linux (si ALLOW_POWER=1)
    "sleep_mac":     _not_supported,
    "screenshot":    _not_supported,
    "mute":          _not_supported,
    "unmute":        _not_supported,
    "set_volume":    _not_supported,
    "get_volume":    _not_supported,
    "open":          _not_supported,
    "kill_process":  cmd_kill_process,
    "run_script":    cmd_run_script,
    # extra Linux
    "services":       cmd_services,
    "docker":         cmd_docker,
    "processes":      cmd_processes,
    "service_action": cmd_service_action,
    "docker_action":  cmd_docker_action,
}

# ── Publicar respuesta ──────────────────────────────────────────────────────
def publish(req_id: str, status: str, data: dict):
    payload = {
        "id":     f"resp_{int(time.time())}",
        "req_id": req_id,
        "status": status,
        "data":   data,
        "ts":     int(time.time()),
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{NTFY_BASE}/{RESP_TOPIC}", data=body, method="POST",
                                 headers={**AUTH_HEADERS, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=REQ_TIMEOUT) as r:
            log(f"PUBLISHED req_id={req_id} status={status} http={r.status}")
    except Exception as e:
        log(f"PUBLISH_ERROR {e}")

# ── Procesar comando ────────────────────────────────────────────────────────
def handle(raw_msg: str):
    try:
        msg    = json.loads(raw_msg)
        req_id = msg.get("id", "unknown")
        cmd    = msg.get("cmd", "")
        args   = msg.get("args", {})
        device = msg.get("device", "?")
        log(f"CMD cmd={cmd} from={device} req_id={req_id}")
        fn = COMMAND_MAP.get(cmd)
        if fn is None:
            publish(req_id, "error", {"error": f"Comando desconocido: {cmd}"})
            return
        publish(req_id, "ok", fn(args))
    except Exception as e:
        log(f"HANDLE_ERROR {e}")
        try:
            publish(json.loads(raw_msg).get("id", "unknown"), "error", {"error": str(e)})
        except Exception:
            pass

# ── Bucle SSE ───────────────────────────────────────────────────────────────
def listen_loop():
    url = f"{NTFY_BASE}/{CMD_TOPIC}/sse"
    headers = {**AUTH_HEADERS, "Accept": "text/event-stream", "Cache-Control": "no-cache"}
    ctx = SSL_CTX if NTFY_BASE.startswith("https") else None
    while True:
        log(f"Conectando a {url} …")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=None) as resp:
                log("Conectado. Esperando comandos…")
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data: "):
                        try:
                            env = json.loads(line[6:])
                            if env.get("event") == "message" and env.get("message"):
                                # Cada comando en su hilo: uno lento no bloquea a los demás.
                                threading.Thread(target=handle, args=(env["message"],),
                                                 daemon=True).start()
                        except json.JSONDecodeError:
                            pass
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log("401 — revisa NTFY_TOKEN."); time.sleep(30)
            elif e.code == 429:
                log("429 rate limit — espero 60s."); time.sleep(60)
            else:
                log(f"HTTP {e.code} — reconecto en {RECONNECT_S}s."); time.sleep(RECONNECT_S)
        except Exception as e:
            log(f"Desconectado ({e}) — reconecto en {RECONNECT_S}s."); time.sleep(RECONNECT_S)

if __name__ == "__main__":
    log(f"Servward Agente Linux — {len(COMMAND_MAP)} comandos")
    log(f"Broker: {NTFY_BASE}  topics: {CMD_TOPIC} / {RESP_TOPIC}")
    listen_loop()
