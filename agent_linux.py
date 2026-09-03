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
    ALLOW_CLAUDE_CONTROL "1" para responder/parar/arrancar sesiones de Claude Code
                      (def: desactivado; NUNCA en un nodo de producción)
    SCRIPTS_DIR       carpeta de scripts permitidos (def: /opt/ntfy/scripts)
"""

import glob
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from collections import deque
from datetime import datetime, timezone

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
SSE_TIMEOUT = int(os.environ.get("SSE_TIMEOUT", "70"))  # watchdog: reconecta si el broker no manda datos/heartbeat en Ns
REQ_TIMEOUT = 30

# ── Alertas en background ─────────────────────────────────────────────────────
# Push APNs OPCIONAL: requiere los certs del desarrollador (APNS_CERT/APNS_KEY).
# Sin certs, el monitor evalúa igual y deja las alertas en el log.
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
APNS_CERT    = os.environ.get("APNS_CERT", os.path.join(_SCRIPT_DIR, "aps_cert.pem"))
APNS_KEY     = os.environ.get("APNS_KEY",  os.path.join(_SCRIPT_DIR, "apns_private_key.pem"))
APNS_BUNDLE  = "com.espymelab.NtfyControl"
APNS_HOST    = "api.push.apple.com"
DEVICE_TOKEN_URL = f"{NTFY_BASE}/device-tokens"

ALERT_CPU_PCT      = float(os.environ.get("ALERT_CPU_PCT",  "85"))
ALERT_RAM_PCT      = float(os.environ.get("ALERT_RAM_PCT",  "85"))
ALERT_DISK_PCT     = float(os.environ.get("ALERT_DISK_PCT", "90"))
ALERT_TEMP_C       = float(os.environ.get("ALERT_TEMP_C",   "80"))
MONITOR_INTERVAL_S = int(os.environ.get("MONITOR_INTERVAL", "60"))
ALERT_COOLDOWN_S   = 600
CUSTOM_ALERTS_FILE = os.environ.get("ALERTS_FILE",
                                    os.path.join(_SCRIPT_DIR, "custom_alerts.json"))

if not TOKEN:
    sys.exit("[FATAL] NTFY_TOKEN no definido.")

AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"}
SSL_CTX = ssl.create_default_context()  # verificación del sistema (Cloudflare) si es https

AGENT_VERSION = "1.7.0"
LASTBOOT_FILE = os.environ.get("LASTBOOT_FILE", os.path.join(_SCRIPT_DIR, "last_boot"))

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
        "version":  AGENT_VERSION,
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
    if not re.match(r'^[\w\-\.]+$', name) or len(re.sub(r'[^A-Za-z0-9]', '', name)) < 2:
        return {"error": "nombre de proceso inválido (mín. 2 alfanuméricos; sin comodines)"}
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

def cmd_list_scripts(_args: dict) -> dict:
    """Lista los scripts .sh de SCRIPTS_DIR (para el selector de la app)."""
    if not os.path.isdir(SCRIPTS_DIR):
        return {"scripts": "", "info": f"La carpeta {SCRIPTS_DIR} no existe todavía"}
    files = sorted(f for f in os.listdir(SCRIPTS_DIR) if f.endswith(".sh"))
    return {"scripts": "\n".join(files)}

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

# ══════════════════════════════════════════════════════════════════════════════
#  ALERTAS EN BACKGROUND (umbrales + reglas personalizadas)
# ══════════════════════════════════════════════════════════════════════════════

_last_alert: dict = {}
_custom_alerts: list = []
_alerts_lock = threading.Lock()
_script_last: dict = {}
_apns_warned = [False]

def _can_alert(key, cooldown=ALERT_COOLDOWN_S):
    now = time.monotonic()
    if now - _last_alert.get(key, 0) > cooldown:
        _last_alert[key] = now
        return True
    return False

def _get_device_tokens():
    try:
        req = urllib.request.Request(DEVICE_TOKEN_URL, headers=AUTH_HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("tokens", [])
    except Exception:
        return []

def _remove_device_token(token):
    try:
        req = urllib.request.Request(DEVICE_TOKEN_URL[:-1],
                                     data=json.dumps({"device_token": token}).encode(),
                                     method="DELETE",
                                     headers={**AUTH_HEADERS, "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        log(f"DEVICE_TOKEN_REMOVED (410) {token[:8]}…")
    except Exception as e:
        log(f"REMOVE_TOKEN_ERROR {e}")

def send_push(title, body):
    """Push APNs vía curl. Sin certs (usuarios sin relay): solo log."""
    if not (os.path.isfile(APNS_CERT) and os.path.isfile(APNS_KEY)):
        if not _apns_warned[0]:
            _apns_warned[0] = True
            log("PUSH desactivado (sin certs APNs) — las alertas quedan en el log")
        log(f"ALERTA (sin push): {title} — {body}")
        return False
    tokens = _get_device_tokens()
    if not tokens:
        log("PUSH sin device tokens registrados")
        return False
    payload = json.dumps({"aps": {"alert": {"title": title, "body": body},
                                  "sound": "default", "category": "SW_ALERT"}})
    ok = False
    for token in tokens:
        cmd = ["curl", "--http2", "-s", "-o", "/dev/null", "-w", "%{http_code}",
               "--cert", APNS_CERT, "--key", APNS_KEY,
               "-H", f"apns-topic: {APNS_BUNDLE}",
               "-H", "apns-push-type: alert", "-H", "apns-priority: 10",
               "-d", payload, f"https://{APNS_HOST}/3/device/{token}"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.stdout.strip() == "200":
                ok = True
                log(f"PUSH_SENT {title!r}")
            else:
                log(f"PUSH_FAIL http={r.stdout.strip()}")
                if r.stdout.strip() == "410":
                    _remove_device_token(token)
        except Exception as e:
            log(f"PUSH_ERROR {e}")
    return ok

def _get_temp():
    try:
        temps = psutil.sensors_temperatures()
        vals = [e.current for entries in temps.values() for e in entries if e.current]
        return max(vals) if vals else None
    except Exception:
        return None

# ── Histórico de métricas (para la gráfica de la app) ─────────────────────────
METRICS_FILE = os.environ.get("METRICS_FILE", os.path.join(_SCRIPT_DIR, "metrics_history.json"))
METRICS_MAX  = 240                                   # ~4 h a 60 s por muestra
_metrics_hist = deque(maxlen=METRICS_MAX)            # [ts, cpu, ram, disk]
_metrics_lock = threading.Lock()

def _load_metrics():
    try:
        if os.path.isfile(METRICS_FILE):
            with open(METRICS_FILE) as fh:
                data = json.load(fh)
            if isinstance(data, list):
                with _metrics_lock:
                    for x in data[-METRICS_MAX:]:
                        if isinstance(x, list) and len(x) == 4:
                            _metrics_hist.append([int(x[0]), int(x[1]), int(x[2]), int(x[3])])
    except Exception as e:
        log(f"METRICS_LOAD_ERROR {e}")

def _save_metrics():
    try:
        with _metrics_lock:
            snapshot = list(_metrics_hist)
        with open(METRICS_FILE, "w") as fh:
            json.dump(snapshot, fh)
    except Exception as e:
        log(f"METRICS_SAVE_ERROR {e}")

def _record_metrics(cpu, ram, disk):
    with _metrics_lock:
        _metrics_hist.append([int(time.time()), int(round(cpu)),
                              int(round(ram)), int(round(disk))])
    _save_metrics()

def cmd_metrics_history(_args: dict) -> dict:
    with _metrics_lock:
        rows = list(_metrics_hist)
    if not rows:
        return {"count": "0", "step_s": str(MONITOR_INTERVAL_S)}
    return {
        "count":  str(len(rows)),
        "step_s": str(MONITOR_INTERVAL_S),
        "ts":     ",".join(str(r[0]) for r in rows),
        "cpu":    ",".join(str(r[1]) for r in rows),
        "ram":    ",".join(str(r[2]) for r in rows),
        "disk":   ",".join(str(r[3]) for r in rows),
    }

# ── Actualizaciones del sistema (APT) ─────────────────────────────────────────
def cmd_updates(_args: dict) -> dict:
    if not shutil.which("apt"):
        return {"count": "0", "manager": "desconocido",
                "info": "gestor de paquetes no soportado (solo apt)"}
    try:
        out = subprocess.run(["apt", "list", "--upgradable"],
                             capture_output=True, text=True, timeout=30,
                             env=dict(os.environ, LANG="C")).stdout
    except Exception as e:
        return {"error": str(e)}
    pkgs, sec = [], 0
    for line in out.splitlines():
        line = line.strip()
        if "/" in line and "[upgradable" in line:
            name = line.split("/", 1)[0]
            pkgs.append(name)
            if "-security" in line.split(" ", 1)[0]:
                sec += 1
    return {
        "count":    str(len(pkgs)),
        "security": str(sec),
        "list":     "\n".join(pkgs),
        "manager":  "APT",
    }

def cmd_apply_updates(_args: dict) -> dict:
    if not shutil.which("apt-get"):
        return {"error": "apt-get no disponible"}
    try:
        r = subprocess.run(["sudo", "-n", "apt-get", "-y", "upgrade"],
                           capture_output=True, text=True, timeout=600,
                           env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        low = out.lower()
        if "password is required" in low or "a terminal is required" in low or "not allowed" in low:
            return {"error": "el agente no tiene permiso sudo para apt (configura sudoers para apt-get)"}
        return {"resultado": "ok" if r.returncode == 0 else f"código {r.returncode}",
                "output": out[-1200:] or "(sin salida)"}
    except subprocess.TimeoutExpired:
        return {"error": "La actualización sigue en curso (>10 min). Vuelve a comprobar en un rato."}
    except Exception as e:
        return {"error": str(e)}

# ── Umbrales ajustables en caliente (paridad con el agente Mac) ──────────────
def cmd_set_thresholds(args: dict) -> dict:
    global ALERT_CPU_PCT, ALERT_RAM_PCT, ALERT_DISK_PCT, ALERT_TEMP_C, MONITOR_INTERVAL_S
    try:
        if "cpu" in args:      ALERT_CPU_PCT      = float(args["cpu"])
        if "ram" in args:      ALERT_RAM_PCT      = float(args["ram"])
        if "disk" in args:     ALERT_DISK_PCT     = float(args["disk"])
        if "temp" in args:     ALERT_TEMP_C       = float(args["temp"])
        if "interval" in args: MONITOR_INTERVAL_S = max(10, int(args["interval"]))
    except (ValueError, TypeError) as e:
        return {"error": f"Valor inválido: {e}"}
    log(f"Umbrales: cpu={ALERT_CPU_PCT} ram={ALERT_RAM_PCT} disk={ALERT_DISK_PCT} temp={ALERT_TEMP_C} int={MONITOR_INTERVAL_S}")
    return cmd_get_thresholds({})

def cmd_get_thresholds(_args: dict) -> dict:
    return {"ok": "true",
            "cpu_pct":   str(ALERT_CPU_PCT),
            "ram_pct":   str(ALERT_RAM_PCT),
            "disk_pct":  str(ALERT_DISK_PCT),
            "temp_c":    str(ALERT_TEMP_C),
            "intervalo": str(MONITOR_INTERVAL_S)}

# ── Alertas personalizadas ────────────────────────────────────────────────────
def _load_custom_alerts():
    global _custom_alerts
    try:
        if os.path.isfile(CUSTOM_ALERTS_FILE):
            with open(CUSTOM_ALERTS_FILE) as fh:
                data = json.load(fh)
            if isinstance(data, list):
                _custom_alerts = [r for r in data if isinstance(r, dict) and r.get("id")]
                log(f"CUSTOM_ALERTS cargadas: {len(_custom_alerts)} reglas")
    except Exception as e:
        log(f"ALERTS_LOAD_ERROR {e}")

def cmd_set_custom_alerts(args: dict) -> dict:
    global _custom_alerts
    try:
        rules = json.loads(args.get("rules", "[]"))
        assert isinstance(rules, list)
    except Exception:
        return {"error": "JSON de reglas inválido"}
    rules = [r for r in rules if isinstance(r, dict) and r.get("id")]
    with _alerts_lock:
        _custom_alerts = rules
        try:
            with open(CUSTOM_ALERTS_FILE, "w") as fh:
                json.dump(rules, fh, ensure_ascii=False)
        except Exception as e:
            log(f"ALERTS_SAVE_ERROR {e}")
    log(f"CUSTOM_ALERTS actualizadas: {len(rules)} reglas")
    return {"ok": "true", "count": str(len(rules))}

def cmd_get_custom_alerts(_args: dict) -> dict:
    with _alerts_lock:
        return {"rules": json.dumps(_custom_alerts, ensure_ascii=False),
                "count": str(len(_custom_alerts))}

def _quiet_now(rule) -> bool:
    try:
        qf = int(float(rule.get("quiet_from", -1)))
        qt = int(float(rule.get("quiet_to", -1)))
    except (TypeError, ValueError):
        return False
    if qf < 0 or qt < 0 or qf == qt:
        return False
    h = time.localtime().tm_hour
    return (qf <= h < qt) if qf < qt else (h >= qf or h < qt)

def _rule_fires(rule, metrics) -> bool:
    kind   = str(rule.get("kind", ""))
    target = str(rule.get("target", "")).strip()
    if kind == "metric":
        cur = metrics.get(target)
        if cur is None:
            return False
        try:
            val = float(rule.get("value", 0))
        except (TypeError, ValueError):
            return False
        return cur > val if str(rule.get("op", ">")) == ">" else cur < val
    if kind == "service":
        if not target or not re.match(r'^[\w\-\.@]+$', target):
            return False
        try:
            r = subprocess.run(["systemctl", "is-active", target],
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip() != "active"
        except Exception:
            return False
    if kind == "docker":
        if not target or not shutil.which("docker"):
            return False
        try:
            r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", target],
                               capture_output=True, text=True, timeout=8)
            return r.returncode != 0 or r.stdout.strip() != "true"
        except Exception:
            return False
    if kind == "script":
        if not target or "/" in target or target.startswith("."):
            return False
        rid = str(rule.get("id"))
        now = time.monotonic()
        if now - _script_last.get(rid, 0) < 600:   # scripts como mucho cada 10 min
            return False
        _script_last[rid] = now
        path = os.path.join(SCRIPTS_DIR, target)
        if not os.path.isfile(path):
            return False
        try:
            r = subprocess.run(["bash", path], capture_output=True, text=True, timeout=30)
            blob = (r.stdout or "") + (r.stderr or "")
            needle = str(rule.get("text", "")).strip()
            return bool(needle) and needle.lower() in blob.lower()
        except Exception:
            return False
    return False

def _eval_custom_alerts(metrics):
    with _alerts_lock:
        rules = list(_custom_alerts)
    for rule in rules:
        try:
            if str(rule.get("enabled", "1")).lower() in ("0", "false"):
                continue
            if _quiet_now(rule):
                continue
            if not _rule_fires(rule, metrics):
                continue
            try:
                cd = 60 * max(1, int(float(rule.get("cooldown_min", 30) or 30)))
            except (TypeError, ValueError):
                cd = 1800
            if not _can_alert(f"cust_{rule.get('id')}", cd):
                continue
            name = str(rule.get("name") or "Alerta")
            msg  = str(rule.get("message") or f"Regla «{name}» disparada en {platform.node()}")
            send_push(name, msg)
        except Exception as e:
            log(f"CUSTOM_ALERT_ERROR {e}")

def cmd_cert_expiry(args: dict) -> dict:
    """Días hasta que caduca el certificado TLS de cada host (hosts=a.com,b.com:8443)."""
    hosts = [h.strip() for h in args.get("hosts", "").split(",") if h.strip()]
    if not hosts:
        return {"info": "pasa hosts=dominio1.com,dominio2.com:8443"}
    ctx = ssl.create_default_context()
    out = {}
    for h in hosts[:10]:
        host, _, port = h.partition(":")
        try:
            with socket.create_connection((host, int(port or 443)), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            exp = ssl.cert_time_to_seconds(cert["notAfter"])
            out[host] = f"{int((exp - time.time()) / 86400)} dias"
        except Exception as e:
            out[host] = f"error: {str(e)[:60]}"
    return out

def cmd_check_endpoints(args: dict) -> dict:
    """Estado up/down + latencia de una lista de URLs (urls=https://a,https://b)."""
    urls = [u.strip() for u in args.get("urls", "").split(",") if u.strip()]
    if not urls:
        return {"info": "pasa urls=https://a.com,https://b.com"}
    out = {}
    for u in urls[:10]:
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "servward"})
            code = urllib.request.urlopen(req, timeout=8).status
            out[u] = f"up {code} ({int((time.monotonic() - t0) * 1000)} ms)"
        except urllib.error.HTTPError as e:
            out[u] = f"up {e.code} ({int((time.monotonic() - t0) * 1000)} ms)"
        except Exception as e:
            out[u] = f"DOWN ({type(e).__name__})"
    return out

def cmd_smart(_args: dict) -> dict:
    """Salud SMART de los discos (smartctl; suele requerir root -> sudo -n)."""
    if not shutil.which("smartctl"):
        return {"info": "smartctl no instalado (apt install smartmontools)"}
    def _sc(a):
        r = subprocess.run(["sudo", "-n", "smartctl"] + a, capture_output=True, text=True, timeout=15)
        low = (r.stderr + r.stdout).lower()
        if r.returncode != 0 and ("password is required" in low or "a terminal is required" in low):
            r = subprocess.run(["smartctl"] + a, capture_output=True, text=True, timeout=15)
        return r
    try:
        scan = _sc(["--scan"]).stdout
    except Exception as e:
        return {"error": str(e)}
    out = {}
    for line in scan.splitlines():
        parts = line.split()
        if not parts:
            continue
        dev = parts[0]
        try:
            r = _sc(["-H", dev])
            m = re.search(r"(?:overall-health self-assessment test result|SMART Health Status):\s*(.+)", r.stdout)
            if m:
                out[dev] = m.group(1).strip()
            elif "permission" in (r.stdout + r.stderr).lower() or r.returncode != 0:
                out[dev] = "sin permiso (sudoers para smartctl)"
            else:
                out[dev] = "desconocido"
        except Exception:
            out[dev] = "error"
    return out or {"info": "sin discos SMART detectados"}

def cmd_update_agent(_args: dict) -> dict:
    """Actualiza el agente/broker vía un helper root acotado (instalado por el instalador)."""
    helper = "/usr/local/sbin/servward-update"
    if not os.path.exists(helper):
        return {"info": "Actualización desde la app no disponible: reinstala el agente (o usa 'ntfyctl update')."}
    chk = subprocess.run(["sudo", "-n", "-l", helper], capture_output=True, text=True, timeout=5)
    if chk.returncode != 0:
        return {"error": "El agente no tiene permiso sudo para actualizar (reinstala el agente para configurarlo)."}
    subprocess.Popen(["bash", "-lc", f"sleep 1; sudo -n {helper}"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return {"status": "Actualizando… el agente se reiniciará en unos segundos", "action": "updating"}

def _check_reboot():
    try:
        boot = int(psutil.boot_time())
        prev = 0
        if os.path.isfile(LASTBOOT_FILE):
            with open(LASTBOOT_FILE) as fh:
                prev = int((fh.read().strip() or "0"))
        with open(LASTBOOT_FILE, "w") as fh:
            fh.write(str(boot))
        if prev and prev != boot:
            up_min = max(0, int((time.time() - boot) / 60))
            send_push("🔄 Servidor reiniciado", f"{platform.node()} se reinició hace {up_min} min")
    except Exception as e:
        log(f"REBOOT_CHECK_ERROR {e}")

def monitoring_thread():
    log(f"Monitor iniciado — intervalo={MONITOR_INTERVAL_S}s CPU>{ALERT_CPU_PCT:.0f}% "
        f"RAM>{ALERT_RAM_PCT:.0f}% disco>{ALERT_DISK_PCT:.0f}% temp>{ALERT_TEMP_C:.0f}°C")
    _check_reboot()
    while True:
        try:
            cpu = psutil.cpu_percent(interval=2)
            if cpu >= ALERT_CPU_PCT and _can_alert("cpu"):
                send_push("⚠️ CPU Alta", f"Uso CPU al {cpu:.0f}% en {platform.node()}")
            mem = psutil.virtual_memory()
            if mem.percent >= ALERT_RAM_PCT and _can_alert("ram"):
                send_push("⚠️ RAM Alta",
                          f"Memoria al {mem.percent:.0f}% ({mem.used/1e9:.1f}/{mem.total/1e9:.1f} GB)")
            disk = psutil.disk_usage("/")
            if disk.percent >= ALERT_DISK_PCT and _can_alert("disk"):
                send_push("⚠️ Disco lleno",
                          f"Disco al {disk.percent:.0f}% ({disk.used/1e9:.1f}/{disk.total/1e9:.1f} GB)")
            _record_metrics(cpu, mem.percent, disk.percent)

            temp = _get_temp()
            if temp and temp >= ALERT_TEMP_C and _can_alert("temp"):
                send_push("🌡️ Temperatura Alta", f"{temp:.1f}°C en {platform.node()}")

            _eval_custom_alerts({"cpu": cpu, "ram": mem.percent,
                                 "disk": disk.percent, "temp": temp})
        except Exception as e:
            log(f"MONITOR_ERROR {e}")
        time.sleep(MONITOR_INTERVAL_S)

# ── Sesiones de Claude Code ─────────────────────────────────────────────────
# Claude Code deja una ficha por sesión viva en ~/.claude/sessions/<pid>.json y una por
# trabajo en segundo plano en ~/.claude/jobs/<id>/state.json. Aquí solo se LEEN: el
# comando no mata, no escribe ni manda nada a las sesiones. Mismo código que agent.py.
CLAUDE_DIR = os.environ.get("CLAUDE_DIR", os.path.expanduser("~/.claude"))
CLAUDE_JOBS_RECENT_S = int(os.environ.get("CLAUDE_JOBS_RECENT_S", str(24 * 3600)))
# Orden de la lista: primero lo que pide atención, luego lo que trabaja, luego el resto.
_CLAUDE_STATE_ORDER = {"blocked": 0, "working": 1, "idle": 2, "unknown": 3, "done": 4, "stopped": 5}

def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True          # existe, pero es de otro usuario
    except (ProcessLookupError, ValueError, TypeError, OverflowError):
        return False

def _read_json_file(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _to_ms(v) -> int:
    """Claude guarda épocas en ms; si alguna llega en segundos, se normaliza."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return n * 1000 if 0 < n < 10_000_000_000 else n

def cmd_claude_sessions(_args: dict) -> dict:
    """Sesiones de Claude Code en esta máquina: vivas (interactivas y en segundo plano)
    y trabajos en segundo plano recientes, con su estado. Devuelve la lista como JSON en
    'sessions' porque el contrato de respuesta es string-only."""
    if not os.path.isdir(CLAUDE_DIR):
        return {"count": "0", "info": "Claude Code no está instalado en esta máquina"}
    now_ms = int(time.time() * 1000)
    out: list = []

    # 1) Sesiones vivas: la ficha existe y el PID sigue ahí.
    for path in glob.glob(os.path.join(CLAUDE_DIR, "sessions", "*.json")):
        d = _read_json_file(path)
        if not isinstance(d, dict) or not _pid_alive(d.get("pid")):
            continue
        status = d.get("status")
        out.append({
            "id":         str(d.get("sessionId") or d.get("pid")),
            "name":       str(d.get("name") or d.get("pid")),
            "kind":       "bg" if d.get("kind") == "bg" else "interactive",
            "state":      {"busy": "working", "idle": "idle"}.get(status, "unknown"),
            "cwd":        str(d.get("cwd") or ""),
            "started_ms": _to_ms(d.get("startedAt")),
            "updated_ms": _to_ms(d.get("updatedAt") or d.get("startedAt")),
            "pid":        int(d.get("pid") or 0),
            "job_id":     str(d.get("jobId") or ""),
            "detail":     "",
        })

    # 2) Trabajos en segundo plano: afinan el estado (bloqueado, terminado) y aportan el
    #    último resumen. Los terminados hace más de CLAUDE_JOBS_RECENT_S no se listan.
    for path in glob.glob(os.path.join(CLAUDE_DIR, "jobs", "*", "state.json")):
        d = _read_json_file(path)
        if not isinstance(d, dict):
            continue
        job_id  = os.path.basename(os.path.dirname(path))
        state   = str(d.get("state") or "unknown")
        updated = _to_ms(d.get("updatedAt"))
        if state in ("done", "stopped") and now_ms - updated > CLAUDE_JOBS_RECENT_S * 1000:
            continue
        detail = str(d.get("detail") or "")[:200]
        live = next((s for s in out if s["job_id"] == job_id), None)
        if live is not None:
            live["detail"] = detail
            if state == "blocked":
                live["state"] = "blocked"
            if d.get("name"):
                live["name"] = str(d["name"])
            continue
        # Sin sesión viva: si el fichero dice "running", el proceso ya no está → unknown.
        mapped = {"running": "unknown", "blocked": "blocked",
                  "done": "done", "stopped": "stopped"}.get(state, "unknown")
        out.append({
            "id":         str(d.get("sessionId") or job_id),
            "name":       str(d.get("name") or job_id),
            "kind":       "bg",
            "state":      mapped,
            "cwd":        str(d.get("cwd") or ""),
            "started_ms": _to_ms(d.get("createdAt")),
            "updated_ms": updated,
            "pid":        0,
            "job_id":     job_id,
            "detail":     detail,
        })

    out.sort(key=lambda s: (_CLAUDE_STATE_ORDER.get(s["state"], 9), -s["updated_ms"]))
    return {
        "count":    str(len(out)),
        "host":     platform.node(),
        "sessions": json.dumps(out, ensure_ascii=False),
    }

# ── Conversación y control de sesiones de Claude Code ────────────────────────
# claude_transcript LEE la conversación de una sesión (~/.claude/projects/*/<id>.jsonl).
# claude_reply / claude_stop / claude_start CONTROLAN sesiones con el CLI `claude`:
# solo funcionan si el nodo arranca con ALLOW_CLAUDE_CONTROL=1 (nunca en producción).
# Mecanismo verificado (3-sep-2026): `claude stop <job>` y después
# `claude --bg --resume <sessionId> "<texto>"` continúa la MISMA sesión; sin el stop
# previo, `--resume` de una sesión viva arranca una copia. `stop` toma el id corto del
# trabajo y `--resume` el sessionId completo (pueden no coincidir).
ALLOW_CLAUDE_CONTROL = os.environ.get("ALLOW_CLAUDE_CONTROL", "0").strip() == "1"
CLAUDE_BIN            = os.environ.get("CLAUDE_BIN", "").strip()
CLAUDE_START_FLAGS    = os.environ.get("CLAUDE_START_FLAGS", "--permission-mode auto").split()
CLAUDE_TAIL_BYTES     = int(os.environ.get("CLAUDE_TAIL_BYTES", str(6 * 1024 * 1024)))
CLAUDE_TEXT_MAX       = 20_000     # caracteres máximos de un mensaje enviado desde la app
_CLAUDE_BG_ID_RE      = re.compile(r"·\s*([0-9a-f]{8})\b")
_CLAUDE_REMINDER_RE   = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)

def _claude_bin() -> str:
    if CLAUDE_BIN and os.access(CLAUDE_BIN, os.X_OK):
        return CLAUDE_BIN
    extra = os.pathsep.join([os.path.expanduser("~/.local/bin"), "/opt/homebrew/bin",
                             "/usr/local/bin", os.environ.get("PATH", "")])
    return shutil.which("claude", path=extra) or ""

def _claude_control_blocked():
    """Motivo por el que no se puede controlar sesiones en este nodo, o None."""
    if not ALLOW_CLAUDE_CONTROL:
        return {"bloqueado": "control de sesiones desactivado en este nodo (ALLOW_CLAUDE_CONTROL=1 para permitirlo)"}
    if not _claude_bin():
        return {"error": "no encuentro el CLI `claude` en esta máquina (CLAUDE_BIN)"}
    return None

def _claude_find(ident: str):
    """Localiza una sesión por sessionId, id corto de trabajo o PID. Devuelve dict con
    session_id, job_id, kind, cwd, pid (0 si no vive) y name; o None si no existe."""
    ident = str(ident or "").strip()
    if not ident:
        return None
    found = None
    for path in glob.glob(os.path.join(CLAUDE_DIR, "sessions", "*.json")):
        d = _read_json_file(path)
        if not isinstance(d, dict):
            continue
        if ident in (str(d.get("sessionId")), str(d.get("jobId")), str(d.get("pid"))):
            alive = _pid_alive(d.get("pid"))
            found = {"session_id": str(d.get("sessionId") or ""), "job_id": str(d.get("jobId") or ""),
                     "kind": "bg" if d.get("kind") == "bg" else "interactive",
                     "cwd": str(d.get("cwd") or ""), "pid": int(d.get("pid") or 0) if alive else 0,
                     "name": str(d.get("name") or "")}
            if alive:
                return found
    for path in glob.glob(os.path.join(CLAUDE_DIR, "jobs", "*", "state.json")):
        d = _read_json_file(path)
        if not isinstance(d, dict):
            continue
        job_id = os.path.basename(os.path.dirname(path))
        sid = str(d.get("resumeSessionId") or d.get("sessionId") or "")
        if ident in (job_id, sid):
            return {"session_id": sid, "job_id": job_id, "kind": "bg",
                    "cwd": str(d.get("cwd") or ""), "pid": found["pid"] if found else 0,
                    "name": str(d.get("name") or job_id)}
    if found is None:
        # Sin ficha viva ni trabajo: puede ser un sessionId cuyo transcript aún existe.
        if _claude_transcript_path(ident):
            found = {"session_id": ident, "job_id": "", "kind": "bg", "cwd": "", "pid": 0, "name": ident}
    return found

def _claude_transcript_path(session_id: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", session_id or ""):
        return ""
    hits = glob.glob(os.path.join(CLAUDE_DIR, "projects", "*", f"{session_id}.jsonl"))
    if not hits:
        return ""
    return max(hits, key=lambda p: os.path.getmtime(p))

def _tail_lines(path: str, max_bytes: int):
    """Últimas líneas completas de un fichero grande sin leerlo entero.
    Devuelve (líneas, truncado)."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
            data = f.read()
            data = data[data.find(b"\n") + 1:]        # descarta la línea partida
            truncated = True
        else:
            data = f.read()
            truncated = False
    return data.decode("utf-8", "replace").splitlines(), truncated

def _iso_to_ms(s) -> int:
    """Los timestamps del transcript son UTC ('…Z'); se devuelven en ms de época."""
    try:
        dt = datetime.strptime(str(s)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (TypeError, ValueError):
        return 0

def _claude_tool_summary(block: dict) -> str:
    name = str(block.get("name") or "herramienta")
    inp = block.get("input") or {}
    if not isinstance(inp, dict):
        return name
    for key in ("description", "command", "file_path", "pattern", "prompt", "query", "skill"):
        v = inp.get(key)
        if isinstance(v, str) and v.strip():
            return f"{name}: {v.strip().splitlines()[0][:160]}"
    return name

def _claude_messages(lines, max_chars: int) -> list:
    """Convierte líneas del jsonl en mensajes legibles: lo que dijo la persona, lo que
    contestó Claude y qué herramientas usó. Fuera: pensamiento, resultados de
    herramientas, mensajes internos (skills, recordatorios) y subagentes."""
    out = []
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        typ = d.get("type")
        if typ not in ("user", "assistant") or d.get("isSidechain"):
            continue
        msg = d.get("message") or {}
        content = msg.get("content")
        ts = _iso_to_ms(d.get("timestamp"))
        uid = str(d.get("uuid") or "")
        if typ == "user":
            if d.get("isMeta"):
                continue
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
                    continue
                text = "\n".join(str(b.get("text") or "") for b in content
                                 if isinstance(b, dict) and b.get("type") == "text")
            else:
                continue
            text = _CLAUDE_REMINDER_RE.sub("", text).strip()
            if not text or text.startswith("<"):
                continue
            out.append({"id": uid, "role": "user", "kind": "text", "text": text[:max_chars], "ts_ms": ts})
            continue
        if not isinstance(content, list):
            continue
        texts = []
        for b in content:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text" and str(b.get("text") or "").strip():
                texts.append(str(b["text"]).strip())
            elif b.get("type") == "tool_use":
                out.append({"id": uid + ":" + str(b.get("id") or ""), "role": "assistant", "kind": "tool",
                            "text": _claude_tool_summary(b), "ts_ms": ts})
        if texts:
            out.append({"id": uid, "role": "assistant", "kind": "text",
                        "text": "\n\n".join(texts)[:max_chars], "ts_ms": ts})
    return out

def cmd_claude_transcript(args: dict) -> dict:
    """Conversación de una sesión (las últimas `limit` entradas), como JSON en 'messages'."""
    ident = str(args.get("id") or "").strip()
    if not ident:
        return {"error": "falta 'id' (sessionId o id del trabajo)"}
    try:
        limit = max(1, min(int(args.get("limit") or 40), 200))
        max_chars = max(200, min(int(args.get("max_chars") or 2500), 20_000))
    except (TypeError, ValueError):
        return {"error": "'limit' y 'max_chars' deben ser números"}
    info = _claude_find(ident)
    if info is None:
        return {"error": f"no hay ninguna sesión '{ident[:24]}' en esta máquina"}
    path = _claude_transcript_path(info["session_id"])
    if not path:
        return {"error": "esta sesión no tiene transcript en disco todavía"}
    lines, truncated = _tail_lines(path, CLAUDE_TAIL_BYTES)
    msgs = _claude_messages(lines, max_chars)
    total = len(msgs)
    msgs = msgs[-limit:]
    state = "unknown"
    for s in json.loads(cmd_claude_sessions({}).get("sessions") or "[]"):
        if s["id"] == info["session_id"] or (info["job_id"] and s["job_id"] == info["job_id"]):
            state = s["state"]
            break
    return {
        "id":        info["session_id"],
        "job_id":    info["job_id"],
        "name":      info["name"],
        "kind":      info["kind"],
        "cwd":       info["cwd"],
        "state":     state,
        "alive":     "1" if info["pid"] else "0",
        "control":   "1" if ALLOW_CLAUDE_CONTROL else "0",
        "count":     str(len(msgs)),
        "total":     str(total),
        "truncated": "1" if (truncated or total > limit) else "0",
        "messages":  json.dumps(msgs, ensure_ascii=False),
    }

def _claude_run(argv: list, cwd: str, timeout: int = 90) -> tuple:
    """Ejecuta el CLI `claude` sin shell (los textos van como argumentos, nunca se
    interpolan). stdout/stderr van a fichero para que el demonio que deja detrás
    `--bg` no mantenga una tubería abierta y bloquee la espera."""
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([os.path.dirname(_claude_bin()), env.get("PATH", "")])
    env.setdefault("HOME", os.path.expanduser("~"))
    if not (cwd and os.path.isdir(cwd)):
        cwd = os.path.expanduser("~")
    with tempfile.TemporaryFile() as out:
        try:
            rc = subprocess.run([_claude_bin()] + argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=out, stderr=subprocess.STDOUT, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = -1
        out.seek(0)
        text = out.read().decode("utf-8", "replace").strip()
    return rc, text

def _claude_wait_gone(pid: int, seconds: float) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if not pid or not _pid_alive(pid):
            return True
        time.sleep(0.3)
    return not _pid_alive(pid)

def _claude_stop_job(info: dict) -> dict:
    """`claude stop <job>` y espera a que el proceso muera. Devuelve {'ok':...} o {'error':...}."""
    if not info["job_id"]:
        return {"error": "solo se pueden parar sesiones en segundo plano (esta no tiene id de trabajo)"}
    rc, text = _claude_run(["stop", info["job_id"]], info["cwd"], timeout=60)
    if rc != 0:
        return {"error": f"claude stop devolvió {rc}: {text[:300]}"}
    if not _claude_wait_gone(info["pid"], 20):
        return {"error": f"claude stop no ha terminado el proceso {info['pid']} en 20 s"}
    return {"ok": "1", "output": text[:300]}

def cmd_claude_stop(args: dict) -> dict:
    """Para una sesión en segundo plano (la conversación se conserva)."""
    blocked = _claude_control_blocked()
    if blocked:
        return blocked
    info = _claude_find(str(args.get("id") or ""))
    if info is None:
        return {"error": "sesión no encontrada"}
    if info["kind"] == "interactive" and info["pid"]:
        return {"error": "es una sesión interactiva en un terminal: se cierra desde allí"}
    if not info["pid"]:
        return {"ok": "1", "info": "la sesión ya no estaba en marcha", "job_id": info["job_id"]}
    log(f"CLAUDE_STOP job={info['job_id']} session={info['session_id'][:8]}")
    res = _claude_stop_job(info)
    res.setdefault("job_id", info["job_id"])
    return res

def cmd_claude_reply(args: dict) -> dict:
    """Manda un mensaje a una sesión existente: la para si sigue viva y la continúa en
    segundo plano con `--resume` (misma conversación, mismo id)."""
    blocked = _claude_control_blocked()
    if blocked:
        return blocked
    text = str(args.get("text") or "").strip()
    if not text:
        return {"error": "falta 'text'"}
    if len(text) > CLAUDE_TEXT_MAX:
        return {"error": f"mensaje demasiado largo (máximo {CLAUDE_TEXT_MAX} caracteres)"}
    info = _claude_find(str(args.get("id") or ""))
    if info is None or not info["session_id"]:
        return {"error": "sesión no encontrada"}
    if info["kind"] == "interactive" and info["pid"]:
        return {"error": "es una sesión interactiva en un terminal: `--resume` abriría una copia. Respóndele allí"}
    if info["pid"]:
        stopped = _claude_stop_job(info)
        if "error" in stopped:
            return stopped
    log(f"CLAUDE_REPLY session={info['session_id'][:8]} chars={len(text)}")
    rc, out = _claude_run(["--bg", "--resume", info["session_id"], text], info["cwd"], timeout=120)
    m = _CLAUDE_BG_ID_RE.search(out)
    if rc != 0 or not m:
        return {"error": f"claude --resume devolvió {rc}: {out[:300] or 'sin salida'}"}
    return {"ok": "1", "id": info["session_id"], "job_id": m.group(1), "output": out.splitlines()[0][:200]}

def cmd_claude_start(args: dict) -> dict:
    """Arranca una sesión nueva en segundo plano con una tarea (`claude --bg "<texto>"`)."""
    blocked = _claude_control_blocked()
    if blocked:
        return blocked
    text = str(args.get("text") or "").strip()
    if not text:
        return {"error": "falta 'text' (la tarea)"}
    if len(text) > CLAUDE_TEXT_MAX:
        return {"error": f"tarea demasiado larga (máximo {CLAUDE_TEXT_MAX} caracteres)"}
    cwd = os.path.expanduser(str(args.get("cwd") or "").strip()) or os.path.expanduser("~")
    if not os.path.isdir(cwd):
        return {"error": f"la carpeta no existe: {cwd[:120]}"}
    name = str(args.get("name") or "").strip()[:80]
    argv = ["--bg"] + CLAUDE_START_FLAGS + (["-n", name] if name else []) + [text]
    log(f"CLAUDE_START cwd={cwd} name={name!r} chars={len(text)}")
    rc, out = _claude_run(argv, cwd, timeout=120)
    m = _CLAUDE_BG_ID_RE.search(out)
    if rc != 0 or not m:
        return {"error": f"claude --bg devolvió {rc}: {out[:300] or 'sin salida'}"}
    job_id = m.group(1)
    # El sessionId de la sesión nueva sale en su ficha en cuanto arranca.
    session_id = ""
    for _ in range(20):
        found = _claude_find(job_id)
        if found and found["session_id"]:
            session_id = found["session_id"]
            break
        time.sleep(0.25)
    return {"ok": "1", "id": session_id or job_id, "job_id": job_id, "cwd": cwd,
            "output": out.splitlines()[0][:200]}

# ── Terminales tmux (el terminal del móvil) ───────────────────────────────────
# Mismo bloque que agent.py salvo dos diferencias de este fichero: aquí `log()` es una
# función (no un logger) y `send_push(title, body)` no lleva datos extra.
# El móvil ve la MISMA sesión tmux que hay en el escritorio: tmux_screen devuelve la
# pantalla (con colores) y tmux_keys teclea en ella. Escribir en un terminal es control
# total de la máquina, así que tmux_keys / tmux_new / tmux_kill exigen
# ALLOW_CLAUDE_CONTROL=1 igual que el control de sesiones. Leer la pantalla es solo con
# token de control (no está en ALLOWED_RO).
TMUX_BIN    = os.environ.get("TMUX_BIN", "").strip()
TMUX_SOCKET = os.environ.get("TMUX_SOCKET", "").strip()      # -L <nombre>, opcional
TMUX_SCROLLBACK_MAX = 2000
_TMUX_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:%@$\-]{1,120}$")
_TMUX_KEY_RE    = re.compile(r"^[A-Za-z0-9\-]{1,12}$")
_TMUX_SESSION_RE = re.compile(r"^[A-Za-z0-9_\-]{1,60}$")

def _tmux_bin() -> str:
    if TMUX_BIN and os.access(TMUX_BIN, os.X_OK):
        return TMUX_BIN
    extra = os.pathsep.join(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", os.environ.get("PATH", "")])
    return shutil.which("tmux", path=extra) or ""

_TMUX_SOCKET_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,60}$")

def _tmux(*args, socket: str = "", timeout: int = 10) -> str:
    """Ejecuta tmux contra un socket concreto (-L nombre). Sin socket: el por defecto."""
    sock = socket or TMUX_SOCKET
    argv = [_tmux_bin()] + (["-L", sock] if sock else []) + list(args)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          check=True).stdout

def _tmux_sockets() -> list:
    """Nombres de los sockets tmux del usuario: cada programa que lanza su propio
    servidor tmux (nodeterm, por ejemplo) usa uno distinto y sus sesiones no se ven
    desde el socket por defecto. Carpeta: $TMUX_TMPDIR/tmux-<uid> o /tmp/tmux-<uid>."""
    base = os.environ.get("TMUX_TMPDIR") or "/tmp"
    d = os.path.join(base, f"tmux-{os.getuid()}")
    names = []
    try:
        for n in sorted(os.listdir(d)):
            p = os.path.join(d, n)
            try:
                import stat as _stat
                if _stat.S_ISSOCK(os.stat(p).st_mode) and _TMUX_SOCKET_RE.match(n):
                    names.append(n)
            except OSError:
                continue
    except OSError:
        pass
    if "default" in names:
        names.remove("default"); names.insert(0, "default")
    return names or ["default"]

def _tmux_missing():
    if not _tmux_bin():
        return {"error": "tmux no está instalado en esta máquina"}
    return None

def _tmux_target_ok(t: str) -> bool:
    return bool(t) and bool(_TMUX_TARGET_RE.match(t))

def _tmux_socket_arg(args: dict):
    """Socket pedido por la app ('' = por defecto) o None si el nombre no vale."""
    s = str(args.get("socket") or "").strip()
    if s and not _TMUX_SOCKET_RE.match(s):
        return None
    return s

def _claude_by_tmux_pane() -> dict:
    """pane_id (%N) → sesión de Claude viva que corre dentro de ese pane."""
    out = {}
    for path in glob.glob(os.path.join(CLAUDE_DIR, "sessions", "*.json")):
        d = _read_json_file(path)
        if not isinstance(d, dict) or not d.get("tmux") or not _pid_alive(d.get("pid")):
            continue
        pane = str(d["tmux"]).rsplit(".", 1)[-1]          # "sess:@1.%1" → "%1"
        out[pane] = {"id": str(d.get("sessionId") or ""), "name": str(d.get("name") or ""),
                     "state": {"busy": "working", "idle": "idle"}.get(d.get("status"), "unknown"),
                     "job_id": str(d.get("jobId") or "")}
    return out

def cmd_tmux_sessions(_args: dict) -> dict:
    """Panes de tmux de esta máquina (uno por terminal) con el programa que corre,
    la carpeta, el tamaño y, si dentro va Claude Code, su sesión. JSON en 'panes'."""
    missing = _tmux_missing()
    if missing:
        return missing
    fmt = "\x1f".join(["#{session_name}", "#{window_index}", "#{pane_index}", "#{pane_id}",
                       "#{pane_pid}", "#{pane_current_command}", "#{pane_current_path}",
                       "#{pane_width}", "#{pane_height}", "#{session_attached}",
                       "#{session_activity}", "#{pane_title}", "#{history_size}",
                       "#{session_created}"])
    claude = _claude_by_tmux_pane()
    panes = []
    errors = []
    for sock in _tmux_sockets():
        try:
            raw = _tmux("list-panes", "-a", "-F", fmt, socket=sock)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or "").strip()
            if "no server running" in err or "error connecting" in err:
                continue                              # socket huérfano o sin servidor
            errors.append(f"{sock}: {err[:120]}")
            continue
        except (OSError, subprocess.TimeoutExpired) as e:
            errors.append(f"{sock}: {e}"[:120])
            continue
        for line in raw.splitlines():
            f = line.split("\x1f")
            if len(f) < 14:
                continue
            cl = claude.get(f[3], {})
            panes.append({
                "socket":      "" if sock == "default" else sock,
                "target":      f"{f[0]}:{f[1]}.{f[2]}",
                "session":     f[0],
                "pane_id":     f[3],
                "pid":         int(f[4] or 0),
                "command":     f[5],
                "cwd":         f[6],
                "cols":        int(f[7] or 0),
                "rows":        int(f[8] or 0),
                "attached":    f[9] not in ("", "0"),
                "activity_ms": _to_ms(f[10]),
                "created_ms":  _to_ms(f[13]),
                "title":       f[11].strip(),
                "history":     int(f[12] or 0),
                "claude_id":   cl.get("id", ""),
                "claude_name": cl.get("name", ""),
                "claude_state": cl.get("state", ""),
                "claude_job":  cl.get("job_id", ""),
            })
    panes.sort(key=lambda p: -p["activity_ms"])
    out = {"count": str(len(panes)), "host": platform.node(),
           "control": "1" if ALLOW_CLAUDE_CONTROL else "0",
           "panes": json.dumps(panes, ensure_ascii=False)}
    if errors:
        out["warning"] = "; ".join(errors)[:300]
    return out

def cmd_tmux_screen(args: dict) -> dict:
    """Pantalla actual de un pane, con colores ANSI (SGR) salvo plain=1. `back` = líneas
    de scrollback por encima de la pantalla (0-2000)."""
    missing = _tmux_missing()
    if missing:
        return missing
    target = str(args.get("target") or "").strip()
    if not _tmux_target_ok(target):
        return {"error": "falta 'target' (sesión:ventana.pane)"}
    sock = _tmux_socket_arg(args)
    if sock is None:
        return {"error": "socket no válido"}
    try:
        back = max(0, min(int(args.get("back") or 0), TMUX_SCROLLBACK_MAX))
    except (TypeError, ValueError):
        back = 0
    cap = ["capture-pane", "-p", "-J", "-t", target]
    if str(args.get("plain") or "") != "1":
        cap.append("-e")
    if back:
        cap += ["-S", f"-{back}"]
    try:
        screen = _tmux(*cap, socket=sock)
        info = _tmux("display-message", "-p", "-t", target,
                     "#{pane_width}\x1f#{pane_height}\x1f#{cursor_x}\x1f#{cursor_y}\x1f"
                     "#{pane_in_mode}\x1f#{alternate_on}\x1f#{history_size}\x1f#{pane_title}\x1f"
                     "#{pane_current_command}\x1f#{pane_dead}", socket=sock).strip().split("\x1f")
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "pane no encontrado").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    info += [""] * (10 - len(info))
    return {
        "target":   target,
        "screen":   screen.rstrip("\n"),
        "cols":     info[0], "rows": info[1],
        "cursor_x": info[2], "cursor_y": info[3],
        "in_mode":  info[4], "alternate": info[5],
        "history":  info[6], "title": info[7], "command": info[8],
        "dead":     info[9] or "0",
        "back":     str(back),
    }

def cmd_tmux_keys(args: dict) -> dict:
    """Teclea en un pane: `text` se envía literal; `keys` son nombres de tecla de tmux
    separados por espacio (Enter, Escape, Tab, BSpace, Up, Down, Left, Right, C-c, C-d,
    C-l, Home, End, PPage, NPage, F1…). Primero el texto, luego las teclas."""
    blocked = _claude_control_blocked() if ALLOW_CLAUDE_CONTROL else \
        {"bloqueado": "teclear en terminales está desactivado en este nodo (ALLOW_CLAUDE_CONTROL=1 para permitirlo)"}
    if blocked:
        return blocked
    missing = _tmux_missing()
    if missing:
        return missing
    target = str(args.get("target") or "").strip()
    if not _tmux_target_ok(target):
        return {"error": "falta 'target'"}
    text = str(args.get("text") or "")
    keys = [k for k in str(args.get("keys") or "").split() if k]
    if len(text) > CLAUDE_TEXT_MAX:
        return {"error": "texto demasiado largo"}
    bad = [k for k in keys if not _TMUX_KEY_RE.match(k)]
    if bad:
        return {"error": f"tecla no válida: {bad[0][:20]}"}
    if not text and not keys:
        return {"error": "nada que enviar"}
    sock = _tmux_socket_arg(args)
    if sock is None:
        return {"error": "socket no válido"}
    try:
        if text:
            _tmux("send-keys", "-t", target, "-l", "--", text, socket=sock)
        if keys:
            _tmux("send-keys", "-t", target, *keys, socket=sock)
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo enviar").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log(f"TMUX_KEYS target={target} chars={len(text)} keys={' '.join(keys)[:60]}")
    return {"ok": "1", "target": target}

def cmd_tmux_new(args: dict) -> dict:
    """Crea una sesión tmux nueva (desacoplada) y opcionalmente arranca en ella un programa:
    `claude_attach`=<job> abre una sesión en segundo plano de Claude en un terminal,
    `claude_resume`=<sessionId> reanuda una conversación de forma interactiva,
    `claude`=1 arranca Claude Code sin más. Sin nada de eso: un shell."""
    blocked = _claude_control_blocked() if ALLOW_CLAUDE_CONTROL else \
        {"bloqueado": "crear terminales está desactivado en este nodo (ALLOW_CLAUDE_CONTROL=1 para permitirlo)"}
    if blocked:
        return blocked
    missing = _tmux_missing()
    if missing:
        return missing
    name = str(args.get("name") or "").strip() or f"sw-{int(time.time()) % 100000}"
    if not _TMUX_SESSION_RE.match(name):
        return {"error": "nombre de sesión no válido (letras, números, - y _)"}
    cwd = os.path.expanduser(str(args.get("cwd") or "").strip()) or os.path.expanduser("~")
    if not os.path.isdir(cwd):
        return {"error": f"la carpeta no existe: {cwd[:120]}"}
    try:
        cols = max(20, min(int(args.get("cols") or 80), 300))
        rows = max(5, min(int(args.get("rows") or 24), 100))
    except (TypeError, ValueError):
        cols, rows = 80, 24
    program = []
    if args.get("claude_attach"):
        job = str(args["claude_attach"]).strip()
        if not re.fullmatch(r"[0-9a-f]{8}", job):
            return {"error": "claude_attach debe ser el id corto del trabajo"}
        program = [_claude_bin(), "attach", job]
    elif args.get("claude_resume"):
        sid = str(args["claude_resume"]).strip()
        if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", sid):
            return {"error": "claude_resume debe ser un sessionId"}
        program = [_claude_bin(), "--resume", sid]
    elif str(args.get("claude") or "") == "1":
        program = [_claude_bin()]
    if program and not program[0]:
        return {"error": "no encuentro el CLI `claude` en esta máquina"}
    sock = _tmux_socket_arg(args)
    if sock is None:
        return {"error": "socket no válido"}
    try:
        _tmux("new-session", "-d", "-s", name, "-c", cwd, "-x", str(cols), "-y", str(rows), *program, socket=sock)
        target = _tmux("display-message", "-p", "-t", name,
                       "#{session_name}:#{window_index}.#{pane_index}", socket=sock).strip()
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo crear").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log(f"TMUX_NEW session={name} cwd={cwd} program={' '.join(program)[:80]}")
    return {"ok": "1", "target": target, "session": name, "cwd": cwd, "socket": sock}

def cmd_tmux_kill(args: dict) -> dict:
    """Cierra una sesión tmux entera (lo que corría dentro muere)."""
    blocked = _claude_control_blocked() if ALLOW_CLAUDE_CONTROL else \
        {"bloqueado": "cerrar terminales está desactivado en este nodo (ALLOW_CLAUDE_CONTROL=1 para permitirlo)"}
    if blocked:
        return blocked
    missing = _tmux_missing()
    if missing:
        return missing
    session = str(args.get("session") or "").strip()
    if not _TMUX_SESSION_RE.match(session):
        return {"error": "falta 'session'"}
    sock = _tmux_socket_arg(args)
    if sock is None:
        return {"error": "socket no válido"}
    try:
        _tmux("kill-session", "-t", f"={session}", socket=sock)
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo cerrar").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log(f"TMUX_KILL session={session}")
    return {"ok": "1", "session": session}

# ── Eventos de Claude Code → push «te necesita» / «terminó» ───────────────────
# Un hook de Claude Code (~/.servward/claude-hook.sh, instalado por
# claude_hooks_install) añade cada evento como una línea JSON a
# ~/.servward/claude-events.jsonl. Este hilo lee las líneas nuevas y avisa al móvil:
#   Notification permission_prompt / idle_prompt / agent_needs_input → «Te necesita»
#   Stop en una sesión en segundo plano                               → «Terminó»
# El interruptor ~/.servward/push-off (claude_push enabled=0) silencia este nodo.
SERVWARD_DIR       = os.environ.get("SERVWARD_DIR", os.path.expanduser("~/.servward"))
CLAUDE_EVENTS_FILE = os.path.join(SERVWARD_DIR, "claude-events.jsonl")
CLAUDE_HOOK_SCRIPT = os.path.join(SERVWARD_DIR, "claude-hook.sh")
CLAUDE_PUSH_OFF    = os.path.join(SERVWARD_DIR, "push-off")
CLAUDE_EVENTS_MAX_BYTES = 2 * 1024 * 1024
CLAUDE_PUSH_STOP_ALL = os.environ.get("CLAUDE_PUSH_STOP_ALL", "0").strip() == "1"
_NEEDS_YOU_TYPES = {"permission_prompt", "idle_prompt", "agent_needs_input",
                    "elicitation_dialog", "elicitation_url_dialog"}
_CLAUDE_HOOK_SH = """#!/bin/bash
# Servward: guarda el evento de Claude Code (JSON por stdin) para que el agente avise al móvil.
# No decide nada: siempre sale 0 y nunca escribe en stdout.
f="$HOME/.servward/claude-events.jsonl"
mkdir -p "$HOME/.servward" 2>/dev/null
ev=$(cat | tr -d '\\n\\r')
[ -n "$ev" ] && printf '{"ts":%s,"ev":%s}\\n' "$(date +%s)" "$ev" >> "$f" 2>/dev/null
exit 0
"""

def _claude_push_enabled() -> bool:
    return not os.path.exists(CLAUDE_PUSH_OFF)

def cmd_claude_push(args: dict) -> dict:
    """Enciende o apaga los avisos de agentes de ESTE nodo (enabled=1/0). Sin args: estado."""
    if "enabled" in args:
        os.makedirs(SERVWARD_DIR, exist_ok=True)
        if str(args["enabled"]) == "1":
            try:
                os.remove(CLAUDE_PUSH_OFF)
            except FileNotFoundError:
                pass
        else:
            open(CLAUDE_PUSH_OFF, "w").close()
    return {"enabled": "1" if _claude_push_enabled() else "0",
            "hooks": "1" if _claude_hooks_installed() else "0"}

def _claude_settings_path() -> str:
    return os.path.join(CLAUDE_DIR, "settings.json")

def _claude_hooks_installed() -> bool:
    d = _read_json_file(_claude_settings_path()) or {}
    hooks = d.get("hooks") if isinstance(d, dict) else None
    if not isinstance(hooks, dict):
        return False
    return any(CLAUDE_HOOK_SCRIPT in json.dumps(v) for v in hooks.values()) and os.access(CLAUDE_HOOK_SCRIPT, os.X_OK)

def cmd_claude_hooks_install(args: dict) -> dict:
    """Instala el hook en ~/.claude/settings.json (fusiona: no toca los hooks que ya haya)
    y escribe ~/.servward/claude-hook.sh. remove=1 lo desinstala."""
    blocked = _claude_control_blocked()
    if blocked:
        return blocked
    path = _claude_settings_path()
    settings = _read_json_file(path)
    if settings is None and os.path.exists(path):
        return {"error": "settings.json no es JSON válido; no lo toco"}
    settings = settings if isinstance(settings, dict) else {}
    hooks = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else {}
    ours = {"type": "command", "command": CLAUDE_HOOK_SCRIPT, "async": True, "timeout": 10}
    events = ["Notification", "Stop", "UserPromptSubmit", "SessionEnd"]
    if str(args.get("remove") or "") == "1":
        for ev in events:
            groups = [g for g in hooks.get(ev, [])
                      if not any(h.get("command") == CLAUDE_HOOK_SCRIPT for h in g.get("hooks", []))]
            if groups:
                hooks[ev] = groups
            else:
                hooks.pop(ev, None)
    else:
        os.makedirs(SERVWARD_DIR, exist_ok=True)
        with open(CLAUDE_HOOK_SCRIPT, "w", encoding="utf-8") as f:
            f.write(_CLAUDE_HOOK_SH)
        os.chmod(CLAUDE_HOOK_SCRIPT, 0o755)
        for ev in events:
            groups = hooks.get(ev) if isinstance(hooks.get(ev), list) else []
            if not any(h.get("command") == CLAUDE_HOOK_SCRIPT for g in groups for h in g.get("hooks", [])):
                groups.append({"hooks": [dict(ours)]})
            hooks[ev] = groups
    if hooks:
        settings["hooks"] = hooks
    else:
        settings.pop("hooks", None)
    tmp = path + ".servward.tmp"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o600
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    log(f"CLAUDE_HOOKS {'removed' if args.get('remove') else 'installed'}")
    return {"ok": "1", "hooks": "1" if _claude_hooks_installed() else "0", "settings": path}

# ── Live Activity (Dynamic Island) de la sesión que el móvil estaba usando ──────
# La app registra aquí el token de la Live Activity (claude_live_register); cada evento
# del hook la actualiza por APNs (push-type liveactivity): working / needs_you / done.
CLAUDE_LIVE_FILE = os.path.join(SERVWARD_DIR, "live-activities.json")
_CLAUDE_LIVE_LOCK = threading.Lock()
_LIVE_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{32,200}$")

def _live_load() -> dict:
    d = _read_json_file(CLAUDE_LIVE_FILE)
    return d if isinstance(d, dict) else {}

def _live_save(d: dict):
    os.makedirs(SERVWARD_DIR, exist_ok=True)
    tmp = CLAUDE_LIVE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(tmp, CLAUDE_LIVE_FILE)

def cmd_claude_live_register(args: dict) -> dict:
    """Registra el token de la Live Activity de una sesión (session_id, token, name)."""
    sid = str(args.get("session_id") or "").strip()
    token = str(args.get("token") or "").strip()
    if not sid or not _LIVE_TOKEN_RE.match(token):
        return {"error": "faltan session_id o token"}
    with _CLAUDE_LIVE_LOCK:
        d = _live_load()
        d[sid] = {"token": token, "name": str(args.get("name") or "")[:80], "ts": int(time.time())}
        for old in sorted(d, key=lambda k: d[k].get("ts", 0))[:-20]:
            d.pop(old, None)
        _live_save(d)
    log(f"LIVE_REGISTER session={sid[:8]}")
    return {"ok": "1", "count": str(len(d))}

def cmd_claude_live_unregister(args: dict) -> dict:
    sid = str(args.get("session_id") or "").strip()
    with _CLAUDE_LIVE_LOCK:
        d = _live_load()
        removed = d.pop(sid, None) is not None
        _live_save(d)
    return {"ok": "1", "removed": "1" if removed else "0"}

def send_live_activity(token, state, detail, name, end=False, alert=None) -> bool:
    """Actualiza (o cierra) una Live Activity por APNs. Devuelve True si APNs aceptó."""
    if not (os.path.isfile(APNS_CERT) and os.path.isfile(APNS_KEY)):
        return False
    aps = {"timestamp": int(time.time()), "event": "end" if end else "update",
           "content-state": {"state": state, "detail": detail[:160], "updatedAt": time.time()}}
    if end:
        aps["dismissal-date"] = int(time.time()) + 600
    if alert:
        aps["alert"] = {"title": alert[0], "body": alert[1]}
    cmd = ["curl", "--http2", "-s", "-o", "/dev/null", "-w", "%{http_code}",
           "--cert", APNS_CERT, "--key", APNS_KEY,
           "-H", f"apns-topic: {APNS_BUNDLE}.push-type.liveactivity",
           "-H", "apns-push-type: liveactivity", "-H", "apns-priority: 10",
           "-d", json.dumps({"aps": aps}), f"https://{APNS_HOST}/3/device/{token}"]
    try:
        code = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception as e:
        log(f"LIVE_ERROR {e}")
        return False
    if code == "200":
        log(f"LIVE_SENT state={state} name={name!r}{' (end)' if end else ''}")
        return True
    log(f"LIVE_FAIL http={code} state={state}")
    return code not in ("400", "410")

def _live_update(sid: str, state: str, detail: str, end: bool = False, alert=None):
    with _CLAUDE_LIVE_LOCK:
        d = _live_load()
        entry = d.get(sid)
    if not entry:
        return
    ok = send_live_activity(entry["token"], state, detail, entry.get("name", ""), end=end, alert=alert)
    if end or not ok:
        with _CLAUDE_LIVE_LOCK:
            d = _live_load()
            d.pop(sid, None)
            _live_save(d)

def _claude_session_label(session_id: str, cwd: str) -> str:
    info = _claude_find(session_id) if session_id else None
    if info and info.get("name"):
        return info["name"]
    return os.path.basename(cwd.rstrip("/")) or session_id[:8]

def _claude_last_answer(transcript_path: str) -> str:
    try:
        lines, _ = _tail_lines(transcript_path, 256 * 1024)
    except OSError:
        return ""
    for m in reversed(_claude_messages(lines, 300)):
        if m["role"] == "assistant" and m["kind"] == "text":
            return m["text"].replace("\n", " ")[:160]
    return ""

def _claude_handle_event(rec: dict):
    ev = rec.get("ev") if isinstance(rec.get("ev"), dict) else {}
    name = str(ev.get("hook_event_name") or "")
    sid  = str(ev.get("session_id") or "")
    cwd  = str(ev.get("cwd") or "")
    # 1) Live Activity de la sesión que el móvil está siguiendo (aunque el push esté silenciado).
    if name == "UserPromptSubmit":
        _live_update(sid, "working", str(ev.get("prompt") or "")[:160])
    elif name == "Notification" and str(ev.get("notification_type") or "") in _NEEDS_YOU_TYPES:
        _live_update(sid, "needs_you", str(ev.get("message") or "Espera tu respuesta"))
    elif name == "Stop":
        _live_update(sid, "done", _claude_last_answer(str(ev.get("transcript_path") or "")) or "Ha acabado")
    elif name == "SessionEnd":
        _live_update(sid, "done", "Sesión cerrada", end=True)
    # 2) Avisos push
    if not _claude_push_enabled():
        return
    if name == "Notification":
        ntype = str(ev.get("notification_type") or "")
        if ntype not in _NEEDS_YOU_TYPES:
            return
        if not _can_alert(f"claude-needs-{sid}", 60):
            return
        label = _claude_session_label(sid, cwd)
        body = str(ev.get("message") or "Claude está esperando tu respuesta")[:180]
        send_push(f"🖐 Te necesita · {label}", body)
    elif name == "Stop":
        info = _claude_find(sid)
        is_bg = bool(info and info.get("kind") == "bg")
        if not (is_bg or CLAUDE_PUSH_STOP_ALL):
            return
        if not _can_alert(f"claude-stop-{sid}", 30):
            return
        label = _claude_session_label(sid, cwd)
        body = _claude_last_answer(str(ev.get("transcript_path") or "")) or "Ha terminado la tarea"
        send_push(f"✅ Terminó · {label}", body)

def claude_events_thread():
    """Lee las líneas nuevas de claude-events.jsonl y las convierte en avisos."""
    offset = os.path.getsize(CLAUDE_EVENTS_FILE) if os.path.exists(CLAUDE_EVENTS_FILE) else 0
    log(f"Eventos de Claude: vigilando {CLAUDE_EVENTS_FILE} (push {'activo' if _claude_push_enabled() else 'APAGADO'})")
    while True:
        try:
            if os.path.exists(CLAUDE_EVENTS_FILE):
                size = os.path.getsize(CLAUDE_EVENTS_FILE)
                if size < offset:
                    offset = 0                      # fichero truncado o rotado
                if size > offset:
                    with open(CLAUDE_EVENTS_FILE, "rb") as f:
                        f.seek(offset)
                        chunk = f.read()
                    nl = chunk.rfind(b"\n")
                    if nl >= 0:
                        offset += nl + 1
                        for line in chunk[:nl].decode("utf-8", "replace").splitlines():
                            try:
                                rec = json.loads(line)
                            except ValueError:
                                continue
                            try:
                                _claude_handle_event(rec)
                            except Exception as e:
                                log(f"CLAUDE_EVENT_ERROR {e}")
                if size > CLAUDE_EVENTS_MAX_BYTES and offset >= size:
                    open(CLAUDE_EVENTS_FILE, "w").close()
                    offset = 0
        except Exception as e:
            log(f"CLAUDE_EVENTS_LOOP {e}")
        time.sleep(2)

# Comandos permitidos con un token de SOLO LECTURA (monitorización).
# Default-deny: cualquier cmd fuera de este set se rechaza si scope == "ro".
ALLOWED_RO = {
    "check_status", "uptime", "disks", "temperatures", "ping_service",
    "metrics_history", "network_speed", "list_scripts", "updates",
    "services", "docker", "last_jobs", "processes",
    "cert_expiry", "check_endpoints", "smart",
    "get_thresholds", "get_custom_alerts",
    "get_volume", "tailscale_status", "list_apps",
    "claude_sessions",
}

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
    "list_scripts":  cmd_list_scripts,
    # extra Linux
    "services":       cmd_services,
    "docker":         cmd_docker,
    "processes":      cmd_processes,
    "service_action": cmd_service_action,
    "docker_action":  cmd_docker_action,
    # Alertas
    "set_thresholds":    cmd_set_thresholds,
    "get_thresholds":    cmd_get_thresholds,
    "set_custom_alerts": cmd_set_custom_alerts,
    "get_custom_alerts": cmd_get_custom_alerts,
    # Histórico y actualizaciones
    "metrics_history": cmd_metrics_history,
    "updates":         cmd_updates,
    "update_agent":    cmd_update_agent,
    "apply_updates":   cmd_apply_updates,
    # Homelab
    "cert_expiry":     cmd_cert_expiry,
    "check_endpoints": cmd_check_endpoints,
    "smart":           cmd_smart,
    # Sesiones de Claude Code
    "claude_sessions":   cmd_claude_sessions,
    "claude_transcript": cmd_claude_transcript,   # lectura
    "claude_reply":      cmd_claude_reply,        # control: exige ALLOW_CLAUDE_CONTROL=1
    "claude_stop":       cmd_claude_stop,
    "claude_start":      cmd_claude_start,
    "claude_push":       cmd_claude_push,
    "claude_hooks_install": cmd_claude_hooks_install,
    "claude_live_register":   cmd_claude_live_register,     # Live Activity (Dynamic Island)
    "claude_live_unregister": cmd_claude_live_unregister,
    # Terminales tmux (teclear/crear/cerrar exigen ALLOW_CLAUDE_CONTROL=1)
    "tmux_sessions":     cmd_tmux_sessions,
    "tmux_screen":       cmd_tmux_screen,
    "tmux_keys":         cmd_tmux_keys,
    "tmux_new":          cmd_tmux_new,
    "tmux_kill":         cmd_tmux_kill,
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
        scope  = msg.get("scope", "rw")
        log(f"CMD cmd={cmd} from={device} req_id={req_id} scope={scope}")
        fn = COMMAND_MAP.get(cmd)
        if fn is None:
            publish(req_id, "error", {"error": f"Comando desconocido: {cmd}"})
            return
        if scope == "ro" and cmd not in ALLOWED_RO:
            log(f"RO_DENIED cmd={cmd} req_id={req_id}")
            publish(req_id, "error", {"error": "Token de solo lectura: comando de control no permitido"})
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
            with urllib.request.urlopen(req, context=ctx, timeout=SSE_TIMEOUT) as resp:
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
    _load_custom_alerts()
    _load_metrics()
    threading.Thread(target=monitoring_thread, daemon=True, name="monitor").start()
    threading.Thread(target=claude_events_thread, daemon=True, name="claude-events").start()
    listen_loop()
