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
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import deque

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
        req = urllib.request.Request(DEVICE_TOKEN_URL)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("tokens", [])
    except Exception:
        return []

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

def monitoring_thread():
    log(f"Monitor iniciado — intervalo={MONITOR_INTERVAL_S}s CPU>{ALERT_CPU_PCT:.0f}% "
        f"RAM>{ALERT_RAM_PCT:.0f}% disco>{ALERT_DISK_PCT:.0f}% temp>{ALERT_TEMP_C:.0f}°C")
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
    "apply_updates":   cmd_apply_updates,
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
    _load_custom_alerts()
    _load_metrics()
    threading.Thread(target=monitoring_thread, daemon=True, name="monitor").start()
    listen_loop()
