#!/usr/bin/env python3
"""
Servward — Agente Mac mini (Hardened + Extended Commands)
Lee comandos por SSE y publica respuestas. Token desde env var. HTTPS con
verificación del certificado local cuando el servidor usa TLS.

Requisitos previos:
    pip3 install psutil requests pillow --break-system-packages
    source ~/.ntfy_env
    python3 agent.py
"""

import base64
import io
import json
import logging
import os
import platform
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

import requests
import psutil

# ── Configuración desde env vars ──────────────────────────────────────────────
TOKEN       = os.environ.get("NTFY_TOKEN", "").strip()
NTFY_BASE   = os.environ.get("NTFY_SERVER", "").strip()
CERT_FILE   = os.environ.get("NTFY_CERT",  os.path.expanduser("~/ntfy_certs/server.crt"))
CMD_TOPIC   = os.environ.get("NTFY_CMD_TOPIC",  "cmd-macmini-demo")
RESP_TOPIC  = os.environ.get("NTFY_RESP_TOPIC", "resp-iphone-demo")
RECONNECT_S = 5
REQ_TIMEOUT = 30; os.environ["PATH"] = "/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "")

# ── APNs push ─────────────────────────────────────────────────────────────────
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APNS_CERT    = os.environ.get("APNS_CERT", os.path.join(_SCRIPT_DIR, "aps_cert.pem"))
APNS_KEY     = os.environ.get("APNS_KEY",  os.path.join(_SCRIPT_DIR, "apns_private_key.pem"))
APNS_BUNDLE  = "com.espymelab.NtfyControl"
APNS_HOST    = "api.push.apple.com"          # producción (App Store / TestFlight)
DEVICE_TOKEN_URL = f"http://127.0.0.1:{os.environ.get('NTFY_PORT', '2586')}/device-tokens"

# ── Umbrales de alerta ────────────────────────────────────────────────────────
ALERT_CPU_PCT   = float(os.environ.get("ALERT_CPU_PCT",  "85"))
ALERT_RAM_PCT   = float(os.environ.get("ALERT_RAM_PCT",  "85"))
ALERT_DISK_PCT  = float(os.environ.get("ALERT_DISK_PCT", "90"))
ALERT_TEMP_C    = float(os.environ.get("ALERT_TEMP_C",   "80"))
MONITOR_INTERVAL_S = int(os.environ.get("MONITOR_INTERVAL", "60"))
ALERT_COOLDOWN_S   = 600   # no re-alertar el mismo tipo en 10 min

if not TOKEN:
    sys.exit(
        "\n[FATAL] Variable NTFY_TOKEN no definida.\n"
        "Ejecuta: source ~/.ntfy_env\n"
    )

if not NTFY_BASE:
    bind = os.environ.get("NTFY_BIND", "localhost")
    port = os.environ.get("NTFY_PORT", "2586")
    proto = "https" if os.path.isfile(CERT_FILE) else "http"
    NTFY_BASE = f"{proto}://{bind}:{port}"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ntfy-agent")

# ── Contexto SSL ──────────────────────────────────────────────────────────────
def _make_ssl_ctx() -> Optional[ssl.SSLContext]:
    if not NTFY_BASE.startswith("https"):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    if os.path.isfile(CERT_FILE):
        ctx.load_verify_locations(CERT_FILE)
        log.info("SSL: confiando en cert local %s", CERT_FILE)
    else:
        log.warning("SSL: cert local no encontrado — usando verificación del sistema")
    return ctx

SSL_CTX = _make_ssl_ctx()
AUTH_HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# ── Helpers ───────────────────────────────────────────────────────────────────
def _run(cmd: list, timeout: int = 10) -> str:
    return subprocess.check_output(cmd, text=True, timeout=timeout,
                                   stderr=subprocess.DEVNULL).strip()

def _osascript(script: str) -> str:
    return _run(["osascript", "-e", script])

# ══════════════════════════════════════════════════════════════════════════════
#  COMANDOS
# ══════════════════════════════════════════════════════════════════════════════

# ── Monitor ───────────────────────────────────────────────────────────────────
def cmd_check_status(_args: dict) -> dict:
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_pct":    f"{cpu:.1f}%",
        "ram_used":   f"{mem.used  / 1e9:.1f} GB",
        "ram_total":  f"{mem.total / 1e9:.1f} GB",
        "ram_pct":    f"{mem.percent:.1f}%",
        "disk_used":  f"{disk.used  / 1e9:.1f} GB",
        "disk_total": f"{disk.total / 1e9:.1f} GB",
        "disk_pct":   f"{disk.percent:.1f}%",
        "hostname":   platform.node(),
        "os":         platform.platform(terse=True),
        "platform":   "mac",
    }

def cmd_ping_service(_args: dict) -> dict:
    targets = ["https://1.1.1.1", "https://google.com"]
    results = {}
    for url in targets:
        try:
            t0 = time.monotonic()
            req = urllib.request.Request(url, headers={"User-Agent": "NtfyAgent/1.0"})
            urllib.request.urlopen(req, timeout=5)
            ms = int((time.monotonic() - t0) * 1000)
            results[url] = f"ok ({ms} ms)"
        except Exception as e:
            results[url] = f"error: {e}"
    return results

def cmd_uptime(_args: dict) -> dict:
    boot = datetime.fromtimestamp(psutil.boot_time())
    diff = datetime.now() - boot
    days, rem = divmod(int(diff.total_seconds()), 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    return {
        "uptime":     f"{days}d {hours}h {mins}m",
        "boot_time":  boot.strftime("%Y-%m-%d %H:%M"),
        "hostname":   platform.node(),
    }

def cmd_disks(_args: dict) -> dict:
    result = {}
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            result[part.mountpoint] = (
                f"{u.used/1e9:.1f}/{u.total/1e9:.1f} GB ({u.percent:.0f}%)"
            )
        except Exception:
            pass
    return result

def cmd_temperatures(_args: dict) -> dict:
    result = {}
    # Método 1: osx-cpu-temp
    try:
        out = _run(["osx-cpu-temp"], timeout=5)
        result["cpu_temp"] = out
    except Exception:
        pass
    # Método 2: istats
    if not result:
        try:
            out = _run(["istats", "cpu", "--no-graphs"], timeout=5)
            for line in out.splitlines():
                if "temp" in line.lower() or "temperature" in line.lower():
                    result["cpu_temp"] = line.strip()
                    break
        except Exception:
            pass
    # Método 3: powermetrics (no sudo, modo seguro)
    if not result:
        try:
            out = _run(["sudo", "-n", "powermetrics", "--samplers", "smc",
                        "-n", "1", "-i", "500"], timeout=8)
            for line in out.splitlines():
                if "CPU die temperature" in line or "GPU die temperature" in line:
                    result[line.split(":")[0].strip()] = line.split(":")[-1].strip()
        except Exception:
            pass
    if not result:
        result["info"] = "Instala osx-cpu-temp: brew install osx-cpu-temp"
    return result

def cmd_last_jobs(_args: dict) -> dict:
    procs = []
    for p in sorted(psutil.process_iter(["name", "cpu_percent", "memory_percent"]),
                    key=lambda p: p.info["cpu_percent"] or 0, reverse=True)[:8]:
        procs.append(f"{p.info['name'][:20]:<20} CPU:{p.info['cpu_percent']:.1f}%  MEM:{p.info['memory_percent']:.1f}%")
    return {"processes": "\n".join(procs)}

def cmd_network_speed(_args: dict) -> dict:
    """Mide bajada y subida con networkQuality (Apple, multi-conexión)."""
    import re
    try:
        r = subprocess.run(
            ["networkQuality", "-s"],
            capture_output=True, text=True, timeout=90
        )
        output = r.stdout + r.stderr

        def extract(pattern):
            m = re.search(pattern, output, re.IGNORECASE)
            if not m:
                return None
            val = float(m.group(1))
            if "gbps" in m.group(0).lower():
                val *= 1000
            return round(val, 1)

        down = extract(r'Downlink capacity[^:]*:\s*([\d.]+)\s*[MG]bps')
        up   = extract(r'Uplink capacity[^:]*:\s*([\d.]+)\s*[MG]bps')

        if down is None and up is None:
            return {"error": "No se pudo parsear la salida", "raw": output[:300]}

        return {
            "bajada": f"{down} Mbps" if down else "—",
            "subida": f"{up} Mbps"   if up   else "—",
        }
    except FileNotFoundError:
        return {"error": "networkQuality requiere macOS 12 o superior"}
    except Exception as e:
        return {"error": str(e)}

# ── Sistema ───────────────────────────────────────────────────────────────────
def cmd_sleep_mac(_args: dict) -> dict:
    _osascript('tell application "System Events" to sleep')
    return {"status": "Durmiendo…"}

def cmd_restart_mac(_args: dict) -> dict:
    _osascript('tell application "System Events" to restart')
    return {"status": "Reiniciando…"}

def cmd_shutdown_mac(_args: dict) -> dict:
    _osascript('tell application "System Events" to shut down')
    return {"status": "Apagando…"}

def cmd_screenshot(_args: dict) -> dict:
    try:
        from PIL import Image
    except ImportError:
        return {"error": "Pillow no instalado. Ejecuta: pip3 install pillow --break-system-packages"}

    path = "/tmp/ntfy_screenshot.png"
    try:
        subprocess.run(["screencapture", "-x", "-t", "png", path],
                       timeout=10, check=True)
        img = Image.open(path).convert("RGB")
        # Reducir a max 900px ancho para que quepa en el payload (< 4MB)
        w, h = img.size
        if w > 900:
            img = img.resize((900, int(h * 900 / w)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=65)
        b64 = base64.b64encode(buf.getvalue()).decode()
        os.remove(path)
        size_kb = len(buf.getvalue()) // 1024
        return {
            "screenshot_b64": b64,
            "size_kb": str(size_kb),
            "resolution": f"{img.size[0]}x{img.size[1]}",
        }
    except Exception as e:
        return {"error": str(e)}

# ── Audio ─────────────────────────────────────────────────────────────────────
def cmd_mute(_args: dict) -> dict:
    _osascript("set volume output muted true")
    return {"audio": "silenciado"}

def cmd_unmute(_args: dict) -> dict:
    _osascript("set volume output muted false")
    return {"audio": "activado"}

def cmd_set_volume(args: dict) -> dict:
    raw = args.get("level", "50")
    try:
        level = max(0, min(100, int(raw)))
    except ValueError:
        return {"error": "El nivel debe ser un número entre 0 y 100"}
    _osascript(f"set volume output volume {level}")
    return {"volume": f"{level}%"}

def cmd_get_volume(_args: dict) -> dict:
    vol = _osascript("output volume of (get volume settings)")
    mut = _osascript("output muted of (get volume settings)")
    return {"volume": f"{vol}%", "muted": mut}

# ── Tareas ────────────────────────────────────────────────────────────────────
def cmd_kill_process(args: dict) -> dict:
    name = args.get("name", "").strip()
    if not name:
        return {"error": "Falta el nombre del proceso"}
    if not re.match(r'^[\w\-\.]+$', name):
        return {"error": "Nombre de proceso inválido (solo letras, números, guiones y puntos)"}
    try:
        result = subprocess.run(["pkill", "-f", name],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return {"killed": name}
        else:
            return {"error": f"Proceso '{name}' no encontrado"}
    except Exception as e:
        return {"error": str(e)}

def cmd_open(args: dict) -> dict:
    target = args.get("target", "").strip()
    if not target:
        return {"error": "Falta el argumento 'target'"}
    # Permitir URLs https/http
    if re.match(r'^https?://', target):
        subprocess.run(["open", target], timeout=5)
        return {"opened": target}
    # Permitir apps de la lista blanca
    ALLOWED_APPS = {
        "safari": "Safari", "finder": "Finder", "terminal": "Terminal",
        "music": "Music", "photos": "Photos", "mail": "Mail",
        "calendar": "Calendar", "notes": "Notes", "maps": "Maps",
        "calculator": "Calculator", "activity monitor": "Activity Monitor",
        "system settings": "System Settings",
    }
    key = target.lower()
    if key in ALLOWED_APPS:
        subprocess.run(["open", "-a", ALLOWED_APPS[key]], timeout=5)
        return {"opened": ALLOWED_APPS[key]}
    return {
        "error": f"Target no permitido: '{target}'",
        "apps_disponibles": ", ".join(ALLOWED_APPS.keys()),
    }

# ── Tailscale ─────────────────────────────────────────────────────────────────
def _tailscale(*args) -> str:
    """Localiza el binario de Tailscale en las rutas habituales de macOS."""
    for path in ["/usr/local/bin/tailscale", "/usr/bin/tailscale",
                 "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]:
        if os.path.isfile(path):
            return _run([path, *args], timeout=5)
    return _run(["tailscale", *args], timeout=5)

def cmd_tailscale_status(_args: dict) -> dict:
    try:
        # --peers=false: solo estado local, sin esperar a cada peer (instantáneo)
        raw = _tailscale("status", "--json", "--peers=false")
        info = json.loads(raw)
        state = info.get("BackendState", "desconocido")
        self_ip = ""
        if "Self" in info:
            ips = info["Self"].get("TailscaleIPs", [])
            self_ip = ips[0] if ips else ""
        return {
            "estado":    state,
            "ip_propia": self_ip or "—",
        }
    except Exception as e:
        return {"error": str(e)}

def cmd_tailscale_up(_args: dict) -> dict:
    try:
        _tailscale("up")
        return {"tailscale": "conectado"}
    except Exception as e:
        return {"error": str(e)}

def cmd_tailscale_down(_args: dict) -> dict:
    try:
        _tailscale("down")
        return {"tailscale": "desconectado"}
    except Exception as e:
        return {"error": str(e)}

# ── Scripts personalizados ────────────────────────────────────────────────────
def cmd_run_script(args: dict) -> dict:
    """Ejecuta scripts pre-aprobados de ~/ntfy_scripts/"""
    name = args.get("script", "").strip()
    if not name or not re.match(r'^[\w\-]+\.sh$', name):
        return {"error": "Nombre de script inválido (solo letras, números, guiones, extensión .sh)"}
    script_dir = os.path.expanduser("~/ntfy_scripts")
    if not os.path.isdir(script_dir):
        os.makedirs(script_dir, exist_ok=True)
        return {"error": "Carpeta ~/ntfy_scripts creada. Añade tus scripts ahí.", "directorio": script_dir}
    script_path = os.path.join(script_dir, name)
    if not os.path.isfile(script_path):
        available = [f for f in os.listdir(script_dir) if f.endswith(".sh")]
        return {
            "error": f"Script '{name}' no encontrado",
            "disponibles": ", ".join(available) or "ninguno",
        }
    try:
        out = subprocess.check_output(
            ["bash", script_path], text=True, timeout=30,
            stderr=subprocess.STDOUT
        )
        return {"output": out[:1000], "script": name}
    except subprocess.TimeoutExpired:
        return {"error": "Script excedió el tiempo límite de 30s"}
    except subprocess.CalledProcessError as e:
        return {"error": f"Error (código {e.returncode})", "output": (e.output or "")[:500]}

def cmd_list_scripts(_args: dict) -> dict:
    """Lista los scripts .sh de ~/ntfy_scripts (para el selector de la app)."""
    script_dir = os.path.expanduser("~/ntfy_scripts")
    if not os.path.isdir(script_dir):
        return {"scripts": "", "info": "La carpeta ~/ntfy_scripts no existe todavía"}
    files = sorted(f for f in os.listdir(script_dir) if f.endswith(".sh"))
    return {"scripts": "\n".join(files)}

# ── Umbrales ajustables en caliente ──────────────────────────────────────────
def cmd_set_thresholds(args: dict) -> dict:
    """Actualiza los umbrales de alerta sin reiniciar el agente."""
    global ALERT_CPU_PCT, ALERT_RAM_PCT, ALERT_DISK_PCT, ALERT_TEMP_C, MONITOR_INTERVAL_S
    changed = {}
    try:
        if "cpu" in args:
            ALERT_CPU_PCT = float(args["cpu"])
            changed["cpu"] = ALERT_CPU_PCT
        if "ram" in args:
            ALERT_RAM_PCT = float(args["ram"])
            changed["ram"] = ALERT_RAM_PCT
        if "disk" in args:
            ALERT_DISK_PCT = float(args["disk"])
            changed["disk"] = ALERT_DISK_PCT
        if "temp" in args:
            ALERT_TEMP_C = float(args["temp"])
            changed["temp"] = ALERT_TEMP_C
        if "interval" in args:
            MONITOR_INTERVAL_S = max(10, int(args["interval"]))
            changed["interval"] = MONITOR_INTERVAL_S
    except (ValueError, TypeError) as e:
        return {"error": f"Valor inválido: {e}"}
    if not changed:
        return {"error": "No se especificó ningún umbral"}
    log.info("Umbrales actualizados: %s", changed)
    return {
        "ok":        "true",
        "cpu_pct":   str(ALERT_CPU_PCT),
        "ram_pct":   str(ALERT_RAM_PCT),
        "disk_pct":  str(ALERT_DISK_PCT),
        "temp_c":    str(ALERT_TEMP_C),
        "intervalo": str(MONITOR_INTERVAL_S),
    }

# ══════════════════════════════════════════════════════════════════════════════
#  APNs PUSH NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

# ── Alertas personalizadas (reglas definidas por el usuario en la app) ────────
CUSTOM_ALERTS_FILE = os.environ.get("ALERTS_FILE",
                                    os.path.expanduser("~/.ntfy_custom_alerts.json"))
_custom_alerts: list = []
_alerts_lock = threading.Lock()
_script_last: dict[str, float] = {}

def _load_custom_alerts():
    global _custom_alerts
    try:
        if os.path.isfile(CUSTOM_ALERTS_FILE):
            with open(CUSTOM_ALERTS_FILE) as fh:
                data = json.load(fh)
            if isinstance(data, list):
                _custom_alerts = [r for r in data if isinstance(r, dict) and r.get("id")]
                log.info("CUSTOM_ALERTS cargadas: %d reglas", len(_custom_alerts))
    except Exception as e:
        log.warning("ALERTS_LOAD_ERROR %s", e)

def cmd_set_custom_alerts(args: dict) -> dict:
    """Recibe TODAS las reglas (JSON en args['rules']) y las aplica en caliente."""
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
            log.warning("ALERTS_SAVE_ERROR %s", e)
    log.info("CUSTOM_ALERTS actualizadas: %d reglas", len(rules))
    return {"ok": "true", "count": str(len(rules))}

def cmd_get_custom_alerts(_args: dict) -> dict:
    with _alerts_lock:
        return {"rules": json.dumps(_custom_alerts, ensure_ascii=False),
                "count": str(len(_custom_alerts))}

def _quiet_now(rule: dict) -> bool:
    """True si estamos dentro del horario silencioso de la regla."""
    try:
        qf = int(float(rule.get("quiet_from", -1)))
        qt = int(float(rule.get("quiet_to", -1)))
    except (TypeError, ValueError):
        return False
    if qf < 0 or qt < 0 or qf == qt:
        return False
    h = time.localtime().tm_hour
    return (qf <= h < qt) if qf < qt else (h >= qf or h < qt)

def _rule_fires(rule: dict, metrics: dict) -> bool:
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
        # macOS: LaunchAgent con estado != running
        if not target or not re.match(r'^[\w\-\.]+$', target):
            return False
        try:
            r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{target}"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                return True
            m = re.search(r"state = (.+)", r.stdout)
            return not (m and "running" in m.group(1))
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
        # scripts como mucho cada 10 min (son los más caros de evaluar)
        if not target or not re.match(r'^[\w\-]+\.sh$', target):
            return False
        rid = str(rule.get("id"))
        now = time.monotonic()
        if now - _script_last.get(rid, 0) < 600:
            return False
        _script_last[rid] = now
        path = os.path.join(os.path.expanduser("~/ntfy_scripts"), target)
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

def _eval_custom_alerts(metrics: dict):
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
            log.error("CUSTOM_ALERT_ERROR  %s", e)

def _get_device_tokens() -> list:
    """Lee los device tokens guardados en el servidor (localhost)."""
    try:
        req = urllib.request.Request(DEVICE_TOKEN_URL)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("tokens", [])
    except Exception as e:
        log.debug("No se pudieron leer device tokens: %s", e)
        return []

def send_push(title: str, body: str, data: dict = None) -> bool:
    """Envía push APNs via curl HTTP/2. Devuelve True si tuvo éxito."""
    if not os.path.isfile(APNS_CERT) or not os.path.isfile(APNS_KEY):
        log.warning("APNs certs no encontrados: %s / %s", APNS_CERT, APNS_KEY)
        return False
    tokens = _get_device_tokens()
    if not tokens:
        log.debug("No hay device tokens registrados — no se envía push")
        return False

    payload = {"aps": {"alert": {"title": title, "body": body}, "sound": "default",
               "category": "SW_ALERT"}}
    if data:
        payload["data"] = data
    payload_json = json.dumps(payload)

    success = False
    for token in tokens:
        cmd = [
            "curl", "--http2", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--cert", APNS_CERT,
            "--key",  APNS_KEY,
            "-H", f"apns-topic: {APNS_BUNDLE}",
            "-H", "apns-push-type: alert",
            "-H", "apns-priority: 10",
            "-d", payload_json,
            f"https://{APNS_HOST}/3/device/{token}",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            code = result.stdout.strip()
            if code == "200":
                log.info("PUSH_SENT  token=%.8s…  title=%r", token, title)
                success = True
            else:
                log.warning("PUSH_FAIL  token=%.8s…  http=%s  err=%s",
                            token, code, result.stderr[:120])
        except Exception as e:
            log.error("PUSH_ERROR  %s", e)
    return success


# ── Monitor de condiciones en background ──────────────────────────────────────

_last_alert: dict[str, float] = {}   # tipo_alerta → timestamp último envío

def _can_alert(key: str, cooldown: float = ALERT_COOLDOWN_S) -> bool:
    now = time.monotonic()
    if now - _last_alert.get(key, 0) > cooldown:
        _last_alert[key] = now
        return True
    return False

def _get_cpu_temp() -> Optional[float]:
    """Intenta obtener temperatura CPU en grados Celsius."""
    for cmd in [["osx-cpu-temp"], ["istats", "cpu", "--no-graphs"]]:
        try:
            out = _run(cmd, timeout=5)
            # Buscar número antes de °C
            m = re.search(r'([\d.]+)\s*°?C', out)
            if m:
                return float(m.group(1))
        except Exception:
            pass
    return None

def monitoring_thread():
    """Loop de monitoreo en background. Envía push si se superan umbrales."""
    log.info("Monitor iniciado — intervalo=%ds  CPU>%.0f%%  RAM>%.0f%%  disco>%.0f%%  temp>%.0f°C",
             MONITOR_INTERVAL_S, ALERT_CPU_PCT, ALERT_RAM_PCT, ALERT_DISK_PCT, ALERT_TEMP_C)
    while True:
        try:
            # CPU (promedio 2s para no fallar por picos)
            cpu = psutil.cpu_percent(interval=2)
            if cpu >= ALERT_CPU_PCT and _can_alert("cpu"):
                send_push(
                    "⚠️ CPU Alta",
                    f"Uso CPU al {cpu:.0f}% en {platform.node()}"
                )

            # RAM
            mem = psutil.virtual_memory()
            if mem.percent >= ALERT_RAM_PCT and _can_alert("ram"):
                send_push(
                    "⚠️ RAM Alta",
                    f"Memoria al {mem.percent:.0f}% "
                    f"({mem.used/1e9:.1f}/{mem.total/1e9:.1f} GB)"
                )

            # Disco raíz
            disk = psutil.disk_usage("/")
            if disk.percent >= ALERT_DISK_PCT and _can_alert("disk"):
                send_push(
                    "⚠️ Disco lleno",
                    f"Disco al {disk.percent:.0f}% "
                    f"({disk.used/1e9:.1f}/{disk.total/1e9:.1f} GB)"
                )

            # Temperatura CPU
            temp = _get_cpu_temp()
            if temp and temp >= ALERT_TEMP_C and _can_alert("temp"):
                send_push(
                    "🌡️ Temperatura Alta",
                    f"CPU a {temp:.1f}°C en {platform.node()}"
                )

            # Reglas personalizadas del usuario
            _eval_custom_alerts({
                "cpu":  cpu,
                "ram":  mem.percent,
                "disk": disk.percent,
                "temp": temp,
            })

        except Exception as e:
            log.error("MONITOR_ERROR  %s", e)

        time.sleep(MONITOR_INTERVAL_S)


# ── Servicios launchd y Docker (para la vista "Servicios y Docker") ───────────
LAUNCHD_WHITELIST = [s.strip() for s in os.environ.get(
    "SERVICE_WHITELIST",
    "com.espymelab.ntfy.server,com.espymelab.ntfy.agent").split(",") if s.strip()]

def cmd_services(_args: dict) -> dict:
    """Estado de los LaunchAgents de la whitelist."""
    uid = os.getuid()
    out = {}
    for label in LAUNCHD_WHITELIST:
        try:
            r = subprocess.run(["launchctl", "print", f"gui/{uid}/{label}"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                out[label] = "no cargado"
            else:
                m = re.search(r"state = (.+)", r.stdout)
                out[label] = (m.group(1).strip() if m else "cargado")
        except Exception:
            out[label] = "error"
    return out

def cmd_service_action(args: dict) -> dict:
    name   = args.get("name", "").strip()
    action = args.get("action", "status").strip()
    if name not in LAUNCHD_WHITELIST:
        return {"error": f"servicio no permitido: {name}"}
    uid    = os.getuid()
    target = f"gui/{uid}/{name}"
    try:
        if action == "restart":
            subprocess.run(["launchctl", "kickstart", "-k", target], timeout=15)
            return {"servicio": name, "accion": "restart", "resultado": "ok"}
        if action == "start":
            subprocess.run(["launchctl", "kickstart", target], timeout=15)
            return {"servicio": name, "accion": "start", "resultado": "ok"}
        if action == "stop":
            subprocess.run(["launchctl", "kill", "TERM", target], timeout=15)
            return {"servicio": name, "accion": "stop", "resultado": "ok"}
        return {"error": f"acción inválida: {action}"}
    except Exception as e:
        return {"error": str(e)}

def cmd_docker(_args: dict) -> dict:
    if not shutil.which("docker"):
        return {"docker": "no instalado"}
    try:
        out = subprocess.check_output(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}"],
            text=True, timeout=8, stderr=subprocess.DEVNULL).strip()
        if not out:
            return {"docker": "(sin contenedores)"}
        result = {}
        for line in out.splitlines():
            if "\t" in line:
                cname, status = line.split("\t", 1)
                result[cname] = status
        return result or {"docker": "(sin contenedores)"}
    except Exception as e:
        return {"docker": f"sin permiso o error ({e})"}

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

# ── Apps abiertas (GUI) ───────────────────────────────────────────────────────
def cmd_list_apps(_args: dict) -> dict:
    """Apps con interfaz (Dock/ventanas) abiertas ahora mismo."""
    try:
        r = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get name of every process whose background only is false'],
            capture_output=True, text=True, timeout=10)
        names = sorted(n.strip() for n in r.stdout.split(",") if n.strip())
        front = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get name of first process whose frontmost is true'],
            capture_output=True, text=True, timeout=10).stdout.strip()
        return {"apps": "\n".join(names), "count": str(len(names)), "frontmost": front}
    except Exception as e:
        return {"error": str(e)}

def cmd_activate_app(args: dict) -> dict:
    """Trae una app al primer plano."""
    name = (args.get("name") or "").strip()
    if not name:
        return {"error": "falta 'name'"}
    safe = name.replace('"', '\\"')
    try:
        r = subprocess.run(
            ["osascript", "-e",
             f'tell application "System Events" to set frontmost of process "{safe}" to true'],
            capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return {"error": r.stderr.strip() or "no se pudo activar"}
        return {"app": name, "accion": "activate", "resultado": "ok"}
    except Exception as e:
        return {"error": str(e)}

def cmd_quit_app(args: dict) -> dict:
    """Cierra una app de forma ordenada (equivalente a Cmd-Q)."""
    name = (args.get("name") or "").strip()
    if not name:
        return {"error": "falta 'name'"}
    safe = name.replace('"', '\\"')
    try:
        r = subprocess.run(
            ["osascript", "-e", f'tell application "{safe}" to quit'],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {"error": r.stderr.strip() or "no se pudo cerrar"}
        return {"app": name, "accion": "quit", "resultado": "ok"}
    except Exception as e:
        return {"error": str(e)}

# ── Mapa de comandos ──────────────────────────────────────────────────────────
COMMAND_MAP = {
    # Monitor
    "check_status":  cmd_check_status,
    "ping_service":  cmd_ping_service,
    "uptime":        cmd_uptime,
    "disks":         cmd_disks,
    "temperatures":  cmd_temperatures,
    "last_jobs":     cmd_last_jobs,
    "network_speed": cmd_network_speed,
    # Sistema
    "sleep_mac":     cmd_sleep_mac,
    "restart_mac":   cmd_restart_mac,
    "shutdown_mac":  cmd_shutdown_mac,
    "screenshot":    cmd_screenshot,
    # Audio
    "mute":          cmd_mute,
    "unmute":        cmd_unmute,
    "set_volume":    cmd_set_volume,
    "get_volume":    cmd_get_volume,
    # Tareas
    "kill_process":  cmd_kill_process,
    "open":          cmd_open,
    # Apps (GUI)
    "list_apps":     cmd_list_apps,
    "activate_app":  cmd_activate_app,
    "quit_app":      cmd_quit_app,
    # Tailscale
    "tailscale_status": cmd_tailscale_status,
    "tailscale_up":     cmd_tailscale_up,
    "tailscale_down":   cmd_tailscale_down,
    # Scripts
    "run_script":    cmd_run_script,
    "list_scripts":  cmd_list_scripts,
    # Servicios y Docker
    "services":       cmd_services,
    "docker":         cmd_docker,
    "service_action": cmd_service_action,
    "docker_action":  cmd_docker_action,
    # Alertas
    "set_thresholds": cmd_set_thresholds,
    "set_custom_alerts": cmd_set_custom_alerts,
    "get_custom_alerts": cmd_get_custom_alerts,
    "get_thresholds": lambda _: {
        "cpu_pct":   str(ALERT_CPU_PCT),
        "ram_pct":   str(ALERT_RAM_PCT),
        "disk_pct":  str(ALERT_DISK_PCT),
        "temp_c":    str(ALERT_TEMP_C),
        "intervalo": str(MONITOR_INTERVAL_S),
    },
}

# ── Publicar respuesta ────────────────────────────────────────────────────────
def publish(req_id: str, status: str, data: dict):
    payload = {
        "id":     f"resp_{int(time.time())}",
        "req_id": req_id,
        "status": status,
        "data":   data,
        "ts":     int(time.time()),
    }
    url = f"{NTFY_BASE}/{RESP_TOPIC}"
    verify = CERT_FILE if NTFY_BASE.startswith("https") and os.path.isfile(CERT_FILE) else True
    try:
        resp = requests.post(url, json=payload, headers=AUTH_HEADERS,
                             verify=verify, timeout=REQ_TIMEOUT)
        if resp.status_code == 200:
            log.info("PUBLISHED  req_id=%s  status=%s", req_id, status)
        else:
            log.warning("PUBLISH_FAIL  code=%d  body=%s", resp.status_code, resp.text[:120])
    except Exception as e:
        log.error("PUBLISH_ERROR  %s", e)

# ── Procesar comando ──────────────────────────────────────────────────────────
def handle(raw_msg: str):
    try:
        msg    = json.loads(raw_msg)
        req_id = msg.get("id", "unknown")
        cmd    = msg.get("cmd", "")
        args   = msg.get("args", {})
        device = msg.get("device", "?")
        log.info("CMD  cmd=%-20s  from=%s  req_id=%s", cmd, device, req_id)

        fn = COMMAND_MAP.get(cmd)
        if fn is None:
            publish(req_id, "error", {"error": f"Comando desconocido: {cmd}"})
            return

        data = fn(args)
        publish(req_id, "ok", data)
    except Exception as e:
        log.error("HANDLE_ERROR  %s", e)
        try:
            publish(msg.get("id", "unknown"), "error", {"error": str(e)})
        except Exception:
            pass

# ── Bucle SSE ─────────────────────────────────────────────────────────────────
def listen_loop():
    url = f"{NTFY_BASE}/{CMD_TOPIC}/sse"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept":        "text/event-stream",
        "Cache-Control": "no-cache",
    }
    while True:
        log.info("Conectando a %s…", url)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=None) as resp:
                log.info("✅  Conectado. Esperando comandos…")
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data: "):
                        payload = line[6:]
                        try:
                            envelope = json.loads(payload)
                            if envelope.get("event") == "message" and envelope.get("message"):
                                # Cada comando en su hilo: uno lento no bloquea a los demás.
                                threading.Thread(target=handle, args=(envelope["message"],),
                                                 daemon=True).start()
                        except json.JSONDecodeError:
                            pass
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log.error("Error de autenticación (401). Revisa NTFY_TOKEN.")
                time.sleep(30)
            elif e.code == 429:
                log.warning("Rate limited (429). Esperando 60s…")
                time.sleep(60)
            else:
                log.warning("HTTP error %d — reconectando en %ds…", e.code, RECONNECT_S)
                time.sleep(RECONNECT_S)
        except ssl.SSLError as e:
            log.error("SSL error: %s — reconectando en %ds…", e, RECONNECT_S)
            time.sleep(RECONNECT_S)
        except Exception as e:
            log.warning("Desconectado (%s) — reconectando en %ds…", e, RECONNECT_S)
            time.sleep(RECONNECT_S)

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("Servward Agent arrancando — %d comandos disponibles", len(COMMAND_MAP))
    log.info("Servidor: %s", NTFY_BASE)
    log.info("APNs cert: %s", APNS_CERT if os.path.isfile(APNS_CERT) else "NO ENCONTRADO")

    _load_custom_alerts()

    # Arrancar monitor en hilo background (daemon: muere con el proceso principal)
    t = threading.Thread(target=monitoring_thread, daemon=True, name="monitor")
    t.start()

    listen_loop()
