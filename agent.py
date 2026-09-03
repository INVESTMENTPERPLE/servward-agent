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
import glob
import io
import json
import logging
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
SSE_TIMEOUT = int(os.environ.get("SSE_TIMEOUT", "70"))  # watchdog: reconecta si el broker no manda datos/heartbeat en Ns
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

# Versión del agente (se reporta a la app en check_status) y marcador de arranque.
AGENT_VERSION = "1.7.0"
LASTBOOT_FILE = os.environ.get("LASTBOOT_FILE", os.path.expanduser("~/.ntfy_lastboot"))

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
        "version":    AGENT_VERSION,
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
    if not re.match(r'^[\w\-\.]+$', name) or len(re.sub(r'[^A-Za-z0-9]', '', name)) < 2:
        return {"error": "Nombre de proceso inválido (mín. 2 caracteres alfanuméricos; sin comodines)"}
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
        req = urllib.request.Request(DEVICE_TOKEN_URL, headers=AUTH_HEADERS)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("tokens", [])
    except Exception as e:
        log.debug("No se pudieron leer device tokens: %s", e)
        return []

def _remove_device_token(token: str):
    """Pide al broker que borre un device token caducado (APNs 410)."""
    try:
        req = urllib.request.Request(DEVICE_TOKEN_URL[:-1],   # …/device-tokens → …/device-token
                                     data=json.dumps({"device_token": token}).encode(),
                                     method="DELETE",
                                     headers={**AUTH_HEADERS, "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        log.info("DEVICE_TOKEN_REMOVED (410) token=%.8s…", token)
    except Exception as e:
        log.debug("REMOVE_TOKEN_ERROR %s", e)

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
                if code == "410":            # token caducado → purgar del broker
                    _remove_device_token(token)
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

# ── Histórico de métricas (para la gráfica de la app) ─────────────────────────
METRICS_FILE = os.environ.get("METRICS_FILE", os.path.expanduser("~/.ntfy_metrics.json"))
METRICS_MAX  = 240                                   # ~4 h a 60 s por muestra
_metrics_hist: deque = deque(maxlen=METRICS_MAX)     # [ts, cpu, ram, disk]
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
        log.warning("METRICS_LOAD_ERROR %s", e)

def _save_metrics():
    try:
        with _metrics_lock:
            snapshot = list(_metrics_hist)
        with open(METRICS_FILE, "w") as fh:
            json.dump(snapshot, fh)
    except Exception as e:
        log.debug("METRICS_SAVE_ERROR %s", e)

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

# ── Actualizaciones del sistema (Homebrew + macOS) ────────────────────────────
def cmd_updates(_args: dict) -> dict:
    brew_list, brew_n = [], 0
    if shutil.which("brew"):
        try:
            out = subprocess.run(["brew", "outdated", "--quiet"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
            brew_list = [l.strip() for l in out.splitlines() if l.strip()]
            brew_n = len(brew_list)
        except Exception:
            pass
    os_list = []
    try:
        r = subprocess.run(["softwareupdate", "-l"],
                           capture_output=True, text=True, timeout=45)
        for line in (r.stdout + r.stderr).splitlines():
            line = line.strip()
            if line.startswith("* Label:"):
                os_list.append(line.split("Label:", 1)[1].strip())
    except Exception:
        pass
    names = brew_list + [f"macOS: {x}" for x in os_list]
    mgr = (["Homebrew"] if shutil.which("brew") else []) + ["macOS"]
    return {
        "count":   str(brew_n + len(os_list)),
        "brew":    str(brew_n),
        "system":  str(len(os_list)),
        "list":    "\n".join(names),
        "manager": " + ".join(mgr),
    }

def cmd_apply_updates(_args: dict) -> dict:
    """Actualiza los paquetes de Homebrew (espacio de usuario, sin sudo)."""
    if not shutil.which("brew"):
        return {"error": "Homebrew no está instalado. Las actualizaciones de macOS "
                         "se instalan desde Ajustes del sistema › General › Software."}
    try:
        r = subprocess.run(["brew", "upgrade"], capture_output=True, text=True, timeout=600)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return {"resultado": "ok" if r.returncode == 0 else f"código {r.returncode}",
                "output": out[-1200:] or "(sin salida)",
                "nota": "Las actualizaciones de macOS se instalan desde Ajustes del sistema."}
    except subprocess.TimeoutExpired:
        return {"error": "La actualización sigue en curso (>10 min). Vuelve a comprobar en un rato."}
    except Exception as e:
        return {"error": str(e)}

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
    """Salud SMART de los discos (requiere smartmontools: brew install smartmontools)."""
    if not shutil.which("smartctl"):
        return {"info": "smartctl no instalado (brew install smartmontools)"}
    try:
        scan = subprocess.run(["smartctl", "--scan"], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        return {"error": str(e)}
    out = {}
    for line in scan.splitlines():
        parts = line.split()
        if not parts:
            continue
        dev = parts[0]
        try:
            r = subprocess.run(["smartctl", "-H", dev], capture_output=True, text=True, timeout=15)
            m = re.search(r"(?:overall-health self-assessment test result|SMART Health Status):\s*(.+)", r.stdout)
            if m:
                out[dev] = m.group(1).strip()
            elif "permission" in r.stdout.lower() or r.returncode != 0:
                out[dev] = "sin permiso"
            else:
                out[dev] = "desconocido"
        except Exception:
            out[dev] = "error"
    return out or {"info": "sin discos SMART detectados"}

def cmd_update_agent(_args: dict) -> dict:
    """Actualiza el propio agente/broker desde GitHub y se reinicia (Mac, sin sudo)."""
    src = os.path.expanduser("~/.ntfycontrol")
    if not os.path.isdir(os.path.join(src, ".git")):
        return {"error": "No encuentro ~/.ntfycontrol; actualiza con 'ntfyctl update'."}
    uid = str(os.getuid())
    repo = "https://github.com/INVESTMENTPERPLE/servward-agent.git"
    script = (f'cd "{src}" && git remote set-url origin "{repo}" && git fetch origin -q && '
              f'git reset --hard origin/main -q && '
              f'launchctl kickstart -k "gui/{uid}/com.espymelab.ntfy.server" 2>/dev/null; '
              f'launchctl kickstart -k "gui/{uid}/com.espymelab.ntfy.agent" 2>/dev/null')
    subprocess.Popen(["bash", "-lc", f"sleep 1; {script}"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return {"status": "Actualizando… el agente se reiniciará en unos segundos", "action": "updating"}

def _check_reboot():
    """Detecta si la máquina se reinició desde la última ejecución y avisa."""
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
            send_push("🔄 Servidor reiniciado",
                      f"{platform.node()} se reinició hace {up_min} min")
    except Exception as e:
        log.debug("REBOOT_CHECK_ERROR %s", e)

def monitoring_thread():
    """Loop de monitoreo en background. Envía push si se superan umbrales."""
    log.info("Monitor iniciado — intervalo=%ds  CPU>%.0f%%  RAM>%.0f%%  disco>%.0f%%  temp>%.0f°C",
             MONITOR_INTERVAL_S, ALERT_CPU_PCT, ALERT_RAM_PCT, ALERT_DISK_PCT, ALERT_TEMP_C)
    _check_reboot()
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

            # Registrar muestra para el histórico de la app
            _record_metrics(cpu, mem.percent, disk.percent)

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
    safe = name.replace('\\', '\\\\').replace('"', '\\"')
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
    safe = name.replace('\\', '\\\\').replace('"', '\\"')
    try:
        r = subprocess.run(
            ["osascript", "-e", f'tell application "{safe}" to quit'],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {"error": r.stderr.strip() or "no se pudo cerrar"}
        return {"app": name, "accion": "quit", "resultado": "ok"}
    except Exception as e:
        return {"error": str(e)}

# ── Sesiones de Claude Code ───────────────────────────────────────────────────
# Claude Code deja una ficha por sesión viva en ~/.claude/sessions/<pid>.json y una por
# trabajo en segundo plano en ~/.claude/jobs/<id>/state.json. Aquí solo se LEEN: el
# comando no mata, no escribe ni manda nada a las sesiones.
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
    log.info("CLAUDE_STOP job=%s session=%s", info["job_id"], info["session_id"][:8])
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
    log.info("CLAUDE_REPLY session=%s chars=%d", info["session_id"][:8], len(text))
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
    log.info("CLAUDE_START cwd=%s name=%r chars=%d", cwd, name, len(text))
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

def _tmux(*args, timeout: int = 10) -> str:
    argv = [_tmux_bin()] + (["-L", TMUX_SOCKET] if TMUX_SOCKET else []) + list(args)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          check=True).stdout

def _tmux_missing():
    if not _tmux_bin():
        return {"error": "tmux no está instalado en esta máquina"}
    return None

def _tmux_target_ok(t: str) -> bool:
    return bool(t) and bool(_TMUX_TARGET_RE.match(t))

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
    try:
        raw = _tmux("list-panes", "-a", "-F", fmt)
    except subprocess.CalledProcessError as e:
        if "no server running" in (e.stderr or "") or "error connecting" in (e.stderr or ""):
            return {"count": "0", "host": platform.node(), "panes": "[]"}
        return {"error": (e.stderr or str(e)).strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    claude = _claude_by_tmux_pane()
    panes = []
    for line in raw.splitlines():
        f = line.split("\x1f")
        if len(f) < 14:
            continue
        cl = claude.get(f[3], {})
        panes.append({
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
    return {"count": str(len(panes)), "host": platform.node(),
            "control": "1" if ALLOW_CLAUDE_CONTROL else "0",
            "panes": json.dumps(panes, ensure_ascii=False)}

def cmd_tmux_screen(args: dict) -> dict:
    """Pantalla actual de un pane, con colores ANSI (SGR) salvo plain=1. `back` = líneas
    de scrollback por encima de la pantalla (0-2000)."""
    missing = _tmux_missing()
    if missing:
        return missing
    target = str(args.get("target") or "").strip()
    if not _tmux_target_ok(target):
        return {"error": "falta 'target' (sesión:ventana.pane)"}
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
        screen = _tmux(*cap)
        info = _tmux("display-message", "-p", "-t", target,
                     "#{pane_width}\x1f#{pane_height}\x1f#{cursor_x}\x1f#{cursor_y}\x1f"
                     "#{pane_in_mode}\x1f#{alternate_on}\x1f#{history_size}\x1f#{pane_title}\x1f"
                     "#{pane_current_command}\x1f#{pane_dead}").strip().split("\x1f")
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
    try:
        if text:
            _tmux("send-keys", "-t", target, "-l", "--", text)
        if keys:
            _tmux("send-keys", "-t", target, *keys)
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo enviar").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log.info("TMUX_KEYS target=%s chars=%d keys=%s", target, len(text), " ".join(keys)[:60])
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
    try:
        _tmux("new-session", "-d", "-s", name, "-c", cwd, "-x", str(cols), "-y", str(rows), *program)
        target = _tmux("display-message", "-p", "-t", name,
                       "#{session_name}:#{window_index}.#{pane_index}").strip()
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo crear").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log.info("TMUX_NEW session=%s cwd=%s program=%s", name, cwd, " ".join(program)[:80])
    return {"ok": "1", "target": target, "session": name, "cwd": cwd}

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
    try:
        _tmux("kill-session", "-t", f"={session}")
    except subprocess.CalledProcessError as e:
        return {"error": (e.stderr or "no se pudo cerrar").strip()[:200]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": f"tmux: {e}"[:200]}
    log.info("TMUX_KILL session=%s", session)
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
    log.info("CLAUDE_HOOKS %s", "removed" if args.get("remove") else "installed")
    return {"ok": "1", "hooks": "1" if _claude_hooks_installed() else "0", "settings": path}

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
        send_push(f"🖐 Te necesita · {label}", body,
                  {"type": "claude", "event": "needs_you", "session": sid, "host": platform.node()})
    elif name == "Stop":
        info = _claude_find(sid)
        is_bg = bool(info and info.get("kind") == "bg")
        if not (is_bg or CLAUDE_PUSH_STOP_ALL):
            return
        if not _can_alert(f"claude-stop-{sid}", 30):
            return
        label = _claude_session_label(sid, cwd)
        body = _claude_last_answer(str(ev.get("transcript_path") or "")) or "Ha terminado la tarea"
        send_push(f"✅ Terminó · {label}", body,
                  {"type": "claude", "event": "done", "session": sid, "host": platform.node()})

def claude_events_thread():
    """Lee las líneas nuevas de claude-events.jsonl y las convierte en avisos."""
    offset = os.path.getsize(CLAUDE_EVENTS_FILE) if os.path.exists(CLAUDE_EVENTS_FILE) else 0
    log.info("Eventos de Claude: vigilando %s (push %s)", CLAUDE_EVENTS_FILE,
             "activo" if _claude_push_enabled() else "APAGADO")
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
                                log.warning("CLAUDE_EVENT_ERROR %s", e)
                if size > CLAUDE_EVENTS_MAX_BYTES and offset >= size:
                    open(CLAUDE_EVENTS_FILE, "w").close()
                    offset = 0
        except Exception as e:
            log.warning("CLAUDE_EVENTS_LOOP %s", e)
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
    # Histórico y actualizaciones
    "metrics_history": cmd_metrics_history,
    "updates":         cmd_updates,
    "update_agent":    cmd_update_agent,
    "apply_updates":   cmd_apply_updates,
    # Homelab
    "cert_expiry":     cmd_cert_expiry,
    "check_endpoints": cmd_check_endpoints,
    "smart":           cmd_smart,
    # Sesiones de Claude Code (transcript = lectura; el resto exige ALLOW_CLAUDE_CONTROL=1)
    "claude_sessions":   cmd_claude_sessions,
    "claude_transcript": cmd_claude_transcript,
    "claude_reply":      cmd_claude_reply,
    "claude_stop":       cmd_claude_stop,
    "claude_start":      cmd_claude_start,
    "claude_push":       cmd_claude_push,
    "claude_hooks_install": cmd_claude_hooks_install,
    # Terminales tmux (el terminal del móvil; teclear/crear/cerrar exigen ALLOW_CLAUDE_CONTROL=1)
    "tmux_sessions":     cmd_tmux_sessions,
    "tmux_screen":       cmd_tmux_screen,
    "tmux_keys":         cmd_tmux_keys,
    "tmux_new":          cmd_tmux_new,
    "tmux_kill":         cmd_tmux_kill,
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
        scope  = msg.get("scope", "rw")      # lo inyecta el broker; ausente = control
        log.info("CMD  cmd=%-20s  from=%s  req_id=%s  scope=%s", cmd, device, req_id, scope)

        fn = COMMAND_MAP.get(cmd)
        if fn is None:
            publish(req_id, "error", {"error": f"Comando desconocido: {cmd}"})
            return

        if scope == "ro" and cmd not in ALLOWED_RO:
            log.warning("RO_DENIED  cmd=%s  req_id=%s", cmd, req_id)
            publish(req_id, "error", {"error": "Token de solo lectura: comando de control no permitido"})
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
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=SSE_TIMEOUT) as resp:
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
    _load_metrics()

    # Arrancar monitor en hilo background (daemon: muere con el proceso principal)
    t = threading.Thread(target=monitoring_thread, daemon=True, name="monitor")
    t.start()
    # Avisos de sesiones de Claude Code (lee los eventos que deja el hook)
    threading.Thread(target=claude_events_thread, daemon=True, name="claude-events").start()

    listen_loop()
