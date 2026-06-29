# NtfyControl — Organización del broker + agente

Mapa claro de qué corre dónde y cómo gestionarlo con un solo comando (`ntfyctl`).

## Arquitectura (recordatorio)

```
[ iPhone: app ]  ◄── túnel (Cloudflare / Tailscale) ──►  [ Broker ]  ◄── localhost ──►  [ Agente ]
   extremo 1                                              el medio                       extremo 2
```

El **broker** (`server.py`) solo reparte mensajes; el **agente** ejecuta los comandos.
Los dos viven **juntos en cada máquina** que controlas. Hay un par broker+agente por servidor.

## Layout estándar

| Pieza            | Linux (tu servidor)              | Mac (tu Mac)                                        |
|------------------|----------------------------------|-----------------------------------------------------|
| Gestor servicios | systemd                          | launchd                                             |
| Broker           | `ntfy-server`                    | `com.espymelab.ntfy.server`                         |
| Agente           | `ntfy-agent`                     | `com.espymelab.ntfy.agent`                          |
| Código           | `/opt/ntfy/server.py` · `agent_linux.py` | `~/.ntfycontrol/server.py` · `agent.py` |
| Variables (env)  | `/etc/ntfy/ntfy.env`             | dentro de los plists (`EnvironmentVariables`)       |
| Puerto broker    | `127.0.0.1:2586`                 | `localhost:2586`                                    |
| Topics           | `cmd-linux-prod` / `resp-linux-prod` | `cmd-macmini-demo` / `resp-iphone-demo`         |
| Salida al exterior | cloudflared (túnel propio) → `https://ntfy.tudominio.com` | Tailscale `100.x.x.x:2586` y/o cloudflared |
| Logs             | `journalctl -u ntfy-server / -u ntfy-agent` | `~/Library/Logs/ntfy/*.log` (tras `add_mac_logs`) |

> El Linux ya sigue el layout estándar (`/opt/ntfy` + `/etc/ntfy`). El Mac corre desde
> el repo de desarrollo a propósito: así un cambio de código se aplica con solo
> reiniciar, sin copiar nada. `ntfyctl` unifica ambos por nombre de servicio.

## ntfyctl — el mando único

Mismo comando en las dos máquinas (por dentro usa systemd o launchd):

```
ntfyctl status            # estado de broker + agente
ntfyctl restart           # reinicia ambos
ntfyctl restart agent     # reinicia solo el agente
ntfyctl start|stop [who]  # who: broker | agent | all
ntfyctl logs [who]        # últimas líneas de log
ntfyctl info              # rutas, puerto, servicios y topics
```

### Instalación

**Linux:**
```bash
cd /tmp/nfty && git pull
bash deploy/install_ntfyctl_linux.sh      # copia a /opt/ntfy y enlaza en el PATH
ntfyctl status
```

**Mac:**
```bash
cd ~/Developer/NFTY
bash deploy/install_ntfyctl_mac.command   # lo pone en /usr/local/bin
bash deploy/add_mac_logs.command          # (opcional) logs para `ntfyctl logs`
ntfyctl status
```

## Tareas habituales

| Quiero…                          | Comando                          |
|----------------------------------|----------------------------------|
| Ver si todo está vivo            | `ntfyctl status`                 |
| Reiniciar tras actualizar código | `ntfyctl restart`                |
| Ver por qué falla el agente      | `ntfyctl logs agent`             |
| Reiniciar solo el broker         | `ntfyctl restart broker`         |
| Ver rutas/puerto/topics          | `ntfyctl info`                   |

> Recuerda: no reinicies broker/agente/túnel **desde la app** (llevan la conexión);
> hazlo con `ntfyctl` desde la propia máquina o por SSH.

## (Opcional) Uniformar también el Mac a `/usr/local/ntfy`

Solo si quieres separar el runtime del repo de desarrollo (a cambio de tener que
sincronizar el código con un paso extra al actualizar). Resumen de pasos seguros:

1. `sudo mkdir -p /usr/local/ntfy && sudo cp server.py agent.py deploy/ntfyctl /usr/local/ntfy/`
2. Volcar las `EnvironmentVariables` de los plists a `/usr/local/ntfy/ntfy.env`.
3. Reescribir los plists para que ejecuten desde `/usr/local/ntfy` y carguen ese env
   (con backup `*.bak` de los plists actuales), y `bootout` + `bootstrap`.
4. Tras cada cambio de código: `cp` al runtime + `ntfyctl restart`.

Recomendación: de momento **no** hace falta; con `ntfyctl` + este documento el
despliegue ya queda claro y unificado. Si lo quieres, te paso el script de migración.
