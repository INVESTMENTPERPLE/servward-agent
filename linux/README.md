# Servward — broker en un servidor Linux (con Cloudflare Tunnel)

Monta el broker `server.py` en tu Linux de producción y exponlo por Cloudflare
Tunnel. El Mac (agent.py), el iPhone (app) y "lo demás" se conectan a él.

```
 iPhone (app) ─┐
               ├──► https://ntfy.tudominio.com (Cloudflare) ──► cloudflared ──► 127.0.0.1:2586 (server.py)
 Mac (agent) ──┘                                                                        ▲
                                                                      el agente del Mac también se conecta aquí
```

## 1. Copiar el código al Linux

En el servidor Linux:

```bash
git clone https://github.com/INVESTMENTPERPLE/servward-agent.git
cd servward-agent
```

(o copia al menos `server.py` y la carpeta `linux/`).

## 2. Instalar el broker como servicio

```bash
sudo bash linux/setup_linux.sh
```

Luego edita el token (usa **el mismo** que ya tiene tu Mac, en `start_server.sh`):

```bash
sudo nano /etc/ntfy/ntfy.env       # NTFY_TOKEN=...
sudo systemctl restart ntfy-server
systemctl status ntfy-server
```

Comprobación local (responde `404` o `401` = está vivo; `000` = caído):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:2586/
```

## 3. Cloudflare Tunnel

Instala cloudflared (Debian/Ubuntu):

```bash
curl -L https://pkg.cloudflare.com/cloudflared.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloudflare.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
```

Crea el túnel y la ruta DNS (necesita tu dominio en Cloudflare):

```bash
cloudflared tunnel login                      # abre el navegador, elige tu dominio
cloudflared tunnel create ntfy                # apunta el TUNNEL_ID que imprime
cloudflared tunnel route dns ntfy ntfy.tudominio.com
```

Coloca la config (ajusta `<TUNNEL_ID>` y el hostname):

```bash
sudo install -d /etc/cloudflared
sudo cp linux/cloudflared-config.yml /etc/cloudflared/config.yml
sudo nano /etc/cloudflared/config.yml         # <TUNNEL_ID> y ntfy.tudominio.com
# las credenciales <TUNNEL_ID>.json suelen quedar en ~/.cloudflared/ → muévelas:
sudo cp ~/.cloudflared/<TUNNEL_ID>.json /etc/cloudflared/
```

Arranca cloudflared como servicio:

```bash
sudo cloudflared service install
sudo systemctl restart cloudflared
sudo systemctl status cloudflared
```

Prueba desde fuera:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://ntfy.tudominio.com/   # 404/401 = ok
```

## 4. Conectar la app (iPhone)

Ajustes → **Añadir servidor**:

- **URL:** `https://ntfy.tudominio.com`  (sin `:2586`)
- **Token:** el `NTFY_TOKEN`
- **Topics:** `cmd-macmini-demo` / `resp-iphone-demo` (los mismos del agente)
- Si proteges el túnel con **Cloudflare Access**, rellena "Cloudflare Zero Trust"
  con el `clientId:clientSecret` de un Service Token.

## 5. Apuntar el agente del Mac al broker Linux

Para que el Mac reciba comandos a través del broker en prod, arráncalo con
`NTFY_SERVER` apuntando al hostname público. En el Mac, edita el LaunchAgent
del agente (o `start_agent.sh`) y añade:

```bash
export NTFY_SERVER="https://ntfy.tudominio.com"
```

Reinicia el agente:

```bash
launchctl kickstart -k gui/$(id -u)/com.espymelab.ntfy.agent
```

> Nota: si mueves el broker al Linux, el **push APNs** necesita un ajuste extra.
> El agente lee los device tokens de `http://127.0.0.1:2586/device-tokens`
> (solo localhost). Con el broker remoto hay que exponer/leer ese endpoint de
> forma autenticada. Dímelo y lo adapto — para empezar, comandos y respuestas
> en tiempo real ya funcionan sin tocar eso.

## Diagnóstico rápido

```bash
journalctl -u ntfy-server -f      # logs del broker
journalctl -u cloudflared -f      # logs del túnel
```
