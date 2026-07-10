# Servward — Beta guide / Guía de la beta

> Control your Mac & Linux servers from your iPhone. This guide explains how to
> **update your agent** and how to **check everything is healthy** while testing.
>
> Controla tus servidores Mac y Linux desde el iPhone. Esta guía explica cómo
> **actualizar tu agente** y cómo **comprobar que todo va bien** durante la beta.

Current agent version / Versión actual del agente: **v1.7.0**

---

## 🇬🇧 English

### 1. Get started
1. In the app, open the **Guide** tab and run the one-line install command on your
   server (Mac or Linux):
   ```
   curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/servward-agent/main/install.sh | bash
   ```
2. Connect the app using the **token** the installer prints, over **Tailscale**
   (`http://100.x.x.x:2586`) or your **Cloudflare** domain (`https://…`).
   You can also **scan the QR** to add a second server.

### 2. How to update your agent
When a new app build ships, keep the server side in sync — two ways:

- **From the app (easiest, any OS):** go to **Settings → “Update the server agent”**
  and tap it. It pulls the latest agent and restarts it for you — Mac *and* Linux,
  no terminal needed.
- **From the server (fallback):** re-run the same install command. It updates in
  place and keeps your token and settings:
  ```
  curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/servward-agent/main/install.sh | bash
  ```

### 3. How to know everything is fine ✅
- **Version chip** (Control tab) should read **v1.7.0**, matching the app. If it
  shows an older version, **pull down to refresh** on the **Control** tab — the chip
  only updates while that tab is open.
- **Control** tab shows **live CPU / RAM / disk**. If the bars move, the app is
  talking to your server.
- **Health** screen gives an overall score plus per-disk **SMART** status
  (SMART needs `smartmontools` installed on the server).
- **No red “server down” alert** means the connection is healthy.
- If a value looks stuck: pull to refresh on Control, or fully close and reopen the
  app to force a fresh poll.

### 4. Reporting
Send any bug, odd wording, or confusing install step via TestFlight feedback.

---

## 🇪🇸 Español

### 1. Empezar
1. En la app, abre la pestaña **Guía** y ejecuta el comando de instalación de un
   pie en tu servidor (Mac o Linux):
   ```
   curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/servward-agent/main/install.sh | bash
   ```
2. Conecta la app con el **token** que imprime el instalador, por **Tailscale**
   (`http://100.x.x.x:2586`) o tu dominio **Cloudflare** (`https://…`).
   También puedes **escanear el QR** para añadir un segundo servidor.

### 2. Cómo actualizar tu agente
Cuando salga un build nuevo de la app, mantén el lado del servidor al día — dos vías:

- **Desde la app (lo más fácil, cualquier OS):** ve a **Ajustes → «Actualizar
  agente del servidor»** y púlsalo. Descarga el agente más reciente y lo reinicia
  por ti — Mac *y* Linux, sin terminal.
- **Desde el servidor (alternativa):** vuelve a ejecutar el mismo comando de
  instalación. Actualiza en el sitio y conserva tu token y ajustes:
  ```
  curl -fsSL https://raw.githubusercontent.com/INVESTMENTPERPLE/servward-agent/main/install.sh | bash
  ```

### 3. Cómo saber si todo está bien ✅
- El **chip de versión** (pestaña Control) debe poner **v1.7.0**, igual que la app.
  Si muestra una versión vieja, **desliza hacia abajo para refrescar** en la
  pestaña **Control** — el chip solo se actualiza con esa pestaña abierta.
- La pestaña **Control** muestra **CPU / RAM / disco en vivo**. Si las barras se
  mueven, la app está hablando con tu servidor.
- La pantalla **Salud** da una puntuación general y el estado **SMART** por disco
  (SMART necesita `smartmontools` instalado en el servidor).
- **Sin alerta roja de «servidor caído»** = la conexión está sana.
- Si un valor se queda pillado: refresca en Control, o cierra y reabre la app del
  todo para forzar un sondeo nuevo.

### 4. Reportar
Envía cualquier fallo, texto raro o paso confuso de instalación por el feedback de
TestFlight.
