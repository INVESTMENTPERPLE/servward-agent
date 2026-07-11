# Servward — Security Model

Servward is a **self-hosted** remote-control tool. The iOS app talks to a broker
(`server.py`) and an agent (`agent.py` / `agent_linux.py`) that **you** run on
**your own** machines. No data passes through EspymeLab servers.

Because it is self-hosted, security is a **shared responsibility**. This document
draws the line so it is clear what the software provides and what every operator
must do.

---

## Understand this first

The agent can **execute commands and scripts on the machine it runs on**
(run scripts, control processes, launch apps, control system power, take
screenshots). Access to all of it is gated by a **single bearer token**.

> **Whoever holds the token can run commands on your Mac.**
> Treat the token like a root password. It is the entire security boundary.

Everything below follows from that fact.

---

## What EspymeLab is responsible for (the code)

We build the agent and broker with reasonable care, including:

- **Authentication** on every sensitive endpoint (bearer token required).
- **Constant-time token comparison** to resist timing attacks.
- **Rate limiting** on failed authentication attempts.
- **Request size limits** to reduce abuse.
- **Allow-lists** for app launching and service control, plus URL-scheme checks.
- **No telemetry, analytics, or third-party SDKs** — the code phones nowhere.
- **Vulnerability handling** — we triage and patch reported issues (see
  [SECURITY.md](SECURITY.md)) and publish fixes on `main`.

What we **cannot** guarantee: that a deployment you misconfigure, a token you
leak, or a script you choose to run is safe. That is the operator's layer.

---

## What you (the operator) are responsible for

| Area | Your responsibility |
| ---- | ------------------- |
| **Token secrecy** | Keep the bearer token secret. Anyone who obtains it gets command execution on your Mac. Never commit it, never share it, rotate it if exposed. |
| **Token strength** | Use a long, random, unique token (e.g. `openssl rand -hex 32`). Do not reuse it elsewhere. |
| **Encrypted transport** | Expose the broker **only** through Cloudflare Tunnel, Tailscale, or TLS. Never over plain HTTP on a public port — the token would travel in clear text. |
| **Network exposure** | Do not publish the broker port (default `2586`) directly to the internet. Bind to `127.0.0.1` behind a tunnel and use a firewall. |
| **Updates** | Run the latest agent and broker, and keep macOS / Linux patched. |
| **Custom scripts** | You alone are responsible for any command or script you run through the agent, and for its consequences. |
| **Account / device access** | Secure the accounts and devices that hold the token (iCloud, your Mac). |

---

## Threat model

**Servward is designed to protect against:**

- A network attacker who does **not** have the token (blocked by authentication,
  rate limiting, and — when you use one — the tunnel / TLS layer).
- Casual scanning and brute-forcing of the token (rate limiting).

**Servward does _not_ protect against, by design:**

- An attacker who already has a valid token (they are, by definition,
  authorized — protect the token).
- A compromised or malicious machine running the agent.
- Commands or scripts the operator chooses to run.
- Misconfiguration (plain HTTP, exposed ports, weak or shared tokens).

---

## Optional hardening: bind the broker to Tailscale only

By default the broker listens on `0.0.0.0:2586` (all interfaces) so it works
over LAN, Tailscale or a local tunnel out of the box. If you only connect via
Tailscale, you can make the broker **unreachable from the LAN entirely** by
binding it to the machine's Tailscale IP with the `NTFY_BIND` environment
variable (already supported):

- **Linux** — edit `/etc/ntfy/ntfy.env`, add `NTFY_BIND=<your 100.x.y.z>`, then
  `sudo systemctl restart ntfy-server`. Note: the local agent reaches the broker
  through `NTFY_SERVER`; point it at the same Tailscale IP.
- **macOS** — add to the `EnvironmentVariables` dict in
  `~/Library/LaunchAgents/com.espymelab.ntfy.server.plist`:
  `<key>NTFY_BIND</key><string>your-100.x-IP</string>`, update `NTFY_SERVER` in
  the agent plist to match, then `ntfyctl restart`.

If you use a Cloudflare Tunnel instead, `NTFY_BIND=127.0.0.1` keeps the broker
loopback-only (the tunnel connects locally).

---

## Reporting

Found a weakness in the code? See [SECURITY.md](SECURITY.md). Please report it
privately rather than opening a public issue.
