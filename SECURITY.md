# Security Policy

Servward (the open-source agent and broker in this repository) is a self-hosted
tool that runs on machines you control. We take security seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Email **investmentperplexity@gmail.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce (a proof of concept if possible)
- The affected file(s) and version / commit

We aim to:

- **Acknowledge** your report within **72 hours**
- Provide an initial assessment within **7 days**
- Release a fix or mitigation as quickly as the severity warrants, and credit
  you in the release notes if you wish

## Supported versions

Security fixes are applied to the latest `main` branch. Always run the most
recent version of the agent and broker.

| Version       | Supported |
| ------------- | --------- |
| Latest `main` | ✅        |
| Older commits | ❌        |

## Scope

**In scope** — issues in the code we ship:

- `server.py` (the broker)
- `agent.py`, `agent_linux.py` (the agents)
- The deploy / setup scripts in this repository

**Out of scope** — the operator's own responsibility (see
[SECURITY-MODEL.md](SECURITY-MODEL.md)):

- Weak, shared, or leaked bearer tokens
- Exposing the broker without TLS or a tunnel
- Firewall, OS, and network configuration of your own machines
- Running untrusted custom scripts through the agent

## Why the split

Servward is designed to be **self-hosted**: the agent and broker run on your own
hardware and no data passes through EspymeLab servers. The security of any given
deployment is therefore shared between the software (our responsibility) and its
configuration (yours). See [SECURITY-MODEL.md](SECURITY-MODEL.md) for the full
breakdown.
