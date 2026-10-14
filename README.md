# Debian & Ubuntu Multi-Protocol VPS Management Panel

A lightweight terminal CLI management panel (`menu`) for **Debian (10/11/12+)** and **Ubuntu (20.04/22.04/24.04+)** that provisions and manages **Xray-core** (`VLESS`, `VMess`, and `Trojan` over **WebSocket** and **TCP** on Ports `443` and `80`), **SSH over WebSocket** (Port `80` with custom HTTP payloads), **SSL/TLS SSH WebSocket** (Port `443` supporting **TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3**), and **BadVPN UDPGW** (Port `7300`).

## Core Features

| Feature | Details |
| :--- | :--- |
| **Xray Protocols (Ports 443 & 80)** | Creates `VLESS`, `VMess`, and `Trojan` accounts over both **WebSocket** (`/vless`, `/vmess`, `/trojan`) and **TCP** on Ports `443` (TLS) and `80` (HTTP), using the official [XTLS/Xray-install](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2FXTLS%2FXray-install) release script for [Xray-core](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fxtls%2Fxray-core). |
| **SSH WebSocket (Port 80)** | Accepts any custom HTTP injector payload (`GET`, `CONNECT`, custom bug headers, split payloads) on Port `80`, replies with `HTTP/1.1 101 Switching Protocols`, and forwards traffic to [Dropbear SSH](https://www.google.com/search?q=https%3A%2F%2Fmatt.ucc.asn.au%2Fdropbear%2Fdropbear.html) (`127.0.0.1:109`) or OpenSSH (`127.0.0.1:22`). |
| **SSL/TLS WebSocket (Port 443)** | Supports **all TLS versions (`TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`)** via `@SECLEVEL=0` and handles both Domain certificates via [acme.sh](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Facmesh-official%2Facme.sh) (Let's Encrypt) and IP-only self-signed X.509 certificates. |
| **Port 80/443 Multiplexing & Service Deactivation** | Runs SSH-WS and Xray simultaneously on Ports `80` and `443` by default (Shared Multiplex Mode), or lets you switch either port to **SSH-WS Exclusive** or **Xray Exclusive** mode (or stop/disable individual services) from the CLI menu to eliminate port conflicts. |
| **BadVPN UDPGW (Port 7300)** | Compiles and runs [ambrop72/badvpn](https://www.google.com/search?q=https%3A%2F%2Fgithub.com%2Fambrop72%2Fbadvpn) `badvpn-udpgw` as a systemd service on `127.0.0.1:7300` for UDP voice/gaming forwarding over SSH. |
| **User Expiration & Deletion** | Every SSH and Xray account is assigned a validity period in days (`chage -E` + `/usr/local/bin/xp-vps` daily cron job) and can be deleted or extended on demand. |
| **Connection Counter & Per-User IP Limit** | `limiter.py` maps proxied localhost sessions back to external client IPs (`X-Forwarded-For`, PROXY protocol v1, and `/run/vps-panel/ws_sessions.json`), displays live connection and unique IP counts per user, and kills or blocks excess IPs. |

## Repository Structure

* `install.sh` — Self-contained one-liner installer that installs dependencies, compiles BadVPN, sets up Xray-core, configures SSL (domain or IP), and installs all panel scripts and systemd units.
* `menu.sh` — Interactive terminal CLI panel installed to `/usr/local/bin/menu`.
* `ssh-ws.py` — Async Port `80` and `443` L4/L7 protocol multiplexer and custom-payload SSH WebSocket engine installed to `/usr/local/share/vps-panel/ssh-ws.py`.
* `limiter.py` — Background daemon (`vps-limiter.service`) and CLI status monitor (`--status`) enforcing per-user concurrent connection and unique IP limits.

## Quick Installation on a Debian / Ubuntu VPS

Run as `root` on a fresh Debian or Ubuntu server:

```bash
chmod +x install.sh
sudo ./install.sh
```

Once published to your GitHub repository (replace `<YOUR_GITHUB_USER>` and `<YOUR_REPO>`), you can install it on any VPS with a single command:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<YOUR_GITHUB_USER>/<YOUR_REPO>/main/install.sh)
```

After installation finishes, open the management panel at any time by running:

```bash
menu
```

## Publishing to GitHub

Run these commands inside a folder containing `install.sh`, `menu.sh`, `ssh-ws.py`, `limiter.py`, and `README.md`:

```bash
git init
git branch -M main
git add install.sh menu.sh ssh-ws.py limiter.py README.md
git commit -m "Initial release: Debian/Ubuntu SSH-WS & Xray VPS Management Panel"
git remote add origin https://github.com/<YOUR_GITHUB_USER>/<YOUR_REPO>.git
git push -u origin main
```
