#!/usr/bin/env bash
# =============================================================================
# Debian & Ubuntu VPS Management Panel — One-Line Installer (`install.sh`)
# Integrates open-source components:
#   - Xray-core (https://github.com/XTLS/Xray-core via XTLS/Xray-install)
#   - BadVPN UDPGW Port 7300 (https://github.com/ambrop72/badvpn)
#   - acme.sh Let's Encrypt Client (https://github.com/acmesh-official/acme.sh)
#   - Dropbear SSH, OpenSSH, Nginx, OpenSSL (TLS 1.0, 1.1, 1.2, 1.3 enabled)
# =============================================================================

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: Please run this installer as root (sudo bash install.sh)."
    exit 1
fi

if ! grep -qiE "debian|ubuntu" /etc/os-release 2>/dev/null; then
    echo "Warning: This script is designed for Debian and Ubuntu."
fi

CONFIG_DIR="/etc/vps-panel"
SHARE_DIR="/usr/local/share/vps-panel"
RUN_DIR="/run/vps-panel"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${CONFIG_DIR}/ssl" "${SHARE_DIR}" "${RUN_DIR}" /var/log/xray /var/www/html

echo "[1/8] Installing system packages and build dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    curl wget git jq python3 openssl ca-certificates \
    nginx dropbear socat cron net-tools iproute2 \
    cmake build-essential uuid-runtime psmisc

# -----------------------------------------------------------------------------
# Enable All TLS Versions (TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3) in OpenSSL
# -----------------------------------------------------------------------------
echo "[2/8] Configuring OpenSSL & Dropbear for full TLS 1.0-1.3 and SSH-WS compatibility..."
if [[ -f /etc/ssl/openssl.cnf ]] && ! grep -q "SECLEVEL=0" /etc/ssl/openssl.cnf; then
    cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.bak
    cat >> /etc/ssl/openssl.cnf <<'EOF'

[vps_panel_tls_sect]
MinProtocol = None
CipherString = DEFAULT@SECLEVEL=0
EOF
fi

# Configure Dropbear on local port 109 (so Port 80/443 multiplexer forwards SSH-WS cleanly)
if [[ -f /etc/default/dropbear ]]; then
    sed -i 's/^NO_START=.*/NO_START=0/' /etc/default/dropbear || true
    sed -i 's/^DROPBEAR_PORT=.*/DROPBEAR_PORT=109/' /etc/default/dropbear || true
    if ! grep -q "^DROPBEAR_PORT=" /etc/default/dropbear; then
        echo 'DROPBEAR_PORT=109' >> /etc/default/dropbear
    fi
fi
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells
systemctl enable dropbear 2>/dev/null || true
systemctl restart dropbear 2>/dev/null || true

# -----------------------------------------------------------------------------
# Install Xray-core via Official XTLS/Xray-install Open-Source Script
# -----------------------------------------------------------------------------
echo "[3/8] Installing official Xray-core (https://github.com/XTLS/Xray-install)..."
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

cat > /usr/local/etc/xray/config.json <<'EOF'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "tag": "vless-ws",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    },
    {
      "tag": "vmess-ws",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    },
    {
      "tag": "trojan-ws",
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan"
        }
      }
    },
    {
      "tag": "vless-tcp",
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "sockopt": {
          "acceptProxyProtocol": true
        }
      }
    },
    {
      "tag": "vmess-tcp",
      "listen": "127.0.0.1",
      "port": 10005,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "sockopt": {
          "acceptProxyProtocol": true
        }
      }
    },
    {
      "tag": "trojan-tcp",
      "listen": "127.0.0.1",
      "port": 10006,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "sockopt": {
          "acceptProxyProtocol": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "blocked"
    }
  ]
}
EOF

systemctl enable xray
systemctl restart xray

# -----------------------------------------------------------------------------
# Build & Install BadVPN UDPGW on Port 7300 (from ambrop72/badvpn)
# -----------------------------------------------------------------------------
echo "[4/8] Installing BadVPN UDPGW on Port 7300 (https://github.com/ambrop72/badvpn)..."
if ! command -v badvpn-udpgw &>/dev/null; then
    BADVPN_TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/ambrop72/badvpn.git "${BADVPN_TMP}/badvpn"
    mkdir -p "${BADVPN_TMP}/badvpn/build"
    pushd "${BADVPN_TMP}/badvpn/build" >/dev/null
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make -j"$(nproc)"
    cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
    chmod +x /usr/local/bin/badvpn-udpgw
    popd >/dev/null
    rm -rf "${BADVPN_TMP}"
fi

cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=BadVPN UDPGW Service on Port 7300
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl restart badvpn-udpgw

# -----------------------------------------------------------------------------
# Configure Nginx on 127.0.0.1:8080 for ACME HTTP-01 Validation
# -----------------------------------------------------------------------------
echo "[5/8] Configuring Nginx ACME responder on 127.0.0.1:8080..."
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/conf.d/vps-panel-acme.conf <<'EOF'
server {
    listen 127.0.0.1:8080 default_server;
    server_name _;
    root /var/www/html;
    location /.well-known/acme-challenge/ {
        allow all;
    }
}
EOF
systemctl enable nginx
systemctl restart nginx

# -----------------------------------------------------------------------------
# Install Panel Daemons (ssh-ws.py, limiter.py, xp-vps, menu)
# -----------------------------------------------------------------------------
echo "[6/8] Installing SSH-WS Multiplexer, Per-User IP Limiter, and CLI Menu..."

cat > "${SHARE_DIR}/ssh-ws.py" <<'EOF_SSH_WS'
#!/usr/bin/env python3
"""
VPS Panel - Multi-Protocol Port 80 & 443 Multiplexer & Custom-Payload SSH WebSocket Proxy
Supports:
  - SSH over WebSocket (Port 80 & 443) with ANY custom HTTP payload (GET, CONNECT, split payloads, bug hosts)
  - Direct SSL/SSH (Stunnel-style SSH-2.0 handshake on Port 443/80)
  - Xray WebSocket (/vless, /vmess, /trojan) on Port 80 & 443 with X-Forwarded-For injection
  - Xray TCP (VLESS TCP, VMess TCP, Trojan TCP) on Port 80 & 443 with PROXY Protocol v1 header injection
  - ACME HTTP-01 challenge forwarding (/.well-known/acme-challenge/) to Nginx (127.0.0.1:8080)
  - TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3 support on Port 443 (@SECLEVEL=0)
  - Exclusive Port Mode overrides via /etc/vps-panel/port_mode.conf
  - Live session tracking (/run/vps-panel/ws_sessions.json) for accurate per-user IP limiting
"""

import asyncio
import json
import logging
import os
import re
import signal
import socket
import ssl
import sys
import time
from typing import Dict, Optional, Tuple

CONFIG_DIR = "/etc/vps-panel"
RUN_DIR = "/run/vps-panel"
PORT_MODE_FILE = os.path.join(CONFIG_DIR, "port_mode.conf")
SESSIONS_FILE = os.path.join(RUN_DIR, "ws_sessions.json")
BLOCKED_IPS_FILE = os.path.join(RUN_DIR, "blocked_ips.json")
CERT_FILE = os.path.join(CONFIG_DIR, "ssl/fullchain.pem")
KEY_FILE = os.path.join(CONFIG_DIR, "ssl/privkey.pem")

# Local backend targets
SSH_BACKEND_HOST = "127.0.0.1"
DROPBEAR_PORT = 109
OPENSSH_PORT = 22
NGINX_ACME_PORT = 8080

# Xray internal inbound ports
XRAY_VLESS_WS_PORT = 10001
XRAY_VMESS_WS_PORT = 10002
XRAY_TROJAN_WS_PORT = 10003
XRAY_VLESS_TCP_PORT = 10004
XRAY_VMESS_TCP_PORT = 10005
XRAY_TROJAN_TCP_PORT = 10006

TROJAN_HEX_RE = re.compile(rb"^[0-9a-fA-F]{56}\r\n")
HTTP_METHODS = (
    b"GET ", b"POST ", b"CONNECT ", b"HEAD ", b"PUT ",
    b"OPTIONS ", b"DELETE ", b"PATCH ", b"TRACE "
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("ssh-ws")

active_sessions: Dict[str, dict] = {}


def load_port_modes() -> Dict[str, str]:
    """
    Reads /etc/vps-panel/port_mode.conf.
    Values for PORT_80_MODE and PORT_443_MODE:
      - 'shared'   : Both SSH-WS and Xray enabled (multiplexed)
      - 'ssh_only' : Only SSH-WS / SSH-SSL allowed on that port (Xray disabled on port)
      - 'xray_only': Only Xray (WS & TCP) allowed on that port (SSH-WS disabled on port)
      - 'off'      : Port listener disabled
    """
    modes = {"PORT_80_MODE": "shared", "PORT_443_MODE": "shared"}
    if os.path.exists(PORT_MODE_FILE):
        try:
            with open(PORT_MODE_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        modes[k.strip()] = v.strip().strip('"').strip("'")
        except Exception as exc:
            logger.warning("Failed to read %s: %s", PORT_MODE_FILE, exc)
    return modes


def is_ip_blocked(client_ip: str) -> bool:
    """Checks if client_ip is temporarily blocked by limiter.py for exceeding IP limits."""
    if not os.path.exists(BLOCKED_IPS_FILE):
        return False
    try:
        with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        expiry = data.get(client_ip, 0)
        return time.time() < expiry
    except Exception:
        return False


def flush_sessions() -> None:
    """Writes active proxied sessions to /run/vps-panel/ws_sessions.json for limiter.py."""
    os.makedirs(RUN_DIR, exist_ok=True)
    tmp_path = SESSIONS_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(active_sessions, f)
        os.replace(tmp_path, SESSIONS_FILE)
    except Exception as exc:
        logger.debug("Could not write sessions file: %s", exc)


def get_ssh_backend_port() -> int:
    """Prefer Dropbear on port 109 if listening, otherwise fallback to OpenSSH on port 22."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        if s.connect_ex((SSH_BACKEND_HOST, DROPBEAR_PORT)) == 0:
            return DROPBEAR_PORT
    return OPENSSH_PORT


def extract_http_path(data: bytes) -> str:
    """Extracts the request path from the first HTTP line, tolerating custom payloads."""
    try:
        first_line = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        parts = first_line.decode("latin1", errors="ignore").split()
        if len(parts) >= 2:
            path = parts[1]
            # Handle full URL in custom payloads like GET http://bug.host/vless HTTP/1.1
            if path.startswith("http://") or path.startswith("https://"):
                idx = path.find("/", 8)
                path = path[idx:] if idx != -1 else "/"
            return path.split("?", 1)[0]
    except Exception:
        pass
    return "/"


def inject_forwarded_for(data: bytes, client_ip: str) -> bytes:
    """Injects X-Forwarded-For and X-Real-IP into HTTP WebSocket upgrade headers for Xray."""
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return data
    extra = (
        f"\r\nX-Forwarded-For: {client_ip}\r\nX-Real-IP: {client_ip}"
    ).encode("latin1")
    return data[:header_end] + extra + data[header_end:]


def classify_traffic(
    initial_data: bytes, listen_port: int, mode: str
) -> Tuple[str, int, bool]:
    """
    Determines the target backend based on initial payload bytes and active port mode.
    Returns: (target_type, target_port, send_ws_101_handshake)
    target_type in {'ssh', 'xray_ws', 'xray_tcp', 'acme', 'reject'}
    """
    # Always allow Let's Encrypt ACME HTTP-01 challenges on port 80
    if initial_data.startswith(b"GET /.well-known/acme-challenge/"):
        return ("acme", NGINX_ACME_PORT, False)

    # Check if raw SSH handshake (e.g. Stunnel/SSL direct SSH client)
    if initial_data.startswith(b"SSH-2.0-") or initial_data.startswith(b"SSH-1."):
        if mode == "xray_only":
            return ("reject", 0, False)
        return ("ssh", get_ssh_backend_port(), False)

    # Check if HTTP / WebSocket / Custom Payload request
    is_http = any(initial_data.upper().startswith(m) for m in HTTP_METHODS)
    if not is_http and b"HTTP/" in initial_data[:256] or b"Upgrade: websocket" in initial_data[:512]:
        is_http = True

    if is_http:
        path = extract_http_path(initial_data)
        if path.startswith("/vless"):
            if mode == "ssh_only":
                return ("reject", 0, False)
            return ("xray_ws", XRAY_VLESS_WS_PORT, False)
        if path.startswith("/vmess"):
            if mode == "ssh_only":
                return ("reject", 0, False)
            return ("xray_ws", XRAY_VMESS_WS_PORT, False)
        if path.startswith("/trojan"):
            if mode == "ssh_only":
                return ("reject", 0, False)
            return ("xray_ws", XRAY_TROJAN_WS_PORT, False)

        # Any other HTTP request or custom payload -> SSH WebSocket!
        if mode == "xray_only":
            return ("reject", 0, False)
        return ("ssh", get_ssh_backend_port(), True)

    # Non-HTTP traffic -> Xray TCP (Trojan TCP, VLESS TCP, VMess TCP)
    if mode == "ssh_only":
        return ("reject", 0, False)

    if TROJAN_HEX_RE.match(initial_data[:58]):
        return ("xray_tcp", XRAY_TROJAN_TCP_PORT, False)

    # VLESS TCP starts with version byte 0x00 followed by 16-byte UUID
    if len(initial_data) >= 17 and initial_data[0] == 0x00:
        return ("xray_tcp", XRAY_VLESS_TCP_PORT, False)

    # Fallback binary stream -> VMess TCP
    return ("xray_tcp", XRAY_VMESS_TCP_PORT, False)


async def pipe_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(16384)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    listen_port: int,
) -> None:
    peer = client_writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "0.0.0.0"
    client_port = peer[1] if peer else 0

    if is_ip_blocked(client_ip):
        client_writer.close()
        return

    modes = load_port_modes()
    mode_key = "PORT_443_MODE" if listen_port == 443 else "PORT_80_MODE"
    mode = modes.get(mode_key, "shared")
    if mode == "off":
        client_writer.close()
        return

    try:
        initial_data = await asyncio.wait_for(client_reader.read(4096), timeout=10.0)
    except Exception:
        client_writer.close()
        return

    if not initial_data:
        client_writer.close()
        return

    target_type, target_port, send_101 = classify_traffic(initial_data, listen_port, mode)
    if target_type == "reject" or target_port == 0:
        try:
            client_writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            await client_writer.drain()
        except Exception:
            pass
        client_writer.close()
        return

    # Handle split payloads used by custom SSH injectors (where a second payload chunk follows immediately)
    if send_101:
        try:
            client_writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n"
                b"Server: VPS-Panel-WS\r\n\r\n"
            )
            await client_writer.drain()
        except Exception:
            client_writer.close()
            return

    try:
        backend_reader, backend_writer = await asyncio.wait_for(
            asyncio.open_connection(SSH_BACKEND_HOST, target_port), timeout=5.0
        )
    except Exception as exc:
        logger.debug("Backend %s:%d unreachable: %s", SSH_BACKEND_HOST, target_port, exc)
        client_writer.close()
        return

    local_sock = backend_writer.get_extra_info("sockname")
    local_ephemeral_port = str(local_sock[1]) if local_sock else f"{client_ip}:{client_port}"

    # Record active session so limiter.py can map localhost ports back to external client IPs
    active_sessions[local_ephemeral_port] = {
        "client_ip": client_ip,
        "client_port": client_port,
        "listen_port": listen_port,
        "target_type": target_type,
        "target_port": target_port,
        "connected_at": int(time.time()),
    }
    flush_sessions()

    try:
        if target_type == "ssh":
            # If initial_data already contained an SSH-2.0 banner (either direct or appended after payload), forward it
            ssh_idx = initial_data.find(b"SSH-2.0-")
            if ssh_idx != -1:
                backend_writer.write(initial_data[ssh_idx:])
                await backend_writer.drain()
        elif target_type == "xray_ws":
            forwarded_payload = inject_forwarded_for(initial_data, client_ip)
            backend_writer.write(forwarded_payload)
            await backend_writer.drain()
        elif target_type == "xray_tcp":
            # Inject PROXY protocol v1 header so Xray logs the real external client IP
            proxy_hdr = (
                f"PROXY TCP4 {client_ip} 127.0.0.1 {client_port} {listen_port}\r\n"
            ).encode("latin1")
            backend_writer.write(proxy_hdr + initial_data)
            await backend_writer.drain()
        else:
            backend_writer.write(initial_data)
            await backend_writer.drain()

        await asyncio.gather(
            pipe_stream(client_reader, backend_writer),
            pipe_stream(backend_reader, client_writer),
        )
    finally:
        active_sessions.pop(local_ephemeral_port, None)
        flush_sessions()


def build_all_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
    """
    Creates an OpenSSL context supporting ALL TLS versions (TLS 1.0, 1.1, 1.2, 1.3)
    by lowering security level to 0 (@SECLEVEL=0) and clearing protocol floor.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT")

    # Enable TLS 1.0 through TLS 1.3
    if hasattr(ssl, "TLSVersion"):
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        except Exception:
            pass

    # Ensure OP_NO_TLSv1 and OP_NO_TLSv1_1 are NOT set
    for opt_name in ("OP_NO_TLSv1", "OP_NO_TLSv1_1", "OP_NO_TLSv1_2", "OP_NO_TLSv1_3"):
        opt_val = getattr(ssl, opt_name, 0)
        if opt_val:
            ctx.options &= ~opt_val

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx


async def main() -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    flush_sessions()

    modes = load_port_modes()
    servers = []

    # Start Port 80 listener unless disabled
    if modes.get("PORT_80_MODE", "shared") != "off":
        srv80 = await asyncio.start_server(
            lambda r, w: handle_client(r, w, 80),
            host="0.0.0.0",
            port=80,
            reuse_address=True,
        )
        servers.append(srv80)
        logger.info("Listening on 0.0.0.0:80 (mode=%s)", modes.get("PORT_80_MODE", "shared"))

    # Start Port 443 SSL/TLS listener unless disabled
    if modes.get("PORT_443_MODE", "shared") != "off":
        if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
            ssl_ctx = build_all_tls_context(CERT_FILE, KEY_FILE)
            srv443 = await asyncio.start_server(
                lambda r, w: handle_client(r, w, 443),
                host="0.0.0.0",
                port=443,
                ssl=ssl_ctx,
                reuse_address=True,
            )
            servers.append(srv443)
            logger.info(
                "Listening on 0.0.0.0:443 SSL/TLS [TLS 1.0-1.3 enabled] (mode=%s)",
                modes.get("PORT_443_MODE", "shared"),
            )
        else:
            logger.warning("SSL certificate missing at %s; Port 443 listener skipped.", CERT_FILE)

    if not servers:
        logger.warning("Both Port 80 and Port 443 are set to 'off'. Sleeping...")
        while True:
            await asyncio.sleep(60)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()
    for srv in servers:
        srv.close()
        await srv.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
EOF_SSH_WS

cat > "${SHARE_DIR}/limiter.py" <<'EOF_LIMITER'
#!/usr/bin/env python3
"""
VPS Panel - Connection Counter & Per-User IP Limit Enforcer (SSH + Xray)
Modes:
  - `limiter.py --daemon` : Continuously monitors SSH and Xray connections every 10s,
                            disconnecting extra sessions or temporarily blocking excess IPs.
  - `limiter.py --status` : Prints a formatted live table of every SSH & Xray user,
                            their configured IP/connection limit, active connection count,
                            and connected client IP addresses.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from typing import Dict, List, Set, Tuple

CONFIG_DIR = "/etc/vps-panel"
RUN_DIR = "/run/vps-panel"
SSH_DB = os.path.join(CONFIG_DIR, "ssh-users.db")
XRAY_DB = os.path.join(CONFIG_DIR, "xray-users.db")
SESSIONS_FILE = os.path.join(RUN_DIR, "ws_sessions.json")
BLOCKED_IPS_FILE = os.path.join(RUN_DIR, "blocked_ips.json")
XRAY_ACCESS_LOG = "/var/log/xray/access.log"
LIMIT_LOG = "/var/log/vps-panel-limiter.log"


def load_ws_sessions() -> Dict[str, dict]:
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_ssh_users() -> Dict[str, dict]:
    """ Format of ssh-users.db: username|password|exp_date|max_ip """
    users = {}
    if not os.path.exists(SSH_DB):
        return users
    with open(SSH_DB, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                users[parts[0]] = {
                    "password": parts[1],
                    "exp": parts[2],
                    "max_ip": int(parts[3]) if parts[3].isdigit() else 2,
                }
    return users


def load_xray_users() -> Dict[str, dict]:
    """ Format of xray-users.db: username|protocol|uuid_or_pwd|exp_date|max_ip """
    users = {}
    if not os.path.exists(XRAY_DB):
        return users
    with open(XRAY_DB, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 5:
                users[parts[0]] = {
                    "protocol": parts[1],
                    "secret": parts[2],
                    "exp": parts[3],
                    "max_ip": int(parts[4]) if parts[4].isdigit() else 2,
                }
    return users


def get_ssh_active_sessions() -> Dict[str, List[Tuple[int, str]]]:
    """
    Returns {username: [(pid, client_ip), ...]} across OpenSSH and Dropbear,
    resolving localhost WebSocket proxy ports via /run/vps-panel/ws_sessions.json.
    """
    ws_map = load_ws_sessions()
    user_sessions: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    # Map PID -> peer IP:port from `ss -tnp`
    pid_to_peer: Dict[int, Tuple[str, str]] = {}
    try:
        out = subprocess.check_output(["ss", "-tnp"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "ESTAB" not in line:
                continue
            cols = line.split()
            if len(cols) < 6:
                continue
            peer_addr = cols[4]
            proc_info = " ".join(cols[5:])
            # Extract IPv4/IPv6 and port
            if peer_addr.startswith("["):
                ip_part, port_part = peer_addr.rsplit(":", 1)
                ip_part = ip_part.strip("[]")
            else:
                ip_part, port_part = peer_addr.rsplit(":", 1)
            if ip_part.startswith("::ffff:"):
                ip_part = ip_part.replace("::ffff:", "")

            # Resolve real external client IP if connection came via ssh-ws.py on 127.0.0.1
            if ip_part == "127.0.0.1" and port_part in ws_map:
                ip_part = ws_map[port_part].get("client_ip", "127.0.0.1")

            for m in re.finditer(r"pid=(\d+)", proc_info):
                pid_to_peer[int(m.group(1))] = (ip_part, port_part)
    except Exception:
        pass

    # Inspect OpenSSH privilege-separated user processes (`sshd: user...`)
    try:
        ps_out = subprocess.check_output(
            ["ps", "-eo", "pid,ppid,user,args"], text=True, stderr=subprocess.DEVNULL
        )
        for line in ps_out.splitlines()[1:]:
            parts = line.strip().split(None, 3)
            if len(parts) < 4:
                continue
            pid_s, ppid_s, uname, args = parts
            pid, ppid = int(pid_s), int(ppid_s)
            if args.startswith("sshd:") and uname not in ("root", "sshd"):
                peer = pid_to_peer.get(pid) or pid_to_peer.get(ppid)
                client_ip = peer[0] if peer else "127.0.0.1"
                user_sessions[uname].append((pid, client_ip))
    except Exception:
        pass

    return user_sessions


def get_xray_active_sessions(window_seconds: int = 90) -> Dict[str, Tuple[int, Set[str]]]:
    """
    Parses /var/log/xray/access.log for recent accepted lines within `window_seconds`.
    Returns {username: (connection_count, {set_of_unique_ips})}.
    Xray log line format:
      2026/10/15 04:10:12 from 203.0.113.5:51234 accepted tcp:1.1.1.1:443 [inbound -> direct] email: alice@vless
    """
    results: Dict[str, Tuple[int, Set[str]]] = {}
    if not os.path.exists(XRAY_ACCESS_LOG):
        return results

    now = time.time()
    conn_counts: Dict[str, int] = defaultdict(int)
    user_ips: Dict[str, Set[str]] = defaultdict(set)

    line_re = re.compile(
        r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}).*?from\s+(?:tcp:)?([0-9a-fA-F\.:]+):\d+\s+accepted.*?email:\s+([^\s@]+)"
    )

    try:
        # Read last 2000 lines for speed
        out = subprocess.check_output(
            ["tail", "-n", "2000", XRAY_ACCESS_LOG], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            m = line_re.search(line)
            if not m:
                continue
            ts_str, client_ip, username = m.group(1), m.group(2), m.group(3)
            try:
                ts = time.mktime(time.strptime(ts_str, "%Y/%m/%d %H:%M:%S"))
                if now - ts > window_seconds:
                    continue
            except Exception:
                pass
            if client_ip != "127.0.0.1":
                conn_counts[username] += 1
                user_ips[username].add(client_ip)
    except Exception:
        pass

    for uname in set(conn_counts.keys()) | set(user_ips.keys()):
        results[uname] = (conn_counts[uname], user_ips[uname])
    return results


def block_client_ip(client_ip: str, duration_sec: int = 120) -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    blocked = {}
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                blocked = json.load(f)
        except Exception:
            blocked = {}
    # Clean expired blocks
    now = time.time()
    blocked = {ip: exp for ip, exp in blocked.items() if exp > now}
    blocked[client_ip] = now + duration_sec
    try:
        with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(blocked, f)
    except Exception:
        pass


def enforce_once() -> None:
    ssh_users = load_ssh_users()
    ssh_active = get_ssh_active_sessions()

    for uname, meta in ssh_users.items():
        max_ip = meta["max_ip"]
        sessions = ssh_active.get(uname, [])
        if not sessions:
            continue
        seen_ips: List[str] = []
        for pid, cip in sessions:
            if cip not in seen_ips:
                seen_ips.append(cip)
            # Enforce both unique IP limit and total concurrent session limit
            if len(seen_ips) > max_ip or len(sessions) > max_ip * 2:
                try:
                    os.kill(pid, 9)
                    with open(LIMIT_LOG, "a", encoding="utf-8") as lf:
                        lf.write(
                            f"{time.strftime('%Y-%m-%d %H:%M:%S')} [SSH] Killed excess session PID {pid} "
                            f"for user '{uname}' from IP {cip} (limit={max_ip})\n"
                        )
                except Exception:
                    pass

    xray_users = load_xray_users()
    xray_active = get_xray_active_sessions(window_seconds=90)

    for uname, meta in xray_users.items():
        max_ip = meta["max_ip"]
        if uname not in xray_active:
            continue
        conn_count, ips = xray_active[uname]
        if len(ips) > max_ip:
            sorted_ips = sorted(ips)
            excess_ips = sorted_ips[max_ip:]
            for eip in excess_ips:
                block_client_ip(eip, duration_sec=180)
                with open(LIMIT_LOG, "a", encoding="utf-8") as lf:
                    lf.write(
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} [XRAY] Blocked excess IP {eip} (180s) "
                        f"for user '{uname}' ({len(ips)}/{max_ip} IPs active)\n"
                    )


def print_status() -> None:
    ssh_users = load_ssh_users()
    ssh_active = get_ssh_active_sessions()
    xray_users = load_xray_users()
    xray_active = get_xray_active_sessions(window_seconds=90)

    print("\n=== SSH Users: Active Connections & IP Limits ===")
    print(f"{'Username':<16} {'Expires':<12} {'Conns':<8} {'Unique IPs / Limit':<20} {'Active Client IPs'}")
    print("-" * 80)
    if not ssh_users:
        print("No SSH users created yet.")
    for uname, meta in sorted(ssh_users.items()):
        sessions = ssh_active.get(uname, [])
        ips = sorted({cip for _, cip in sessions})
        ip_ratio = f"{len(ips)} / {meta['max_ip']}"
        ip_list = ", ".join(ips) if ips else "-"
        print(f"{uname:<16} {meta['exp']:<12} {len(sessions):<8} {ip_ratio:<20} {ip_list}")

    print("\n=== Xray Users: Active Connections & IP Limits ===")
    print(f"{'Username':<16} {'Proto':<8} {'Expires':<12} {'Conns':<8} {'Unique IPs / Limit':<20} {'Active Client IPs'}")
    print("-" * 90)
    if not xray_users:
        print("No Xray users created yet.")
    for uname, meta in sorted(xray_users.items()):
        conn_count, ips_set = xray_active.get(uname, (0, set()))
        ips = sorted(ips_set)
        ip_ratio = f"{len(ips)} / {meta['max_ip']}"
        ip_list = ", ".join(ips) if ips else "-"
        print(f"{uname:<16} {meta['protocol']:<8} {meta['exp']:<12} {conn_count:<8} {ip_ratio:<20} {ip_list}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="VPS Panel Connection & IP Limiter")
    parser.add_argument("--daemon", action="store_true", help="Run continuous enforcement loop")
    parser.add_argument("--status", action="store_true", help="Print live user connection & IP table")
    args = parser.parse_args()

    if args.status:
        print_status()
        return

    if args.daemon:
        while True:
            enforce_once()
            time.sleep(10)
    else:
        enforce_once()


if __name__ == "__main__":
    main()
EOF_LIMITER

cat > /usr/local/bin/menu <<'EOF_MENU'
#!/usr/bin/env bash
# =============================================================================
# VPS Management Panel CLI (`menu`) for Debian & Ubuntu
# Supports:
#   - SSH & SSH-WS (Port 80 Custom Payload) & SSH-SSL (Port 443 All TLS 1.0-1.3)
#   - Xray-core (VLESS, VMess, Trojan over WebSocket & TCP on Ports 443 & 80)
#   - BadVPN UDPGW (Port 7300)
#   - User Validity (Days), Expiration Cron, User Deletion, Per-User IP Limiter
#   - Service Status Monitor & Port Conflict / Exclusive Mode Switcher
# =============================================================================

set -u

CONFIG_DIR="/etc/vps-panel"
SSH_DB="${CONFIG_DIR}/ssh-users.db"
XRAY_DB="${CONFIG_DIR}/xray-users.db"
PORT_MODE_FILE="${CONFIG_DIR}/port_mode.conf"
DOMAIN_FILE="${CONFIG_DIR}/domain"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
CERT_FILE="${CONFIG_DIR}/ssl/fullchain.pem"
KEY_FILE="${CONFIG_DIR}/ssl/privkey.pem"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "${CONFIG_DIR}"
touch "${SSH_DB}" "${XRAY_DB}"

get_host() {
    if [[ -s "${DOMAIN_FILE}" ]]; then
        cat "${DOMAIN_FILE}"
    else
        curl -fsSL4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}'
    fi
}

svc_badge() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${GREEN}[ACTIVE]${NC}"
    else
        echo -e "${RED}[INACTIVE]${NC}"
    fi
}

get_port_mode_label() {
    local key="$1"
    local val="shared"
    if [[ -f "${PORT_MODE_FILE}" ]]; then
        val=$(grep -E "^${key}=" "${PORT_MODE_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "shared")
    fi
    case "${val}" in
        shared)    echo -e "${GREEN}Shared Multiplex (SSH-WS + Xray WS/TCP)${NC}" ;;
        ssh_only)  echo -e "${YELLOW}SSH-WS Exclusive (Xray Disabled on Port)${NC}" ;;
        xray_only) echo -e "${CYAN}Xray Exclusive (SSH-WS Disabled on Port)${NC}" ;;
        off)       echo -e "${RED}Disabled (Port Closed)${NC}" ;;
        *)         echo -e "${GREEN}Shared Multiplex${NC}" ;;
    esac
}

# -----------------------------------------------------------------------------
# SSH User Management
# -----------------------------------------------------------------------------
create_ssh_user() {
    echo -e "\n${CYAN}--- Create SSH / SSH-WS / SSL User ---${NC}"
    read -rp "Username: " uname
    if [[ -z "${uname}" ]]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        return
    fi
    if id "${uname}" &>/dev/null; then
        echo -e "${RED}User '${uname}' already exists!${NC}"
        return
    fi
    read -rp "Password: " upass
    read -rp "Validity (days, e.g. 30): " days
    read -rp "Max Concurrent IPs (e.g. 2): " max_ip

    days=${days:-30}
    max_ip=${max_ip:-2}
    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")

    useradd -e "${exp_date}" -s /bin/false -M "${uname}"
    echo "${uname}:${upass}" | chpasswd

    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo "${uname}|${upass}|${exp_date}|${max_ip}" >> "${SSH_DB}"

    local host
    host=$(get_host)
    echo -e "\n${GREEN}=== SSH / WebSocket Account Created ===${NC}"
    echo -e "Host / IP          : ${host}"
    echo -e "Username           : ${uname}"
    echo -e "Password           : ${upass}"
    echo -e "Expires On         : ${exp_date} (${days} days)"
    echo -e "Max IP Limit       : ${max_ip} IP(s)"
    echo -e "OpenSSH Port       : 22"
    echo -e "Dropbear Port      : 109"
    echo -e "SSH WS (HTTP) Port : 80 (Supports any custom payload)"
    echo -e "SSH SSL/WS Port    : 443 (Supports TLS 1.0, 1.1, 1.2, 1.3)"
    echo -e "BadVPN UDPGW Port  : 7300"
    echo -e "Sample Payload     : GET / HTTP/1.1[crlf]Host: ${host}[crlf]Upgrade: websocket[crlf][crlf]"
}

delete_ssh_user() {
    echo -e "\n${CYAN}--- Delete SSH User ---${NC}"
    if [[ ! -s "${SSH_DB}" ]]; then
        echo -e "${YELLOW}No SSH users found.${NC}"
        return
    fi
    nl -w2 -s'. ' "${SSH_DB}" | awk -F'|' '{printf "%s %-16s (Expires: %s, Max IP: %s)\n", $1, $2, $3, $4}'
    read -rp "Enter username to delete: " uname
    if [[ -z "${uname}" ]]; then return; fi

    pkill -9 -u "${uname}" 2>/dev/null || true
    userdel -f "${uname}" 2>/dev/null || true
    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo -e "${GREEN}SSH user '${uname}' deleted.${NC}"
}

update_ssh_ip_limit() {
    echo -e "\n${CYAN}--- Update SSH User IP Limit / Validity ---${NC}"
    read -rp "Enter SSH username: " uname
    if ! grep -q "^${uname}|" "${SSH_DB}"; then
        echo -e "${RED}User '${uname}' not found in SSH database.${NC}"
        return
    fi
    read -rp "New Max Concurrent IPs (e.g. 2): " max_ip
    read -rp "Extend validity by days from today (leave blank to keep current): " days

    local line pass cur_exp
    line=$(grep "^${uname}|" "${SSH_DB}" | head -n1)
    pass=$(echo "${line}" | cut -d'|' -f2)
    cur_exp=$(echo "${line}" | cut -d'|' -f3)

    if [[ -n "${days}" ]]; then
        cur_exp=$(date -d "+${days} days" +"%Y-%m-%d")
        chage -E "${cur_exp}" "${uname}" 2>/dev/null || true
    fi
    max_ip=${max_ip:-2}
    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo "${uname}|${pass}|${cur_exp}|${max_ip}" >> "${SSH_DB}"
    echo -e "${GREEN}Updated '${uname}': Expires=${cur_exp}, Max IP=${max_ip}.${NC}"
}

# -----------------------------------------------------------------------------
# Xray User Management (VLESS, VMess, Trojan - Port 443 & 80 WS & TCP)
# -----------------------------------------------------------------------------
create_xray_user() {
    echo -e "\n${CYAN}--- Create Xray User (VLESS / VMess / Trojan on Port 443 & 80 WS + TCP) ---${NC}"
    read -rp "Username: " uname
    if [[ -z "${uname}" ]]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        return
    fi
    if grep -q "^${uname}|" "${XRAY_DB}"; then
        echo -e "${RED}Xray user '${uname}' already exists!${NC}"
        return
    fi
    echo "Select Protocol:"
    echo "  1) VLESS (WS + TCP on 443 & 80)"
    echo "  2) VMess (WS + TCP on 443 & 80)"
    echo "  3) Trojan (WS + TCP on 443 & 80)"
    echo "  4) All Three (VLESS + VMess + Trojan)"
    read -rp "Choice [1-4]: " pchoice
    read -rp "Validity (days, e.g. 30): " days
    read -rp "Max Concurrent IPs (e.g. 2): " max_ip

    days=${days:-30}
    max_ip=${max_ip:-2}
    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
    uuid=$(cat /proc/sys/kernel/random/uuid)

    local proto="all"
    case "${pchoice}" in
        1) proto="vless" ;;
        2) proto="vmess" ;;
        3) proto="trojan" ;;
        *) proto="all" ;;
    esac

    if [[ -f "${XRAY_CONFIG}" ]]; then
        local tmp_json
        tmp_json=$(mktemp)
        cp "${XRAY_CONFIG}" "${tmp_json}"

        if [[ "${proto}" == "vless" || "${proto}" == "all" ]]; then
            jq --arg id "${uuid}" --arg email "${uname}@vless" \
               '(.inbounds[] | select(.tag=="vless-ws" or .tag=="vless-tcp") | .settings.clients) += [{"id": $id, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi
        if [[ "${proto}" == "vmess" || "${proto}" == "all" ]]; then
            jq --arg id "${uuid}" --arg email "${uname}@vmess" \
               '(.inbounds[] | select(.tag=="vmess-ws" or .tag=="vmess-tcp") | .settings.clients) += [{"id": $id, "alterId": 0, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi
        if [[ "${proto}" == "trojan" || "${proto}" == "all" ]]; then
            jq --arg pw "${uuid}" --arg email "${uname}@trojan" \
               '(.inbounds[] | select(.tag=="trojan-ws" or .tag=="trojan-tcp") | .settings.clients) += [{"password": $pw, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi

        mv "${tmp_json}" "${XRAY_CONFIG}"
        systemctl restart xray 2>/dev/null || true
    fi

    echo "${uname}|${proto}|${uuid}|${exp_date}|${max_ip}" >> "${XRAY_DB}"

    local host
    host=$(get_host)
    echo -e "\n${GREEN}=== Xray Account Created ===${NC}"
    echo -e "Username     : ${uname}"
    echo -e "Protocol(s)  : ${proto^^}"
    echo -e "UUID / Pass  : ${uuid}"
    echo -e "Host / SNI   : ${host}"
    echo -e "Expires On   : ${exp_date} (${days} days)"
    echo -e "Max IP Limit : ${max_ip} IP(s)"
    echo -e "Ports        : 443 (TLS) & 80 (Non-TLS) [WS & TCP]"

    if [[ "${proto}" == "vless" || "${proto}" == "all" ]]; then
        echo -e "\n${YELLOW}[VLESS Links]${NC}"
        echo "VLESS WS TLS (443)  : vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&path=%2Fvless&sni=${host}#${uname}-VLESS-WS-443"
        echo "VLESS WS HTTP (80)  : vless://${uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=%2Fvless#${uname}-VLESS-WS-80"
        echo "VLESS TCP TLS (443) : vless://${uuid}@${host}:443?encryption=none&security=tls&type=tcp&sni=${host}#${uname}-VLESS-TCP-443"
        echo "VLESS TCP HTTP (80) : vless://${uuid}@${host}:80?encryption=none&security=none&type=tcp#${uname}-VLESS-TCP-80"
    fi

    if [[ "${proto}" == "vmess" || "${proto}" == "all" ]]; then
        local vmess_ws_443 vmess_ws_80 vmess_tcp_443 vmess_tcp_80
        vmess_ws_443=$(jq -n --arg ps "${uname}-VMESS-WS-443" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"ws",type:"none",host:$add,path:"/vmess",tls:"tls",sni:$add}' | base64 -w0)
        vmess_ws_80=$(jq -n --arg ps "${uname}-VMESS-WS-80" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"80",id:$id,aid:"0",net:"ws",type:"none",host:$add,path:"/vmess",tls:"none"}' | base64 -w0)
        vmess_tcp_443=$(jq -n --arg ps "${uname}-VMESS-TCP-443" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"tcp",type:"none",host:$add,tls:"tls",sni:$add}' | base64 -w0)
        vmess_tcp_80=$(jq -n --arg ps "${uname}-VMESS-TCP-80" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"80",id:$id,aid:"0",net:"tcp",type:"none",host:$add,tls:"none"}' | base64 -w0)
        echo -e "\n${YELLOW}[VMess Links]${NC}"
        echo "VMess WS TLS (443)  : vmess://${vmess_ws_443}"
        echo "VMess WS HTTP (80)  : vmess://${vmess_ws_80}"
        echo "VMess TCP TLS (443) : vmess://${vmess_tcp_443}"
        echo "VMess TCP HTTP (80) : vmess://${vmess_tcp_80}"
    fi

    if [[ "${proto}" == "trojan" || "${proto}" == "all" ]]; then
        echo -e "\n${YELLOW}[Trojan Links]${NC}"
        echo "Trojan WS TLS (443)  : trojan://${uuid}@${host}:443?security=tls&type=ws&host=${host}&path=%2Ftrojan&sni=${host}#${uname}-TROJAN-WS-443"
        echo "Trojan WS HTTP (80)  : trojan://${uuid}@${host}:80?security=none&type=ws&host=${host}&path=%2Ftrojan#${uname}-TROJAN-WS-80"
        echo "Trojan TCP TLS (443) : trojan://${uuid}@${host}:443?security=tls&type=tcp&sni=${host}#${uname}-TROJAN-TCP-443"
        echo "Trojan TCP HTTP (80) : trojan://${uuid}@${host}:80?security=none&type=tcp#${uname}-TROJAN-TCP-80"
    fi
}

delete_xray_user() {
    echo -e "\n${CYAN}--- Delete Xray User ---${NC}"
    if [[ ! -s "${XRAY_DB}" ]]; then
        echo -e "${YELLOW}No Xray users found.${NC}"
        return
    fi
    nl -w2 -s'. ' "${XRAY_DB}" | awk -F'|' '{printf "%s %-16s [%-6s] (Expires: %s, Max IP: %s)\n", $1, $2, $3, $4, $5}'
    read -rp "Enter Xray username to delete: " uname
    if [[ -z "${uname}" ]]; then return; fi

    if [[ -f "${XRAY_CONFIG}" ]]; then
        local tmp_json
        tmp_json=$(mktemp)
        jq --arg u1 "${uname}@vless" --arg u2 "${uname}@vmess" --arg u3 "${uname}@trojan" \
           '(.inbounds[].settings.clients) |= map(select(.email != $u1 and .email != $u2 and .email != $u3))' \
           "${XRAY_CONFIG}" > "${tmp_json}" && mv "${tmp_json}" "${XRAY_CONFIG}"
        systemctl restart xray 2>/dev/null || true
    fi
    sed -i "/^${uname}|/d" "${XRAY_DB}"
    echo -e "${GREEN}Xray user '${uname}' deleted.${NC}"
}

update_xray_ip_limit() {
    echo -e "\n${CYAN}--- Update Xray User IP Limit / Validity ---${NC}"
    read -rp "Enter Xray username: " uname
    if ! grep -q "^${uname}|" "${XRAY_DB}"; then
        echo -e "${RED}User '${uname}' not found in Xray database.${NC}"
        return
    fi
    read -rp "New Max Concurrent IPs (e.g. 2): " max_ip
    read -rp "Extend validity by days from today (leave blank to keep current): " days

    local line proto secret cur_exp
    line=$(grep "^${uname}|" "${XRAY_DB}" | head -n1)
    proto=$(echo "${line}" | cut -d'|' -f2)
    secret=$(echo "${line}" | cut -d'|' -f3)
    cur_exp=$(echo "${line}" | cut -d'|' -f4)

    if [[ -n "${days}" ]]; then
        cur_exp=$(date -d "+${days} days" +"%Y-%m-%d")
    fi
    max_ip=${max_ip:-2}
    sed -i "/^${uname}|/d" "${XRAY_DB}"
    echo "${uname}|${proto}|${secret}|${cur_exp}|${max_ip}" >> "${XRAY_DB}"
    echo -e "${GREEN}Updated '${uname}': Expires=${cur_exp}, Max IP=${max_ip}.${NC}"
}

# -----------------------------------------------------------------------------
# Service Status & Port Mode / Deactivation Manager
# -----------------------------------------------------------------------------
service_and_port_menu() {
    while true; do
        echo -e "\n${CYAN}============================================================${NC}"
        echo -e "${CYAN}         Service Status & Port Deactivation Manager         ${NC}"
        echo -e "${CYAN}============================================================${NC}"
        echo -e "  OpenSSH (Port 22)          : $(svc_badge ssh)"
        echo -e "  Dropbear SSH (Port 109)    : $(svc_badge dropbear)"
        echo -e "  SSH-WS & Multiplexer (80/443): $(svc_badge ssh-ws)"
        echo -e "  Xray-core (VLESS/VMess/Trojan): $(svc_badge xray)"
        echo -e "  BadVPN UDPGW (Port 7300)   : $(svc_badge badvpn-udpgw)"
        echo -e "  Nginx (ACME / Web)         : $(svc_badge nginx)"
        echo -e "  IP & Conn Limiter Daemon   : $(svc_badge vps-limiter)"
        echo -e "------------------------------------------------------------"
        echo -e "  Port 80 Mode  : $(get_port_mode_label PORT_80_MODE)"
        echo -e "  Port 443 Mode : $(get_port_mode_label PORT_443_MODE)"
        echo -e "------------------------------------------------------------"
        echo "  1) Set Port 80 to SHARED Mode (SSH-WS + Xray WS/TCP)"
        echo "  2) Set Port 80 to SSH-WS EXCLUSIVE (Disable Xray on Port 80)"
        echo "  3) Set Port 80 to XRAY EXCLUSIVE (Disable SSH-WS on Port 80)"
        echo "  4) Set Port 443 to SHARED Mode (SSH-SSL/WS + Xray TLS WS/TCP)"
        echo "  5) Set Port 443 to SSH-SSL/WS EXCLUSIVE (Disable Xray on Port 443)"
        echo "  6) Set Port 443 to XRAY EXCLUSIVE (Disable SSH-SSL/WS on Port 443)"
        echo "  7) Stop / Disable an Individual Service (xray, ssh-ws, dropbear, badvpn-udpgw)"
        echo "  8) Start / Enable an Individual Service"
        echo "  0) Back to Main Menu"
        read -rp "Select option: " sopt

        local p80 p443
        p80=$(grep -E "^PORT_80_MODE=" "${PORT_MODE_FILE}" 2>/dev/null | cut -d'=' -f2 || echo "shared")
        p443=$(grep -E "^PORT_443_MODE=" "${PORT_MODE_FILE}" 2>/dev/null | cut -d'=' -f2 || echo "shared")

        case "${sopt}" in
            1) p80="shared" ;;
            2) p80="ssh_only" ;;
            3) p80="xray_only" ;;
            4) p443="shared" ;;
            5) p443="ssh_only" ;;
            6) p443="xray_only" ;;
            7)
                read -rp "Enter service name to stop/disable (xray / ssh-ws / dropbear / badvpn-udpgw / vps-limiter): " tsvc
                systemctl stop "${tsvc}" 2>/dev/null && systemctl disable "${tsvc}" 2>/dev/null
                echo -e "${YELLOW}Service '${tsvc}' stopped and disabled.${NC}"
                continue
                ;;
            8)
                read -rp "Enter service name to start/enable (xray / ssh-ws / dropbear / badvpn-udpgw / vps-limiter): " tsvc
                systemctl enable "${tsvc}" 2>/dev/null && systemctl restart "${tsvc}" 2>/dev/null
                echo -e "${GREEN}Service '${tsvc}' enabled and started.${NC}"
                continue
                ;;
            0) break ;;
            *) continue ;;
        esac

        cat > "${PORT_MODE_FILE}" <<EOF
PORT_80_MODE=${p80}
PORT_443_MODE=${p443}
EOF
        systemctl restart ssh-ws 2>/dev/null || true
        echo -e "${GREEN}Port routing mode updated and applied cleanly!${NC}"
    done
}

# -----------------------------------------------------------------------------
# SSL Certificate Manager (Domain Let's Encrypt OR IP Self-Signed)
# -----------------------------------------------------------------------------
ssl_menu() {
    echo -e "\n${CYAN}--- SSL Certificate Setup (Domain Let's Encrypt or IP Self-Signed) ---${NC}"
    echo "  1) Issue Free Let's Encrypt Certificate for a Domain (via acme.sh)"
    echo "  2) Generate Self-Signed Certificate for VPS IP (No Domain Needed)"
    echo "  0) Back"
    read -rp "Select option: " copt
    mkdir -p "${CONFIG_DIR}/ssl"
    case "${copt}" in
        1)
            read -rp "Enter your domain name (pointing to this VPS IP): " dom
            if [[ -z "${dom}" ]]; then return; fi
            echo "${dom}" > "${DOMAIN_FILE}"
            systemctl start nginx 2>/dev/null || true
            if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
                curl -fsSL https://get.acme.sh | sh -s email="admin@${dom}"
            fi
            "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
            "$HOME/.acme.sh/acme.sh" --issue -d "${dom}" --webroot /var/www/html --keylength ec-256 --force
            "$HOME/.acme.sh/acme.sh" --install-cert -d "${dom}" --ecc \
                --fullchain-file "${CERT_FILE}" \
                --key-file "${KEY_FILE}"
            chmod 600 "${KEY_FILE}"
            systemctl restart ssh-ws xray 2>/dev/null || true
            echo -e "${GREEN}Let's Encrypt SSL certificate installed for ${dom}!${NC}"
            ;;
        2)
            local vip
            vip=$(curl -fsSL4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
            rm -f "${DOMAIN_FILE}"
            openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${vip}" \
                -addext "subjectAltName=IP:${vip}" 2>/dev/null || \
            openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${vip}"
            chmod 600 "${KEY_FILE}"
            systemctl restart ssh-ws xray 2>/dev/null || true
            echo -e "${GREEN}Self-signed IP certificate generated for ${vip} (TLS 1.0-1.3 supported)!${NC}"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Main Interactive CLI Loop
# -----------------------------------------------------------------------------
main_menu() {
    while true; do
        local host os_name
        host=$(get_host)
        os_name=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)

        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "${CYAN}         DEBIAN / UBUNTU VPS MANAGEMENT PANEL (CLI)         ${NC}"
        echo -e "${BLUE}============================================================${NC}"
        echo -e "  OS           : ${os_name}"
        echo -e "  Host / IP    : ${host}"
        echo -e "  SSH-WS (80)  : $(svc_badge ssh-ws)   | Xray-core : $(svc_badge xray)"
        echo -e "  Dropbear     : $(svc_badge dropbear)   | BadVPN 7300: $(svc_badge badvpn-udpgw)"
        echo -e "  IP Limiter   : $(svc_badge vps-limiter)   | OpenSSH   : $(svc_badge ssh)"
        echo -e "  Port 80 Mode : $(get_port_mode_label PORT_80_MODE)"
        echo -e "  Port 443 Mode: $(get_port_mode_label PORT_443_MODE)"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        echo "  [SSH / SSH-WS / SSL-WS Management]"
        echo "    1) Create SSH / WS / SSL User (Custom Payload 80 & SSL 443)"
        echo "    2) Delete SSH User"
        echo "    3) Update SSH User IP Limit / Validity"
        echo ""
        echo "  [Xray Management (VLESS, VMess, Trojan - 443 & 80 WS/TCP)]"
        echo "    4) Create Xray User (VLESS / VMess / Trojan)"
        echo "    5) Delete Xray User"
        echo "    6) Update Xray User IP Limit / Validity"
        echo ""
        echo "  [Monitoring, Port Modes & SSL]"
        echo "    7) Show Active Connections & Per-User IP Usage"
        echo "    8) Service Status & Port 80/443 Conflict Manager"
        echo "    9) SSL Certificate Manager (Domain Let's Encrypt / IP Self-Signed)"
        echo "   10) Run Expired Account Cleanup Now"
        echo "    0) Exit"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        read -rp "Select an option [0-10]: " opt

        case "${opt}" in
            1) create_ssh_user ;;
            2) delete_ssh_user ;;
            3) update_ssh_ip_limit ;;
            4) create_xray_user ;;
            5) delete_xray_user ;;
            6) update_xray_ip_limit ;;
            7) python3 /usr/local/share/vps-panel/limiter.py --status ;;
            8) service_and_port_menu ;;
            9) ssl_menu ;;
            10) /usr/local/bin/xp-vps && echo -e "${GREEN}Expired users cleaned up.${NC}" ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid selection.${NC}" ;;
        esac
    done
}

main_menu
EOF_MENU

chmod +x "${SHARE_DIR}/ssh-ws.py" "${SHARE_DIR}/limiter.py" /usr/local/bin/menu

# Initialize default port mode config (Option 2: Shared Multiplex Mode on 80 & 443)
if [[ ! -f "${CONFIG_DIR}/port_mode.conf" ]]; then
    cat > "${CONFIG_DIR}/port_mode.conf" <<'EOF'
PORT_80_MODE=shared
PORT_443_MODE=shared
EOF
fi
touch "${CONFIG_DIR}/ssh-users.db" "${CONFIG_DIR}/xray-users.db"

# Create Daily Cron Job for Expired SSH & Xray User Deletion (/usr/local/bin/xp-vps)
cat > /usr/local/bin/xp-vps <<'EOF'
#!/usr/bin/env bash
set -u
TODAY=$(date +"%Y-%m-%d")
SSH_DB="/etc/vps-panel/ssh-users.db"
XRAY_DB="/etc/vps-panel/xray-users.db"
XRAY_CONFIG="/usr/local/etc/xray/config.json"

if [[ -s "${SSH_DB}" ]]; then
    while IFS='|' read -r uname pass exp max_ip; do
        [[ -z "${uname}" || "${uname}" =~ ^# ]] && continue
        if [[ "${exp}" < "${TODAY}" ]]; then
            pkill -9 -u "${uname}" 2>/dev/null || true
            userdel -f "${uname}" 2>/dev/null || true
            sed -i "/^${uname}|/d" "${SSH_DB}"
        fi
    done < "${SSH_DB}"
fi

if [[ -s "${XRAY_DB}" ]]; then
    CHANGED=0
    while IFS='|' read -r uname proto secret exp max_ip; do
        [[ -z "${uname}" || "${uname}" =~ ^# ]] && continue
        if [[ "${exp}" < "${TODAY}" ]]; then
            if [[ -f "${XRAY_CONFIG}" ]]; then
                tmp_json=$(mktemp)
                jq --arg u1 "${uname}@vless" --arg u2 "${uname}@vmess" --arg u3 "${uname}@trojan" \
                   '(.inbounds[].settings.clients) |= map(select(.email != $u1 and .email != $u2 and .email != $u3))' \
                   "${XRAY_CONFIG}" > "${tmp_json}" && mv "${tmp_json}" "${XRAY_CONFIG}"
                CHANGED=1
            fi
            sed -i "/^${uname}|/d" "${XRAY_DB}"
        fi
    done < "${XRAY_DB}"
    [[ "${CHANGED}" -eq 1 ]] && systemctl restart xray 2>/dev/null || true
fi
EOF
chmod +x /usr/local/bin/xp-vps

cat > /etc/cron.d/vps-panel-xp <<'EOF'
0 0 * * * root /usr/local/bin/xp-vps >/dev/null 2>&1
EOF

# Create systemd services for ssh-ws and vps-limiter
cat > /etc/systemd/system/ssh-ws.service <<'EOF'
[Unit]
Description=VPS Panel Port 80 & 443 SSH-WS & Xray Multiplexer (TLS 1.0-1.3)
After=network.target dropbear.service xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/share/vps-panel/ssh-ws.py
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vps-limiter.service <<'EOF'
[Unit]
Description=VPS Panel Per-User Connection & IP Limit Enforcer
After=network.target ssh-ws.service xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/share/vps-panel/limiter.py --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# -----------------------------------------------------------------------------
# SSL Certificate Setup (Domain via acme.sh OR IP-only Self-Signed)
# -----------------------------------------------------------------------------
echo "[7/8] Configuring SSL Certificate (Supports Domain Let's Encrypt or IP Self-Signed)..."
VPS_IP=$(curl -fsSL4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
CERT_FILE="${CONFIG_DIR}/ssl/fullchain.pem"
KEY_FILE="${CONFIG_DIR}/ssl/privkey.pem"

if [[ -t 0 ]]; then
    echo ""
    echo "Select SSL Certificate Mode for Port 443:"
    echo "  1) Domain Mode (Free Let's Encrypt certificate via acme.sh)"
    echo "  2) IP-Only Mode (Self-signed certificate for ${VPS_IP})"
    read -rp "Choice [1-2, default 2]: " ssl_choice
else
    ssl_choice="2"
fi

if [[ "${ssl_choice}" == "1" ]]; then
    read -rp "Enter your domain name (must point to ${VPS_IP}): " USER_DOMAIN
    echo "${USER_DOMAIN}" > "${CONFIG_DIR}/domain"
    # Generate fallback self-signed cert first so port 80/443 starts cleanly
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
        -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${USER_DOMAIN}" 2>/dev/null
    systemctl daemon-reload
    systemctl enable ssh-ws vps-limiter
    systemctl restart ssh-ws vps-limiter
    curl -fsSL https://get.acme.sh | sh -s email="admin@${USER_DOMAIN}"
    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
    "$HOME/.acme.sh/acme.sh" --issue -d "${USER_DOMAIN}" --webroot /var/www/html --keylength ec-256 --force || true
    "$HOME/.acme.sh/acme.sh" --install-cert -d "${USER_DOMAIN}" --ecc \
        --fullchain-file "${CERT_FILE}" \
        --key-file "${KEY_FILE}" || true
else
    rm -f "${CONFIG_DIR}/domain"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
        -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${VPS_IP}" \
        -addext "subjectAltName=IP:${VPS_IP}" 2>/dev/null || \
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
        -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${VPS_IP}"
fi
chmod 600 "${KEY_FILE}"

echo "[8/8] Starting all panel services..."
systemctl daemon-reload
systemctl enable ssh-ws vps-limiter
systemctl restart ssh-ws vps-limiter xray badvpn-udpgw dropbear

echo ""
echo "============================================================"
echo " VPS Management Panel Installed Successfully!"
echo " Run 'menu' from your terminal at any time to manage users."
echo "============================================================"