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