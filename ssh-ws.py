#!/usr/bin/env python3
"""
VPS Panel - High-Speed Port 80 & 443 Multiplexer & Custom-Payload / Custom-SNI Proxy
Supports:
  - SSH over WebSocket (Port 80 & 443) with ANY custom HTTP payload (GET, CONNECT, split payloads, bug hosts)
  - Direct SSL/SSH (Stunnel-style SSH-2.0 handshake on Port 443/80 with fast banner handoff)
  - Any Custom SNI / Bug Host on Port 443 (wildcard SNI callback accepting any spoofed hostname)
  - Xray WebSocket (/vless, /vmess, /trojan) on Port 80 & 443 with X-Forwarded-For injection
  - Xray TCP (VLESS TCP, VMess TCP, Trojan TCP) on Port 80 & 443
  - ACME HTTP-01 challenge forwarding (/.well-known/acme-challenge/) to Nginx (127.0.0.1:8080)
  - High-speed TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3 support on Port 443 (AEAD prioritized + @SECLEVEL=0)
  - TCP_NODELAY and 64KB zero-lag streaming buffers for low-latency SSL tunneling
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

BUFFER_SIZE = 65536
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
_cached_ssh_port: int = 0
_cached_ssh_ts: float = 0.0


def set_fast_socket_opts(writer: asyncio.StreamWriter) -> None:
    """Enables TCP_NODELAY and SO_KEEPALIVE to eliminate SSL/TCP packet latency."""
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass


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
    """Prefer Dropbear on port 109 if listening, otherwise fallback to OpenSSH on port 22 (cached 5s)."""
    global _cached_ssh_port, _cached_ssh_ts
    now = time.time()
    if _cached_ssh_port and (now - _cached_ssh_ts) < 5.0:
        return _cached_ssh_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.05)
        if s.connect_ex((SSH_BACKEND_HOST, DROPBEAR_PORT)) == 0:
            _cached_ssh_port = DROPBEAR_PORT
        else:
            _cached_ssh_port = OPENSSH_PORT
    _cached_ssh_ts = now
    return _cached_ssh_port


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


def normalize_ws_upgrade_for_xray(data: bytes, client_ip: str, path: str) -> bytes:
    """
    Ensures Xray WebSocket inbounds receive a clean Host header and X-Forwarded-For
    even when the client uses a custom SNI / spoofed bug Host header.
    """
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
    # If client connected over SSL (Port 443) and sent nothing immediately, it is waiting
    # for the SSH server banner (Direct SSL/TLS -> SSH Stunnel mode)
    if not initial_data:
        if mode == "xray_only":
            return ("reject", 0, False)
        return ("ssh", get_ssh_backend_port(), False)

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
    if not is_http and (b"HTTP/" in initial_data[:256] or b"Upgrade: websocket" in initial_data[:512]):
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


async def pipe_client_to_ssh(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    seen_ssh_banner: bool,
) -> None:
    """
    Pipes client -> SSH backend, stripping any secondary split-payload HTTP lines
    until the client's `SSH-2.0-` banner begins.
    """
    banner_found = seen_ssh_banner
    try:
        while True:
            chunk = await reader.read(BUFFER_SIZE)
            if not chunk:
                break
            if not banner_found:
                idx = chunk.find(b"SSH-2.0-")
                if idx != -1:
                    banner_found = True
                    chunk = chunk[idx:]
                elif any(chunk.upper().startswith(m) for m in HTTP_METHODS):
                    # Secondary split HTTP payload chunk from injector; reply 101 or drop chunk
                    continue
                else:
                    banner_found = True
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def pipe_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(BUFFER_SIZE)
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
    set_fast_socket_opts(client_writer)
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

    # On Port 443 (SSL), use a short 0.8s initial read timeout so Direct SSL/SSH clients
    # that wait for the server's SSH-2.0 banner get connected immediately without lag.
    read_timeout = 0.8 if listen_port == 443 else 8.0
    initial_data = b""
    try:
        initial_data = await asyncio.wait_for(client_reader.read(BUFFER_SIZE), timeout=read_timeout)
        if not initial_data:
            # EOF (client closed connection)
            client_writer.close()
            return
    except asyncio.TimeoutError:
        if listen_port != 443 or mode == "xray_only":
            client_writer.close()
            return
        # Timeout on 443 in shared/ssh_only mode -> treat as Direct SSL-SSH client waiting for server banner
        initial_data = b""
    except Exception:
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
            asyncio.open_connection(SSH_BACKEND_HOST, target_port), timeout=4.0
        )
        set_fast_socket_opts(backend_writer)
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
            seen_banner = False
            ssh_idx = initial_data.find(b"SSH-2.0-")
            if ssh_idx != -1:
                seen_banner = True
                backend_writer.write(initial_data[ssh_idx:])
                await backend_writer.drain()
            await asyncio.gather(
                pipe_client_to_ssh(client_reader, backend_writer, seen_banner),
                pipe_stream(backend_reader, client_writer),
            )
        elif target_type == "xray_ws":
            path = extract_http_path(initial_data)
            forwarded_payload = normalize_ws_upgrade_for_xray(initial_data, client_ip, path)
            backend_writer.write(forwarded_payload)
            await backend_writer.drain()
            await asyncio.gather(
                pipe_stream(client_reader, backend_writer),
                pipe_stream(backend_reader, client_writer),
            )
        else:
            # xray_tcp or acme
            if initial_data:
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
    Creates a high-speed OpenSSL context supporting:
      - ALL TLS versions (TLS 1.0, 1.1, 1.2, 1.3)
      - Hardware-accelerated AEAD ciphers (AES-GCM & ChaCha20-Poly1305) prioritized first,
        with @SECLEVEL=0 fallback for legacy TLS 1.0/1.1 clients
      - Arbitrary Custom SNI / Bug Hostnames (sni_callback accepts any SNI without error)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fast_ciphers = (
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE+AES:RSA+AES:ALL:@SECLEVEL=0"
    )
    try:
        ctx.set_ciphers(fast_ciphers)
    except ssl.SSLError:
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

    # Accept ANY custom SNI / Bug Host sent in ClientHello
    def _accept_any_sni(ssl_sock, server_name, ssl_context):
        return None

    try:
        ctx.sni_callback = _accept_any_sni
    except Exception:
        pass

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
            backlog=1024,
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
                backlog=1024,
            )
            servers.append(srv443)
            logger.info(
                "Listening on 0.0.0.0:443 SSL/TLS [TLS 1.0-1.3 + Custom SNI enabled] (mode=%s)",
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