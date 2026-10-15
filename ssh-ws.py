#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import os
import socket
import ssl

PANEL_DIR = "/etc/ssh-panel"
CERT_FILE = os.path.join(PANEL_DIR, "cert.pem")
KEY_FILE = os.path.join(PANEL_DIR, "key.pem")
PORTS_CONF = os.path.join(PANEL_DIR, "ports.conf")

DROPBEAR_HOST = "127.0.0.1"
DROPBEAR_PORT = 109
OPENSSH_PORT = 22

XRAY_PORTS = {
    "vless_ws": 10001,
    "vmess_ws": 10002,
    "trojan_ws": 10003,
    "vless_tcp": 10004,
    "vmess_tcp": 10005,
    "trojan_tcp": 10006,
}

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTTP_METHODS = (b"GET ", b"POST ", b"CONNECT ", b"HEAD ", b"PUT ", b"OPTIONS ", b"PATCH ")


def set_nodelay(sock):
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def build_ws_upgrade_response(header_bytes):
    """Returns 101 Switching Protocols with RFC6455 Sec-WebSocket-Accept if requested (needed by cloudflared)."""
    ws_key = None
    try:
        lines = header_bytes.decode("latin-1", errors="ignore").split("\r\n")
        for line in lines:
            if line.lower().startswith("sec-websocket-key:"):
                ws_key = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass

    if ws_key:
        accept = base64.b64encode(
            hashlib.sha1((ws_key + WS_GUID).encode("utf-8")).digest()
        ).decode("utf-8")
        return (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("utf-8")

    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n\r\n"
    )


async def pipe_stream(reader, writer):
    try:
        while True:
            chunk = await reader.read(32768)
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


async def connect_ssh_backend():
    for port in (DROPBEAR_PORT, OPENSSH_PORT):
        try:
            return await asyncio.open_connection(DROPBEAR_HOST, port)
        except Exception:
            continue
    raise ConnectionError("Neither Dropbear nor OpenSSH is reachable")


async def handle_multiplexed_client(reader, writer):
    sock = writer.get_extra_info("socket")
    if sock:
        set_nodelay(sock)

    try:
        first_data = await asyncio.wait_for(reader.read(8192), timeout=15.0)
    except Exception:
        writer.close()
        return

    if not first_data:
        writer.close()
        return

    target_reader = None
    target_writer = None

    try:
        # 1. Direct SSH-2.0 Handshake
        if first_data.startswith(b"SSH-2.0-"):
            target_reader, target_writer = await connect_ssh_backend()
            target_writer.write(first_data)
            await target_writer.drain()

        # 2. HTTP / WebSocket Requests (Xray WS or SSH-WS Payload / Cloudflared)
        elif first_data.startswith(HTTP_METHODS):
            first_line = first_data.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
            parts = first_line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"

            if path.startswith("/vless"):
                normalized = first_data.replace(b"GET /vless-ws ", b"GET /vless ", 1)
                target_reader, target_writer = await asyncio.open_connection("127.0.0.1", XRAY_PORTS["vless_ws"])
                target_writer.write(normalized)
                await target_writer.drain()

            elif path.startswith("/vmess"):
                normalized = first_data.replace(b"GET /vmess-ws ", b"GET /vmess ", 1)
                target_reader, target_writer = await asyncio.open_connection("127.0.0.1", XRAY_PORTS["vmess_ws"])
                target_writer.write(normalized)
                await target_writer.drain()

            elif path.startswith("/trojan"):
                normalized = first_data.replace(b"GET /trojan-ws ", b"GET /trojan ", 1)
                target_reader, target_writer = await asyncio.open_connection("127.0.0.1", XRAY_PORTS["trojan_ws"])
                target_writer.write(normalized)
                await target_writer.drain()

            else:
                # SSH-WS Custom Payload or Cloudflared SSH-WS Upgrade
                target_reader, target_writer = await connect_ssh_backend()
                writer.write(build_ws_upgrade_response(first_data))
                await writer.drain()

                if b"\r\n\r\n" in first_data:
                    remainder = first_data.split(b"\r\n\r\n", 1)[1]
                    if remainder:
                        target_writer.write(remainder)
                        await target_writer.drain()

        # 3. Binary Xray TCP Streams (Trojan TCP / VLESS TCP / VMess TCP)
        else:
            if len(first_data) >= 58 and first_data[56:58] == b"\r\n":
                xray_port = XRAY_PORTS["trojan_tcp"]
            elif first_data[0] == 0:
                xray_port = XRAY_PORTS["vless_tcp"]
            else:
                xray_port = XRAY_PORTS["vmess_tcp"]

            target_reader, target_writer = await asyncio.open_connection("127.0.0.1", xray_port)
            target_writer.write(first_data)
            await target_writer.drain()

        tsock = target_writer.get_extra_info("socket")
        if tsock:
            set_nodelay(tsock)

        await asyncio.gather(
            pipe_stream(reader, target_writer),
            pipe_stream(target_reader, writer),
        )
    except Exception:
        try:
            writer.close()
        except Exception:
            pass


def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    # Accept any spoofed SNI / Bug Host from client
    def sni_callback(ssl_sock, server_name, ssl_context):
        return None

    ctx.sni_callback = sni_callback
    return ctx


def load_port_modes():
    modes = {"PORT_80_MODE": "multiplex", "PORT_443_MODE": "multiplex"}
    if os.path.exists(PORTS_CONF):
        with open(PORTS_CONF, "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    modes[k.strip()] = v.strip()
    return modes


async def main():
    modes = load_port_modes()
    servers = []

    if modes.get("PORT_80_MODE", "multiplex") != "disabled":
        srv80 = await asyncio.start_server(
            handle_multiplexed_client, "0.0.0.0", 80, reuse_address=True
        )
        servers.append(srv80)

    if modes.get("PORT_443_MODE", "multiplex") != "disabled":
        ssl_ctx = create_ssl_context()
        srv443 = await asyncio.start_server(
            handle_multiplexed_client, "0.0.0.0", 443, ssl=ssl_ctx, reuse_address=True
        )
        servers.append(srv443)

    if not servers:
        while True:
            await asyncio.sleep(3600)

    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
