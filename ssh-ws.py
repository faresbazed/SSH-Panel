#!/usr/bin/env python3
"""SSH/Xray WebSocket frontend for ports 80 and 443."""

import asyncio
import base64
import functools
import hashlib
import logging
import ssl
import struct
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path("/etc/ssh-panel")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

XRAY_PATHS = {
    "/vless": 10001,
    "/vmess": 10002,
    "/trojan": 10003,
}
SSH_PATHS = {"/", "/ssh", "/ssh-ws", "/ws"}

HTTP_METHODS = (
    b"GET ", b"POST ", b"CONNECT ", b"HEAD ",
    b"OPTIONS ", b"PUT ", b"PATCH ",
)
MAX_HEADER = 65536
MAX_MESSAGE = 1048576


def read_modes():
    values = {
        "PORT_80_MODE": "multiplex",
        "PORT_443_MODE": "multiplex",
    }
    config = ROOT / "ports.conf"
    if config.exists():
        for line in config.read_text().splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            if key.strip() in values:
                values[key.strip()] = value.strip()

    allowed = {
        "multiplex", "disabled",
        "ssh", "ssh-only", "xray", "xray-only",
    }
    for key, value in values.items():
        if value not in allowed:
            raise ValueError("Invalid {}: {}".format(key, value))
    if all(value == "disabled" for value in values.values()):
        raise ValueError("Both frontend ports are disabled")
    return values


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        str(ROOT / "cert.pem"),
        str(ROOT / "key.pem"),
    )
    return context


async def close_writer(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except Exception:
        pass


async def pump(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            return
        writer.write(data)
        await writer.drain()


async def relay(first, second):
    tasks = [
        asyncio.create_task(first),
        asyncio.create_task(second),
    ]
    try:
        done, _ = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            task.result()
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def open_ssh():
    for port in (109, 22):
        try:
            return await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), 5
            )
        except (OSError, asyncio.TimeoutError):
            continue
    raise ConnectionError("SSH backend unavailable on 109 and 22")


async def http_reply(writer, status, message):
    body = message.encode()
    writer.write(
        (
            "HTTP/1.1 {}\r\n"
            "Connection: close\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: {}\r\n\r\n"
        ).format(status, len(body)).encode() + body
    )
    await writer.drain()


def websocket_frame(opcode, payload=b""):
    length = len(payload)
    if length < 126:
        header = bytes((0x80 | opcode, length))
    elif length <= 65535:
        header = bytes((0x80 | opcode, 126))
        header += struct.pack("!H", length)
    else:
        header = bytes((0x80 | opcode, 127))
        header += struct.pack("!Q", length)
    return header + payload


class BufferedReader:
    def __init__(self, reader, initial=b""):
        self.reader = reader
        self.buffer = bytearray(initial)

    async def exact(self, length):
        data = bytes(self.buffer[:length])
        del self.buffer[:length]
        if len(data) < length:
            data += await self.reader.readexactly(length - len(data))
        return data


async def websocket_to_ssh(reader, backend_writer, client_writer):
    fragmented = False
    message_size = 0

    while True:
        first, second = await reader.exact(2)
        final = bool(first & 0x80)
        opcode = first & 0x0F

        if first & 0x70:
            raise ValueError("WebSocket extensions were not negotiated")
        if not second & 0x80:
            raise ValueError("Client WebSocket frames must be masked")

        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", await reader.exact(2))[0]
            if length < 126:
                raise ValueError("Non-canonical WebSocket length")
        elif length == 127:
            length = struct.unpack("!Q", await reader.exact(8))[0]
            if length <= 65535 or length >> 63:
                raise ValueError("Invalid WebSocket length")

        if length > MAX_MESSAGE:
            raise ValueError("WebSocket frame too large")
        if opcode >= 8 and (not final or length > 125):
            raise ValueError("Invalid WebSocket control frame")

        mask = await reader.exact(4)
        payload = await reader.exact(length)
        payload = bytes(
            byte ^ mask[index % 4]
            for index, byte in enumerate(payload)
        )

        if opcode == 8:
            client_writer.write(websocket_frame(8))
            await client_writer.drain()
            return

        if opcode == 9:
            client_writer.write(websocket_frame(10, payload))
            await client_writer.drain()
            continue

        if opcode == 10:
            continue

        if opcode == 2:
            if fragmented:
                raise ValueError("Unexpected new WebSocket message")
            message_size = length
            fragmented = not final
        elif opcode == 0:
            if not fragmented:
                raise ValueError("Unexpected continuation frame")
            message_size += length
            fragmented = not final
        elif opcode == 1:
            raise ValueError("SSH requires binary WebSocket frames")
        else:
            raise ValueError("Unsupported WebSocket opcode")

        if message_size > MAX_MESSAGE:
            raise ValueError("WebSocket message too large")

        if payload:
            backend_writer.write(payload)
            await backend_writer.drain()

        if final:
            message_size = 0


async def ssh_to_websocket(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data:
            return
        writer.write(websocket_frame(2, data))
        await writer.drain()


async def read_http(reader, initial):
    data = initial
    while b"\r\n\r\n" not in data:
        if len(data) >= MAX_HEADER:
            raise ValueError("HTTP headers too large")
        part = await reader.read(4096)
        if not part:
            raise ValueError("Incomplete HTTP request")
        data += part

    header, remainder = data.split(b"\r\n\r\n", 1)
    if len(header) > MAX_HEADER:
        raise ValueError("HTTP headers too large")

    return header + b"\r\n\r\n", remainder


async def handle_client(reader, writer, mode):
    backend_writer = None
    peer = writer.get_extra_info("peername")
    ssh_allowed = mode not in ("xray", "xray-only")
    xray_allowed = mode not in ("ssh", "ssh-only")

    try:
        # Allow server-first plain SSH/SSH-over-TLS clients.
        try:
            initial = await asyncio.wait_for(reader.read(8192), 5)
            if not initial:
                return
        except asyncio.TimeoutError:
            if not ssh_allowed:
                return
            backend_reader, backend_writer = await open_ssh()
            await relay(
                pump(reader, backend_writer),
                pump(backend_reader, writer),
            )
            return

        possible_http = any(
            initial.startswith(method) or method.startswith(initial)
            for method in HTTP_METHODS
        )

        if not possible_http:
            if not ssh_allowed:
                return
            if not (
                initial.startswith(b"SSH-")
                or b"SSH-".startswith(initial)
            ):
                return

            backend_reader, backend_writer = await open_ssh()
            backend_writer.write(initial)
            await backend_writer.drain()
            await relay(
                pump(reader, backend_writer),
                pump(backend_reader, writer),
            )
            return

        header, remainder = await asyncio.wait_for(
            read_http(reader, initial), 15
        )

        lines = header.decode("latin-1").split("\r\n")
        request = lines[0].split()
        if len(request) != 3:
            raise ValueError("Invalid HTTP request")

        method, target, version = request
        if version not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("Unsupported HTTP version")

        parsed = urlsplit(target)
        path = parsed.path or "/"

        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise ValueError("Malformed HTTP header")
            key, value = line.split(":", 1)
            key = key.strip().lower()
            if key in headers and key in (
                "sec-websocket-key", "sec-websocket-version",
                "content-length", "host",
            ):
                raise ValueError("Duplicate sensitive HTTP header")
            headers[key] = (
                headers.get(key, "")
                + ("," if key in headers else "")
                + value.strip()
            )

        if path == "/healthz":
            await http_reply(
                writer, "200 OK", "ssh-panel frontend ready\n"
            )
            return

        # Accept old aliases but forward the canonical Xray path.
        for base in XRAY_PATHS:
            if path == base + "-ws":
                path = base
                break

        if path in XRAY_PATHS:
            if not xray_allowed:
                await http_reply(
                    writer, "403 Forbidden", "Xray disabled\n"
                )
                return

            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    "127.0.0.1", XRAY_PATHS[path]
                ), 5
            )
            query = "?" + parsed.query if parsed.query else ""
            first_line = "{} {}{} {}".format(
                method, path, query, version
            ).encode()
            forwarded = (
                first_line + b"\r\n"
                + header.split(b"\r\n", 1)[1]
            )

            backend_writer.write(forwarded + remainder)
            await backend_writer.drain()

            # Xray handles its own WS framing.
            await relay(
                pump(reader, backend_writer),
                pump(backend_reader, writer),
            )
            return

        if path not in SSH_PATHS:
            await http_reply(
                writer, "404 Not Found", "Unknown endpoint\n"
            )
            return

        if not ssh_allowed:
            await http_reply(
                writer, "403 Forbidden", "SSH disabled\n"
            )
            return

        key = headers.get("sec-websocket-key")
        if key:
            connection_tokens = [
                item.strip().lower()
                for item in headers.get(
                    "connection", ""
                ).split(",")
            ]
            if (
                method != "GET"
                or headers.get("upgrade", "").lower() != "websocket"
                or "upgrade" not in connection_tokens
                or headers.get("sec-websocket-version") != "13"
            ):
                await http_reply(
                    writer, "400 Bad Request",
                    "Invalid WebSocket handshake\n",
                )
                return

            try:
                decoded_key = base64.b64decode(key, validate=True)
            except Exception as error:
                raise ValueError("Invalid WebSocket key") from error

            if len(decoded_key) != 16:
                raise ValueError("Invalid WebSocket key length")

        backend_reader, backend_writer = await open_ssh()

        if key:
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()
            ).decode()

            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Accept: {}\r\n"
            ).format(accept)

            offered = [
                item.strip()
                for item in headers.get(
                    "sec-websocket-protocol", ""
                ).split(",")
            ]
            if "binary" in offered:
                response += "Sec-WebSocket-Protocol: binary\r\n"

            writer.write((response + "\r\n").encode())
            await writer.drain()

            await relay(
                websocket_to_ssh(
                    BufferedReader(reader, remainder),
                    backend_writer,
                    writer,
                ),
                ssh_to_websocket(backend_reader, writer),
            )
        else:
            # Legacy injector mode: HTTP upgrade then unframed SSH.
            # This mode is not a genuine RFC6455 WebSocket.
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n\r\n"
            )
            await writer.drain()

            if remainder:
                backend_writer.write(remainder)
                await backend_writer.drain()

            await relay(
                pump(reader, backend_writer),
                pump(backend_reader, writer),
            )

    except (
        asyncio.IncompleteReadError,
        ConnectionError,
        BrokenPipeError,
    ):
        pass
    except Exception as error:
        logging.warning("Client %s: %s", peer, error)
    finally:
        await close_writer(backend_writer)
        await close_writer(writer)


async def main():
    modes = read_modes()
    servers = []

    try:
        for port in (80, 443):
            mode = modes["PORT_{}_MODE".format(port)]
            if mode == "disabled":
                continue

            options = {}
            if port == 443:
                options["ssl"] = tls_context()
                options["ssl_handshake_timeout"] = 15

            server = await asyncio.start_server(
                functools.partial(handle_client, mode=mode),
                host="0.0.0.0",
                port=port,
                limit=MAX_HEADER,
                **options
            )
            servers.append(server)
            logging.info("Listening on IPv4 :%s (%s)", port, mode)

        await asyncio.gather(
            *(server.serve_forever() for server in servers)
        )
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(
            *(server.wait_closed() for server in servers)
        )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if "--check" in sys.argv:
        settings = read_modes()
        if settings["PORT_443_MODE"] != "disabled":
            tls_context()
        print("Frontend settings and certificate load successfully.")
    else:
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            pass
