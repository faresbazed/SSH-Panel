#!/usr/bin/env python3
"""Account expiry, Xray account management and WS URI generation.

Legacy LIMIT metadata is preserved, but true IP limits are not enforced.
"""

import argparse
import base64
import contextlib
import datetime
import fcntl
import ipaddress
import json
import logging
import os
import pwd
import re
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode

ROOT = Path("/etc/ssh-panel")
USERS = ROOT / "users"
XUSERS = ROOT / "xray_users"
CONFIG = Path("/usr/local/etc/xray/config.json")
XRAY = "/usr/local/bin/xray"
LOCK = "/run/lock/ssh-panel-state.lock"

PROTOCOLS = ("vless", "vmess", "trojan")
PORTS = {"vless": 10001, "vmess": 10002, "trojan": 10003}
NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def valid_name(name):
    if not NAME.fullmatch(name):
        raise ValueError("Invalid username")
    return name


@contextlib.contextmanager
def locked():
    with open(LOCK, "a") as stream:
        os.chmod(LOCK, 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def metadata(path):
    result = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key] = value
    return result


def atomic_write(path, data, template=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=path.name + ".", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        if template is not None:
            os.chown(temporary, template.st_uid, template.st_gid)
            os.chmod(temporary, template.st_mode & 0o777)
        else:
            os.chmod(temporary, 0o600)

        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_metadata(path, values):
    data = "".join(
        "{}={}\n".format(key, value)
        for key, value in values.items()
    )
    atomic_write(path, data.encode())


def load_config():
    return json.loads(CONFIG.read_text())


def managed_inbounds(config):
    result = []
    for inbound in config.get("inbounds", []):
        protocol = inbound.get("protocol")
        if protocol not in PROTOCOLS:
            continue
        stream = inbound.get("streamSettings", {})
        if (
            inbound.get("tag") in {
                "vless-ws", "vmess-ws", "trojan-ws",
                "vless-tcp", "vmess-tcp", "trojan-tcp",
            }
            or (
                inbound.get("listen") == "127.0.0.1"
                and inbound.get("port") == PORTS[protocol]
                and stream.get("network") == "ws"
            )
        ):
            result.append(inbound)
    return result


def verify_ws_layout(config):
    for protocol, port in PORTS.items():
        matches = [
            item for item in managed_inbounds(config)
            if item.get("protocol") == protocol
            and item.get("listen") == "127.0.0.1"
            and item.get("port") == port
            and item.get("streamSettings", {}).get("network") == "ws"
            and item.get("streamSettings", {}).get(
                "wsSettings", {}
            ).get("path") == "/" + protocol
        ]
        if len(matches) != 1:
            raise ValueError(
                "Expected one {} WS inbound at 127.0.0.1:{} "
                "with path /{}".format(protocol, port, protocol)
            )


def validate_config(path):
    subprocess.run(
        [XRAY, "run", "-test", "-config", str(path)],
        check=True,
        timeout=30,
    )


def commit_config(config):
    verify_ws_layout(config)
    old_data = CONFIG.read_bytes()
    old_stat = CONFIG.stat()
    new_data = (
        json.dumps(config, indent=2) + "\n"
    ).encode()

    fd, candidate = tempfile.mkstemp(
        prefix="config.test.", dir=str(CONFIG.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(new_data)
        validate_config(candidate)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)

    atomic_write(CONFIG, new_data, old_stat)

    try:
        subprocess.run(
            ["systemctl", "restart", "xray"],
            check=True, timeout=45,
        )
        time.sleep(0.5)
        subprocess.run(
            ["systemctl", "is-active", "--quiet", "xray"],
            check=True, timeout=10,
        )
    except Exception:
        atomic_write(CONFIG, old_data, old_stat)
        subprocess.run(
            ["systemctl", "restart", "xray"],
            timeout=45, check=False,
        )
        raise RuntimeError(
            "Xray restart failed; previous configuration restored"
        )


def remove_client(config, email):
    changed = False
    for inbound in managed_inbounds(config):
        settings = inbound.setdefault("settings", {})
        clients = settings.get("clients", [])
        kept = [
            client for client in clients
            if client.get("email") != email
        ]
        if len(kept) != len(clients):
            settings["clients"] = kept
            changed = True
    return changed


def put_client(config, name, credential):
    email = name + "@panel"
    remove_client(config, email)

    for inbound in managed_inbounds(config):
        protocol = inbound["protocol"]
        client = {"email": email}
        if protocol == "trojan":
            client["password"] = credential
        else:
            client["id"] = credential
            if protocol == "vmess":
                client["alterId"] = 0

        inbound.setdefault("settings", {}).setdefault(
            "clients", []
        ).append(client)


def expiry_after(days):
    days = int(days)
    if not 1 <= days <= 3650:
        raise ValueError("Days must be between 1 and 3650")
    return (
        datetime.date.today() + datetime.timedelta(days=days)
    ).isoformat()


def initialise():
    credential = str(uuid.uuid4())
    inbounds = []

    for protocol, port in PORTS.items():
        settings = {"clients": []}
        if protocol == "vless":
            settings["decryption"] = "none"

        inbounds.append({
            "tag": protocol + "-ws",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": protocol,
            "settings": settings,
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {"path": "/" + protocol},
            },
        })

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}}
        ],
    }
    put_client(config, "default", credential)
    atomic_write(
        CONFIG, (json.dumps(config, indent=2) + "\n").encode()
    )
    save_metadata(XUSERS / "default.conf", {
        "UUID": credential,
        "EXPIRY": "2099-12-31",
        "LIMIT": "0",
    })
    print("Created initial WS configuration and default account.")


def sync_accounts():
    config = load_config()
    verify_ws_layout(config)
    found = {}

    for inbound in managed_inbounds(config):
        for client in inbound.get("settings", {}).get("clients", []):
            email = client.get("email", "")
            if not email.endswith("@panel"):
                continue
            name = email[:-6]
            if not NAME.fullmatch(name):
                continue
            credential = client.get("id") or client.get("password")
            if credential:
                found.setdefault(name, set()).add(credential)

    for name, credentials in found.items():
        path = XUSERS / (name + ".conf")
        if path.exists():
            continue
        if len(credentials) != 1:
            logging.warning(
                "Cannot auto-import %s: protocol credentials differ", name
            )
            continue
        credential = next(iter(credentials))
        try:
            uuid.UUID(credential)
        except ValueError:
            logging.warning(
                "Cannot auto-import %s: credential is not a UUID", name
            )
            continue

        save_metadata(path, {
            "UUID": credential,
            "EXPIRY": "2099-12-31",
            "LIMIT": "0",
        })
        print("Recovered metadata:", name)


def add_account(name, days, sni):
    valid_name(name)
    if any(character in sni for character in "\r\n"):
        raise ValueError("Invalid SNI")
    path = XUSERS / (name + ".conf")
    if path.exists():
        raise ValueError("Account already exists")

    config = load_config()
    verify_ws_layout(config)

    email = name + "@panel"
    if any(
        client.get("email") == email
        for inbound in managed_inbounds(config)
        for client in inbound.get("settings", {}).get("clients", [])
    ):
        raise ValueError("Xray already contains this account; run sync")

    credential = str(uuid.uuid4())
    expiry = expiry_after(days)
    put_client(config, name, credential)
    commit_config(config)

    save_metadata(path, {
        "UUID": credential,
        "SNI": sni,
        "EXPIRY": expiry,
        "LIMIT": "0",
        "DISABLED": "0",
    })
    print("Created {}. Expires at start of {}.".format(name, expiry))


def renew_account(name, days):
    valid_name(name)
    path = XUSERS / (name + ".conf")
    values = metadata(path)
    if not values.get("UUID"):
        raise ValueError("Account not found")

    expiry = expiry_after(days)
    config = load_config()
    put_client(config, name, values["UUID"])
    commit_config(config)

    values.update(EXPIRY=expiry, DISABLED="0")
    save_metadata(path, values)
    print("Renewed {} until {}.".format(name, expiry))


def delete_account(name):
    valid_name(name)
    path = XUSERS / (name + ".conf")
    if not path.exists():
        raise ValueError("Account not found")

    config = load_config()
    if remove_client(config, name + "@panel"):
        commit_config(config)
    path.unlink()
    print("Deleted Xray account:", name)


def check_expiry():
    today = datetime.date.today()

    config = load_config()
    expired = []
    changed = False

    for path in XUSERS.glob("*.conf"):
        if not NAME.fullmatch(path.stem):
            continue
        values = metadata(path)
        try:
            expiry = datetime.date.fromisoformat(
                values.get("EXPIRY", "2099-12-31")
            )
        except ValueError:
            logging.error("Invalid expiry in %s", path)
            continue

        if today >= expiry:
            changed |= remove_client(config, path.stem + "@panel")
            if values.get("DISABLED") != "1":
                expired.append((path, values))

    if changed:
        commit_config(config)

    for path, values in expired:
        values["DISABLED"] = "1"
        save_metadata(path, values)

    for path in USERS.glob("*.conf"):
        if not NAME.fullmatch(path.stem):
            continue
        values = metadata(path)
        try:
            expiry = datetime.date.fromisoformat(
                values.get("EXPIRY", "2099-12-31")
            )
            account = pwd.getpwnam(path.stem)
        except (ValueError, KeyError):
            continue

        # Refuse to operate on privileged/system accounts.
        if account.pw_uid < 1000 or today < expiry:
            continue

        if values.get("PANEL_LOCKED") != "1":
            subprocess.run(
                ["usermod", "-L", path.stem],
                check=True, timeout=15,
            )
            values["PANEL_LOCKED"] = "1"
            save_metadata(path, values)

        # End existing sessions of an expired panel-managed SSH account.
        subprocess.run(
            ["pkill", "-KILL", "-u", str(account.pw_uid)],
            check=False, timeout=15,
        )


def cf_hostname():
    if (
        subprocess.run(
            ["systemctl", "is-active", "--quiet", "cf-panel-named"],
            check=False,
        ).returncode == 0
    ):
        path = ROOT / "cf_custom_domain"
        return path.read_text().strip() if path.exists() else ""

    # Legacy named tunnel: only report it when its process is active.
    custom = ROOT / "cf_custom_domain"
    if custom.exists() and subprocess.run(
        ["systemctl", "is-active", "--quiet", "cloudflared"],
        check=False,
    ).returncode == 0:
        return custom.read_text().strip()

    if subprocess.run(
        ["systemctl", "is-active", "--quiet", "cf-vless"],
        check=False,
    ).returncode:
        return ""

    invocation = subprocess.check_output(
        ["systemctl", "show", "cf-vless", "-p", "InvocationID", "--value"],
        text=True,
    ).strip()
    if not invocation:
        return ""

    logs = subprocess.check_output(
        [
            "journalctl",
            "_SYSTEMD_INVOCATION_ID=" + invocation,
            "-n", "1000", "--no-pager", "-o", "cat",
        ],
        text=True,
    )
    hosts = re.findall(
        r"https://([-a-zA-Z0-9]+\.trycloudflare\.com)", logs
    )
    return hosts[-1] if hosts else ""


def uri_address(server):
    server = server.strip("[]")
    try:
        if ipaddress.ip_address(server).version == 6:
            return "[" + server + "]"
    except ValueError:
        pass
    return server


def emit_links(name, credential, server, host, port, cloudflare=False):
    tls = port == 443
    prefix = name + ("-CF" if cloudflare else "")

    for protocol in PROTOCOLS:
        label = "{}-{}-WS-{}".format(
            prefix, protocol.upper(), port
        )
        title = "{} WS {} :{}".format(
            protocol.upper(), "TLS" if tls else "NON-TLS", port
        )
        if protocol == "trojan" and not tls:
            title += " [EXPERIMENTAL / INSECURE / MAY BE REJECTED]"

        print("\n" + title)
        if protocol == "vmess":
            value = {
                "v": "2", "ps": label,
                "add": server.strip("[]"),
                "port": str(port),
                "id": credential, "aid": "0",
                "net": "ws", "type": "none",
                "host": host, "path": "/vmess",
                "tls": "tls" if tls else "",
            }
            if tls:
                value.update(sni=host, alpn="http/1.1")

            encoded = base64.b64encode(
                json.dumps(
                    value, separators=(",", ":")
                ).encode()
            ).decode()
            print("vmess://" + encoded)
        else:
            params = {
                "security": "tls" if tls else "none",
                "type": "ws",
                "host": host,
                "path": "/" + protocol,
            }
            if protocol == "vless":
                params["encryption"] = "none"
            if tls:
                params.update(sni=host, alpn="http/1.1")

            print(
                "{}://{}@{}:{}?{}#{}".format(
                    protocol,
                    quote(credential, safe=""),
                    uri_address(server),
                    port,
                    urlencode(params),
                    quote(label, safe=""),
                )
            )


def print_links(name, server):
    names = (
        [valid_name(name)] if name != "all"
        else sorted(path.stem for path in XUSERS.glob("*.conf"))
    )
    cf = cf_hostname()
    default = ROOT / "default_sni"
    default_host = (
        default.read_text().strip() if default.exists() else server
    )

    for account in names:
        if not NAME.fullmatch(account):
            continue
        values = metadata(XUSERS / (account + ".conf"))
        credential = values.get("UUID")
        if not credential:
            continue

        host = values.get("SNI") or default_host or server
        print("\n" + "=" * 60)
        print("Account:", account)
        print("Expiry:", values.get("EXPIRY", "unknown"))
        print("Disabled:", values.get("DISABLED", "0"))

        for port in (80, 443):
            emit_links(account, credential, server, host, port)

        if cf:
            emit_links(
                account, credential, cf, cf, 443, cloudflare=True
            )

    print("\nTLS certificate verification is NOT disabled in these links.")
    print("Cloudflare requires real WS clients, not unframed SSH payloads.")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("init")
    commands.add_parser("sync")
    commands.add_parser("check")
    commands.add_parser("cf-host")

    add = commands.add_parser("add")
    add.add_argument("name")
    add.add_argument("days", type=int)
    add.add_argument("--sni", default="")

    renew = commands.add_parser("renew")
    renew.add_argument("name")
    renew.add_argument("days", type=int)

    delete = commands.add_parser("delete")
    delete.add_argument("name")

    links = commands.add_parser("links")
    links.add_argument("name")
    links.add_argument("--server", required=True)

    args = parser.parse_args()

    if os.geteuid() != 0:
        raise SystemExit("Run as root")

    USERS.mkdir(parents=True, exist_ok=True)
    XUSERS.mkdir(parents=True, exist_ok=True)

    if args.command == "cf-host":
        print(cf_hostname())
        return

    if args.command == "links":
        with locked():
            print_links(args.name, args.server)
        return

    if args.command:
        with locked():
            if args.command == "init":
                initialise()
            elif args.command == "sync":
                sync_accounts()
            elif args.command == "check":
                verify_ws_layout(load_config())
                validate_config(CONFIG)
            elif args.command == "add":
                add_account(args.name, args.days, args.sni)
            elif args.command == "renew":
                renew_account(args.name, args.days)
            elif args.command == "delete":
                delete_account(args.name)
        return

    logging.info(
        "Expiry manager started. Legacy LIMIT metadata is not enforced."
    )
    while True:
        try:
            with locked():
                check_expiry()
        except Exception:
            logging.exception("Expiry enforcement failed")
        time.sleep(30)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as error:
        logging.error("%s", error)
        sys.exit(1)
