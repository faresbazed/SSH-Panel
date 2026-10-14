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