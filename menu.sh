#!/usr/bin/env bash
set -uo pipefail
umask 077

PANEL_DIR="/etc/ssh-panel"
USERS_DIR="$PANEL_DIR/users"
XRAY_USERS_DIR="$PANEL_DIR/xray_users"
HELPER="$PANEL_DIR/limiter.py"

[[ $EUID -eq 0 ]] || {
  echo "Run as root: sudo menu"
  exit 1
}

mkdir -p "$USERS_DIR" "$XRAY_USERS_DIR"
chmod 700 "$PANEL_DIR" "$USERS_DIR" "$XRAY_USERS_DIR"

pause() {
  read -r -p "Press Enter to return..." _
}

valid_name() {
  [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || {
    echo "Use lowercase letters, digits, _ and -; maximum 32 characters."
    return 1
  }
}

valid_days() {
  [[ "${1:-}" =~ ^[1-9][0-9]{0,3}$ ]] &&
    ((10#$1 <= 3650)) || {
      echo "Enter days between 1 and 3650."
      return 1
    }
}

public_ip() {
  curl -fsS4 --connect-timeout 4 --max-time 7 \
    https://icanhazip.com 2>/dev/null ||
    hostname -I | awk '{print $1}'
}

status() {
  if systemctl is-active --quiet "$1"; then
    printf ACTIVE
  else
    printf INACTIVE
  fi
}

list_accounts() {
  local kind="$1" file
  for file in "$kind"/*.conf; do
    [[ -f "$file" ]] || continue
    printf '%s\n' "$(basename "$file" .conf)"
  done
}

show_ssh_info() {
  local name="$1" server host cf
  server=$(public_ip)
  host=$(cat "$PANEL_DIR/default_sni" 2>/dev/null)
  host="${host:-$server}"
  cf=$(python3 "$HELPER" cf-host 2>/dev/null || true)

  echo
  echo "Username: $name"
  echo "Server: $server"
  echo "WS: port 80, path /ssh"
  echo "WSS: port 443, path /ssh"
  echo "TLS hostname: $host"
  echo
  echo "Legacy direct HTTP-upgrade payload:"
  echo "GET /ssh HTTP/1.1[crlf]Host: ${host}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
  echo
  echo "Real WebSocket clients must send masked binary frames."
  echo "Do not manually invent a fixed Sec-WebSocket-Key."
  if [[ -n "$cf" ]]; then
    echo "Cloudflare WSS: $cf:443, path /ssh"
    echo "Cloudflare requires an actual WebSocket-capable SSH client."
  fi
}

create_ssh() {
  local name password days expiry
  read -r -p "Username: " name
  valid_name "$name" || return
  if id "$name" >/dev/null 2>&1; then
    echo "System account already exists; refusing to replace it."
    return
  fi
  [[ ! -f "$USERS_DIR/$name.conf" ]] || {
    echo "Panel metadata already exists."
    return
  }

  read -r -s -p "Password: " password
  echo
  [[ -n "$password" ]] || {
    echo "Password cannot be empty."
    return
  }
  read -r -p "Validity days [30]: " days
  days="${days:-30}"
  valid_days "$days" || return
  expiry=$(date -d "+$days days" +%F) || return

  (
    flock -x 8
    if ! useradd -M -s /bin/false -e "$expiry" "$name"; then
      exit 1
    fi
    if ! printf '%s:%s\n' "$name" "$password" | chpasswd; then
      userdel "$name" 2>/dev/null || true
      exit 1
    fi
    printf 'EXPIRY=%s\nLIMIT=0\nPANEL_LOCKED=0\n' "$expiry" \
      > "$USERS_DIR/$name.conf"
    chmod 600 "$USERS_DIR/$name.conf"
  ) 8>/run/lock/ssh-panel-state.lock || {
    unset password
    echo "Could not create account."
    return
  }

  unset password
  echo "Created. Expires at start of $expiry."
  echo "Password is not stored in the panel metadata."
  show_ssh_info "$name"
}

managed_ssh() {
  local name="$1" uid
  valid_name "$name" || return
  [[ -f "$USERS_DIR/$name.conf" ]] || {
    echo "Not a panel-managed account."
    return 1
  }
  uid=$(id -u "$name") || return
  ((uid >= 1000)) || {
    echo "Refusing to modify a privileged/system account."
    return 1
  }
}

renew_ssh() {
  local name days expiry
  list_accounts "$USERS_DIR"
  read -r -p "Username: " name
  managed_ssh "$name" || return
  read -r -p "Validity days from today [30]: " days
  days="${days:-30}"
  valid_days "$days" || return
  expiry=$(date -d "+$days days" +%F) || return

  (
    flock -x 8
    chage -E "$expiry" "$name" || exit 1

    if grep -qx 'PANEL_LOCKED=1' "$USERS_DIR/$name.conf"; then
      usermod -U "$name" || exit 1
    fi

    # Preserve metadata keys, but remove legacy plaintext passwords.
    python3 - "$USERS_DIR/$name.conf" "$expiry" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
values = {}
for line in path.read_text().splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        if key != "PASSWORD":
            values[key] = value
values.update(EXPIRY=sys.argv[2], PANEL_LOCKED="0")

fd, temporary = tempfile.mkstemp(dir=str(path.parent))
try:
    with os.fdopen(fd, "w") as stream:
        for key, value in values.items():
            stream.write("{}={}\n".format(key, value))
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
  ) 8>/run/lock/ssh-panel-state.lock || return

  echo "Renewed until $expiry."
}

delete_ssh() {
  local name answer uid
  list_accounts "$USERS_DIR"
  read -r -p "Username: " name
  managed_ssh "$name" || return
  read -r -p "Type DELETE to remove $name: " answer
  [[ "$answer" == DELETE ]] || return
  uid=$(id -u "$name") || return

  (
    flock -x 8
    pkill -KILL -u "$uid" 2>/dev/null || true
    userdel "$name" || exit 1
    rm -f "$USERS_DIR/$name.conf"
  ) 8>/run/lock/ssh-panel-state.lock
}

create_xray() {
  local name days host server
  read -r -p "Username: " name
  valid_name "$name" || return
  read -r -p "Validity days [30]: " days
  days="${days:-30}"
  valid_days "$days" || return
  read -r -p "TLS hostname [panel default]: " host
  [[ -z "$host" || "$host" =~ ^[A-Za-z0-9.:-]+$ ]] || {
    echo "Enter a hostname or IP, not a URL."
    return
  }

  python3 "$HELPER" add "$name" "$days" --sni "$host" || return
  server=$(public_ip)
  python3 "$HELPER" links "$name" --server "$server"
}

renew_xray() {
  local name days
  list_accounts "$XRAY_USERS_DIR"
  read -r -p "Username: " name
  valid_name "$name" || return
  read -r -p "Validity days from today [30]: " days
  days="${days:-30}"
  valid_days "$days" || return
  python3 "$HELPER" renew "$name" "$days"
}

delete_xray() {
  local name answer
  list_accounts "$XRAY_USERS_DIR"
  read -r -p "Username: " name
  valid_name "$name" || return
  read -r -p "Type DELETE to remove $name: " answer
  [[ "$answer" == DELETE ]] || return
  python3 "$HELPER" delete "$name"
}

show_links() {
  local name server
  python3 "$HELPER" sync || return
  list_accounts "$XRAY_USERS_DIR"
  read -r -p "Username or all [all]: " name
  name="${name:-all}"
  server=$(public_ip)
  python3 "$HELPER" links "$name" --server "$server"
}

diagnostics() {
  local choice
  echo "1) Service status, listeners and logs"
  echo "2) Validate and restart frontend/Xray"
  echo "3) Enable both public frontend ports"
  read -r -p "Select: " choice

  case "$choice" in
    1)
      for service in ssh-ws xray ssh-limiter cf-vless cf-panel-named; do
        echo "$service: $(status "$service")"
      done
      ss -ltnp | grep -E ':(22|80|109|443|1000[1-6])\b' || true
      curl -fsS --max-time 5 http://127.0.0.1/healthz || true
      journalctl \
        -u ssh-ws -u xray -u ssh-limiter \
        -u cf-vless -u cf-panel-named \
        -n 100 --no-pager
      ;;
    2)
      python3 "$PANEL_DIR/ssh-ws.py" --check || return
      python3 "$HELPER" check || return
      systemctl restart xray ssh-ws ssh-limiter
      ;;
    3)
      cat > "$PANEL_DIR/ports.conf" <<'EOF'
PORT_80_MODE=multiplex
PORT_443_MODE=multiplex
EOF
      python3 "$PANEL_DIR/ssh-ws.py" --check || return
      systemctl restart ssh-ws
      ;;
  esac
}

cloudflare_menu() {
  local choice host token binary current i answer

  current=$(python3 "$HELPER" cf-host 2>/dev/null || true)
  echo "Reported hostname: ${current:-not detected}"
  echo "An active process alone does not prove tunnel connectivity."
  echo "1) Start/recreate Quick Tunnel"
  echo "2) Configure panel-owned named tunnel"
  echo "3) Stop panel-owned tunnels"
  echo "4) Show tunnel logs"
  echo "0) Back"
  read -r -p "Select: " choice

  if [[ "$choice" == 1 || "$choice" == 2 ]]; then
    if systemctl is-active --quiet cloudflared; then
      echo "Generic cloudflared.service is active."
      echo "It may serve unrelated applications; it will not be stopped."
      echo "Migrate/stop it explicitly before switching this panel's tunnel."
      return
    fi
  fi

  case "$choice" in
    1)
      echo "A Quick Tunnel receives a new hostname when recreated."
      read -r -p "Continue? [y/N]: " answer
      [[ "$answer" == y || "$answer" == Y ]] || return

      systemctl disable --now cf-panel-named 2>/dev/null || true
      rm -f "$PANEL_DIR/cf_custom_domain"

      systemctl enable cf-vless || return
      systemctl restart cf-vless || return

      current=""
      for ((i=0; i<60; i++)); do
        current=$(python3 "$HELPER" cf-host 2>/dev/null || true)
        [[ -n "$current" ]] && break
        sleep 1
      done

      echo "Hostname: ${current:-not detected; inspect logs}"
      echo "Regenerate account links using menu option 7."
      ;;
    2)
      binary=$(command -v cloudflared) || return
      if ! "$binary" tunnel run --help 2>&1 |
          grep -q -- '--token-file'; then
        echo "This cloudflared version lacks --token-file."
        echo "Update cloudflared before configuring a named tunnel."
        return
      fi

      echo "In Cloudflare's tunnel dashboard, configure the public hostname"
      echo "to use HTTP service: http://127.0.0.1:80"
      read -r -p "Configured public hostname: " host
      [[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || {
        echo "Enter a hostname, without https:// or a path."
        return
      }

      read -r -s -p "Tunnel token: " token
      echo
      [[ -n "$token" ]] || return
      printf '%s' "$token" > "$PANEL_DIR/cf-token"
      chmod 600 "$PANEL_DIR/cf-token"
      unset token

      printf '%s\n' "$host" > "$PANEL_DIR/cf_custom_domain"
      printf '{}\n' > "$PANEL_DIR/cloudflared-empty.yml"

      cat > /etc/systemd/system/cf-panel-named.service <<EOF
# SSH-PANEL-MANAGED
[Unit]
Description=SSH-Panel named Cloudflare Tunnel
Wants=network-online.target
After=network-online.target ssh-ws.service

[Service]
Type=simple
ExecStart=${binary} tunnel --config /etc/ssh-panel/cloudflared-empty.yml --no-autoupdate --edge-ip-version 4 --protocol http2 run --token-file /etc/ssh-panel/cf-token
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

      systemctl disable --now cf-vless 2>/dev/null || true
      systemctl daemon-reload
      systemctl enable cf-panel-named &&
        systemctl restart cf-panel-named

      echo "Inspect option 4 for successful tunnel registration."
      ;;
    3)
      systemctl disable --now cf-vless cf-panel-named 2>/dev/null || true
      echo "Panel-owned tunnels stopped."
      echo "Generic cloudflared.service was not modified."
      ;;
    4)
      journalctl -u cf-vless -u cf-panel-named -n 120 --no-pager
      ;;
  esac
}

certificate_menu() {
  local cert key temporary backup answer new_host
  echo "1) Import a trusted certificate and private key"
  echo "2) Change default TLS hostname for new account links"
  echo "3) Show installed certificate"
  read -r -p "Select: " answer

  case "$answer" in
    1)
      read -r -p "Full certificate-chain file: " cert
      read -r -p "Private-key file: " key
      [[ -f "$cert" && -f "$key" ]] || {
        echo "Certificate/key file not found."
        return
      }

      # Confirm the certificate/key pair loads before replacing anything.
      python3 - "$cert" "$key" <<'PY'
import ssl
import sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
print("Certificate/key pair loads successfully.")
PY
      [[ $? -eq 0 ]] || return

      temporary=$(mktemp -d "$PANEL_DIR/cert-import.XXXXXX") || return
      install -m 600 "$cert" "$temporary/cert.pem" || {
        rm -rf "$temporary"; return;
      }
      install -m 600 "$key" "$temporary/key.pem" || {
        rm -rf "$temporary"; return;
      }

      backup="/root/ssh-panel-backups/cert-$(date -u +%Y%m%dT%H%M%SZ)-$$"
      mkdir -p "$backup"
      chmod 700 "$backup"
      cp -p "$PANEL_DIR/cert.pem" "$PANEL_DIR/key.pem" "$backup/" || {
        rm -rf "$temporary"; return;
      }

      mv "$temporary/cert.pem" "$PANEL_DIR/cert.pem"
      mv "$temporary/key.pem" "$PANEL_DIR/key.pem"
      rmdir "$temporary"

      if ! systemctl restart ssh-ws; then
        cp -p "$backup/cert.pem" "$backup/key.pem" "$PANEL_DIR/"
        systemctl restart ssh-ws || true
        echo "Restart failed; previous certificate restored."
        return
      fi
      echo "Certificate installed. Ensure your TLS hostname matches it."
      echo "Renewed certificates must be reimported unless automated separately."
      ;;
    2)
      read -r -p "Default TLS hostname: " new_host
      [[ "$new_host" =~ ^[A-Za-z0-9.:-]+$ ]] || {
        echo "Invalid hostname/IP."
        return
      }
      printf '%s\n' "$new_host" > "$PANEL_DIR/default_sni"
      echo "Default updated. Existing accounts with SNI metadata retain it."
      ;;
    3)
      openssl x509 -in "$PANEL_DIR/cert.pem" \
        -noout -subject -issuer -dates
      ;;
  esac
}

uninstall_panel() {
  local answer stamp backup service unit
  local items=(etc/ssh-panel)

  echo "This removes the panel frontend, expiry manager and panel-owned tunnels."
  echo "It preserves SSH accounts, certificates, metadata, Xray and OpenSSH."
  echo "Generic Dropbear/cloudflared services and BadVPN are not removed."
  echo "Connections through the panel's public ports will be disconnected."
  echo "Keep a separate normal SSH session open."
  read -r -p "Type UNINSTALL to continue: " answer
  [[ "$answer" == UNINSTALL ]] || return

  stamp=$(date -u +%Y%m%dT%H%M%SZ)-$$
  mkdir -p /root/ssh-panel-backups
  chmod 700 /root/ssh-panel-backups
  backup="/root/ssh-panel-backups/uninstall-${stamp}.tar.gz"

  for service in \
    ssh-ws ssh-limiter cf-vless cf-panel-named ssh-panel-dropbear; do
    unit="etc/systemd/system/${service}.service"
    [[ ! -f "/$unit" ]] || items+=("$unit")
  done

  tar -czpf "$backup" -C / "${items[@]}" || {
    echo "Backup failed; uninstall cancelled."
    return
  }
  chmod 600 "$backup"

  for service in \
    ssh-ws ssh-limiter cf-vless cf-panel-named ssh-panel-dropbear; do
    unit="/etc/systemd/system/${service}.service"
    if [[ -f "$unit" ]] &&
        grep -qx '# SSH-PANEL-MANAGED' "$unit"; then
      systemctl disable --now "$service" 2>/dev/null || true
      rm -f "$unit"
    fi
  done

  if [[ -L /usr/local/bin/menu ]] &&
      [[ "$(readlink -f /usr/local/bin/menu)" == "$PANEL_DIR/menu.sh" ]]; then
    rm -f /usr/local/bin/menu
  fi

  rm -f \
    "$PANEL_DIR/ssh-ws.py" \
    "$PANEL_DIR/limiter.py" \
    "$PANEL_DIR/menu.sh" \
    "$PANEL_DIR/cf-token"

  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true

  echo "Panel software removed."
  echo "Backup: $backup"
  echo "Accounts/configuration/certificates remain in $PANEL_DIR."
  echo "Xray remains installed, with its existing configuration."
  exit 0
}

while true; do
  echo
  echo "============================================================"
  echo " SSH-Panel"
  echo " Frontend: $(status ssh-ws) | Xray: $(status xray)"
  echo " Quick CF: $(status cf-vless) | Named CF: $(status cf-panel-named)"
  echo "============================================================"
  echo " 1) Create SSH account"
  echo " 2) Renew SSH account"
  echo " 3) Delete SSH account"
  echo " 4) Create Xray account"
  echo " 5) Renew Xray account"
  echo " 6) Delete Xray account"
  echo " 7) Print Xray links: VLESS / VMess / Trojan, ports 80 / 443"
  echo " 8) Diagnostics / restart / enable ports"
  echo " 9) Cloudflared management"
  echo "10) TLS certificate / default hostname"
  echo "99) Uninstall panel software"
  echo " 0) Exit"
  echo "============================================================"
  read -r -p "Select: " choice || exit 0

  case "$choice" in
    1) create_ssh ;;
    2) renew_ssh ;;
    3) delete_ssh ;;
    4) create_xray ;;
    5) renew_xray ;;
    6) delete_xray ;;
    7) show_links ;;
    8) diagnostics ;;
    9) cloudflare_menu ;;
    10) certificate_menu ;;
    99) uninstall_panel ;;
    0) exit 0 ;;
    *) echo "Invalid selection." ;;
  esac

  pause
done
