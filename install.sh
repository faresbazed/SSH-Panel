#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPO_URL="${REPO_URL:-https://raw.githubusercontent.com/faresbazed/SSH-Panel/main}"
PANEL_DIR="/etc/ssh-panel"
XRAY_CFG="/usr/local/etc/xray/config.json"

[[ $EUID -eq 0 ]] || {
  echo "Run as root: sudo bash install.sh"
  exit 1
}

command -v apt-get >/dev/null || {
  echo "This installer supports Debian/Ubuntu with systemd."
  exit 1
}
[[ -d /run/systemd/system ]] || {
  echo "A running systemd installation is required."
  exit 1
}

command -v flock >/dev/null || {
  echo "Install util-linux first."
  exit 1
}
exec 9>/run/lock/ssh-panel-install.lock
flock -n 9 || {
  echo "Another installation is running."
  exit 1
}

STAGE=$(mktemp -d)
BACKUP=""
cleanup() {
  rm -rf -- "$STAGE"
}
trap cleanup EXIT
trap 'echo "Installation stopped at line $LINENO. Backup: ${BACKUP:-not created}. Inspect the error before retrying." >&2' ERR

echo "============================================================"
echo " SSH-Panel installation / non-destructive update"
echo " Existing Xray configuration, accounts and certificates kept"
echo "============================================================"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  ca-certificates curl python3 openssl iproute2 \
  dropbear-bin passwd procps tar unzip

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

for file in ssh-ws.py limiter.py menu.sh; do
  if [[ -f "$SCRIPT_DIR/$file" ]]; then
    cp -- "$SCRIPT_DIR/$file" "$STAGE/$file"
  else
    curl -fL --retry 3 --connect-timeout 15 \
      "$REPO_URL/$file" -o "$STAGE/$file"
  fi
done

bash -n "$STAGE/menu.sh"
python3 - "$STAGE" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for name in ("ssh-ws.py", "limiter.py"):
    compile((root / name).read_text(), name, "exec")
print("Downloaded/local script syntax checks passed.")
PY

mkdir -p /root/ssh-panel-backups
chmod 700 /root/ssh-panel-backups

STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
BACKUP="/root/ssh-panel-backups/install-${STAMP}.tar.gz"

ITEMS=()
for path in \
  etc/ssh-panel \
  usr/local/etc/xray \
  etc/systemd/system/ssh-ws.service \
  etc/systemd/system/ssh-limiter.service \
  etc/systemd/system/cf-vless.service \
  etc/systemd/system/cf-panel-named.service \
  etc/systemd/system/ssh-panel-dropbear.service; do
  [[ ! -e "/$path" ]] || ITEMS+=("$path")
done

if ((${#ITEMS[@]})); then
  tar -czpf "$BACKUP" -C / "${ITEMS[@]}"
else
  tar -czpf "$BACKUP" --files-from /dev/null
fi
chmod 600 "$BACKUP"
echo "Backup: $BACKUP"

mkdir -p \
  "$PANEL_DIR/users" \
  "$PANEL_DIR/xray_users" \
  /usr/local/etc/xray

chmod 700 "$PANEL_DIR" "$PANEL_DIR/users" "$PANEL_DIR/xray_users"

# Do not stop unrelated services or forcibly kill port occupants.
# An existing panel frontend may already own these ports.
if ! systemctl is-active --quiet ssh-ws; then
  if ss -H -ltn '( sport = :80 or sport = :443 )' | grep -q .; then
    echo
    echo "Port 80 or 443 is occupied:"
    ss -ltnp '( sport = :80 or sport = :443 )'
    echo "Resolve this conflict explicitly, then rerun."
    exit 1
  fi
fi

PUBLIC_IP=$(
  curl -fsS4 --connect-timeout 5 --max-time 10 \
    https://icanhazip.com 2>/dev/null ||
  hostname -I | awk '{print $1}'
)
PUBLIC_IP="${PUBLIC_IP//$'\n'/}"

if [[ ! -s "$PANEL_DIR/default_sni" ]]; then
  printf '%s\n' "$PUBLIC_IP" > "$PANEL_DIR/default_sni"
fi

if [[ ! -f "$PANEL_DIR/ports.conf" ]]; then
  cat > "$PANEL_DIR/ports.conf" <<'EOF'
PORT_80_MODE=multiplex
PORT_443_MODE=multiplex
EOF
fi

# Never replace an existing certificate pair automatically.
if [[ ! -f "$PANEL_DIR/cert.pem" && ! -f "$PANEL_DIR/key.pem" ]]; then
  CERT_NAME=$(cat "$PANEL_DIR/default_sni")
  [[ "$CERT_NAME" =~ ^[A-Za-z0-9.:-]+$ ]] || CERT_NAME=localhost

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$PANEL_DIR/key.pem" \
    -out "$PANEL_DIR/cert.pem" \
    -subj "/CN=$CERT_NAME"

  echo "Created a self-signed certificate."
  echo "For verified TLS, import a matching trusted certificate in menu."
elif [[ ! -f "$PANEL_DIR/cert.pem" || ! -f "$PANEL_DIR/key.pem" ]]; then
  echo "Only one certificate/key file exists. Repair the pair first."
  exit 1
fi
chmod 600 "$PANEL_DIR/key.pem" "$PANEL_DIR/cert.pem"

# Verify the replacement frontend can load the existing settings/certificate.
python3 "$STAGE/ssh-ws.py" --check

# Install Xray only when its binary is missing.
HAD_XRAY_CONFIG=0
[[ ! -s "$XRAY_CFG" ]] || HAD_XRAY_CONFIG=1

if [[ ! -x /usr/local/bin/xray ]]; then
  curl -fL --retry 3 \
    https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh \
    -o "$STAGE/xray-install.sh"
  bash "$STAGE/xray-install.sh" install
fi

if ((HAD_XRAY_CONFIG == 0)); then
  python3 "$STAGE/limiter.py" init
else
  echo "Preserving existing Xray configuration."
fi

/usr/local/bin/xray run -test -config "$XRAY_CFG"

# Make the configuration readable by Xray's actual service account.
XRAY_USER=$(systemctl show xray -p User --value)
XRAY_USER="${XRAY_USER:-root}"
XRAY_GROUP=$(systemctl show xray -p Group --value)
XRAY_GROUP="${XRAY_GROUP:-$(id -gn "$XRAY_USER")}"

chown root:"$XRAY_GROUP" "$XRAY_CFG"
chmod 640 "$XRAY_CFG"

# Existing configurations may write logs here.
mkdir -p /var/log/xray
chown "$XRAY_USER:$XRAY_GROUP" /var/log/xray
chmod 750 /var/log/xray
for logfile in /var/log/xray/access.log /var/log/xray/error.log; do
  if [[ -f "$logfile" && ! -L "$logfile" ]]; then
    chown "$XRAY_USER:$XRAY_GROUP" "$logfile"
    chmod 640 "$logfile"
  fi
done

# Prefer an existing backend on 109; otherwise create a panel-owned one.
# This does not alter OpenSSH or the generic Dropbear service.
if [[ -f /etc/systemd/system/ssh-panel-dropbear.service ]] ||
   ! ss -H -ltn 'sport = :109' | grep -q .; then
  DROPBEAR_BIN=$(command -v dropbear)
  cat > /etc/systemd/system/ssh-panel-dropbear.service <<EOF
# SSH-PANEL-MANAGED
[Unit]
Description=SSH-Panel loopback Dropbear backend
After=network.target

[Service]
Type=simple
ExecStart=${DROPBEAR_BIN} -F -E -w -p 127.0.0.1:109
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
fi

grep -qxF /bin/false /etc/shells || echo /bin/false >> /etc/shells

if ! command -v cloudflared >/dev/null; then
  ARCH=$(dpkg --print-architecture)
  curl -fL --retry 3 \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb" \
    -o "$STAGE/cloudflared.deb"
  dpkg -i "$STAGE/cloudflared.deb"
fi
CF_BIN=$(command -v cloudflared)

# An explicit empty config avoids accidentally using another tunnel's config.
printf '{}\n' > "$PANEL_DIR/cloudflared-empty.yml"

QUICK_WAS_ACTIVE=0
systemctl is-active --quiet cf-vless && QUICK_WAS_ACTIVE=1 || true
NEW_INSTALL=0
[[ -f "$PANEL_DIR/menu.sh" ]] || NEW_INSTALL=1

systemctl stop ssh-limiter 2>/dev/null || true

for file in ssh-ws.py limiter.py menu.sh; do
  install -m 700 "$STAGE/$file" "$PANEL_DIR/$file"
done

cat > /etc/systemd/system/ssh-ws.service <<'EOF'
# SSH-PANEL-MANAGED
[Unit]
Description=SSH-Panel WebSocket frontend
Wants=network-online.target
After=network-online.target xray.service dropbear.service ssh-panel-dropbear.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/ssh-panel/ssh-ws.py
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ssh-limiter.service <<'EOF'
# SSH-PANEL-MANAGED
[Unit]
Description=SSH-Panel account expiry manager
After=network.target xray.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/ssh-panel/limiter.py
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/cf-vless.service <<EOF
# SSH-PANEL-MANAGED
[Unit]
Description=SSH-Panel Cloudflare Quick Tunnel
Wants=network-online.target
After=network-online.target ssh-ws.service

[Service]
Type=simple
ExecStart=${CF_BIN} tunnel --config /etc/ssh-panel/cloudflared-empty.yml --no-autoupdate --edge-ip-version 4 --protocol http2 --url http://127.0.0.1:80
Restart=on-failure
RestartSec=5
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

ln -sfn "$PANEL_DIR/menu.sh" /usr/local/bin/menu
systemctl daemon-reload

if [[ -f /etc/systemd/system/ssh-panel-dropbear.service ]]; then
  systemctl enable ssh-panel-dropbear
  systemctl restart ssh-panel-dropbear
fi

systemctl enable xray ssh-ws ssh-limiter
systemctl restart xray

# Recover account metadata for legacy panel clients without changing UUIDs.
python3 "$PANEL_DIR/limiter.py" sync

systemctl restart ssh-ws ssh-limiter

# Do not start Quick Tunnel alongside an existing named tunnel.
if ! systemctl is-active --quiet cf-panel-named &&
   ! systemctl is-active --quiet cloudflared; then
  if ((NEW_INSTALL || QUICK_WAS_ACTIVE)); then
    systemctl enable cf-vless
    systemctl restart cf-vless
  fi
fi

echo
echo "============================================================"
echo " Installed. Run: menu"
echo " Backup: $BACKUP"
echo " Option 7: print existing Xray account links"
echo " Option 9: Cloudflared"
echo " Option 99: uninstall panel software"
echo "============================================================"

sleep 2
if curl -fsS --max-time 5 http://127.0.0.1/healthz; then
  echo "Local port 80 frontend responds."
else
  echo "Port 80 readiness failed or port 80 is disabled."
  echo "Inspect: journalctl -u ssh-ws -n 80 --no-pager"
fi

echo
echo "External firewall/provider rules are not changed."
echo "Quick Tunnel may need additional time to connect."
echo "BadVPN is not installed/modified by this version."
