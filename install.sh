#!/usr/bin/env bash

REPO_URL="https://raw.githubusercontent.com/faresbazed/SSH-Panel/main"
PANEL_DIR="/etc/ssh-panel"
XRAY_CFG="/usr/local/etc/xray/config.json"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo -i"
  exit 1
fi

echo "=================================================================="
echo "   Installing SSH-Panel (SSH-WS 80 + SSL 443 + Xray + Cloudflared)"
echo "=================================================================="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget jq unzip openssl python3 socat dropbear cron net-tools lsof psmisc

mkdir -p "${PANEL_DIR}" "${PANEL_DIR}/users" "${PANEL_DIR}/xray_users" /var/log/xray

# 1. Detect Public IP & Default SNI
PUB_IP=$(curl -s4 --max-time 5 https://icanhazip.com || curl -s4 --max-time 5 https://ifconfig.me || hostname -I | awk '{print $1}')
[ ! -f "${PANEL_DIR}/default_sni" ] && echo "${PUB_IP}" > "${PANEL_DIR}/default_sni"

cat > "${PANEL_DIR}/ports.conf" <<EOF
PORT_80_MODE=multiplex
PORT_443_MODE=multiplex
EOF

# 2. Stop Conflicting Web Servers on Port 80 / 443
for svc in nginx apache2 httpd; do
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
done
fuser -k 80/tcp 2>/dev/null || true
fuser -k 443/tcp 2>/dev/null || true

# 3. Enable Password Authentication in OpenSSH (Fixes AWS/Ubuntu 24.04)
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
if [ -d /etc/ssh/sshd_config.d ]; then
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$f" ] && sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$f"
  done
fi
grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# 4. Configure Dropbear on Port 109 (Without Duplicate Port Flags)
cat > "${PANEL_DIR}/banner.txt" <<EOF
<font color="green"><b>=== Connected via SSH-Panel Multiplexer ===</b></font>
EOF

cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS=""
DROPBEAR_BANNER="/etc/ssh-panel/banner.txt"
DROPBEAR_RECEIVE_WINDOW=65536
EOF

systemctl enable dropbear 2>/dev/null || true
systemctl restart dropbear 2>/dev/null || true

# 5. Generate Self-Signed TLS Certificate for Port 443
if [ ! -f "${PANEL_DIR}/cert.pem" ] || [ ! -f "${PANEL_DIR}/key.pem" ]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${PANEL_DIR}/key.pem" \
    -out "${PANEL_DIR}/cert.pem" \
    -subj "/C=US/ST=Cloud/L=Edge/O=SSH-Panel/CN=${PUB_IP}"
fi

# 6. Install Official Xray-core & Run as Root to Prevent Permission Errors
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

mkdir -p /etc/systemd/system/xray.service.d
cat > /etc/systemd/system/xray.service.d/override.conf <<EOF
[Service]
User=root
EOF

DEFAULT_UUID=$(cat /proc/sys/kernel/random/uuid)
cat > "${XRAY_CFG}" <<EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "vless-ws",
      "listen": "127.0.0.1",
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${DEFAULT_UUID}", "email": "default@panel" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vless" }
      }
    },
    {
      "tag": "vmess-ws",
      "listen": "127.0.0.1",
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": [
          { "id": "${DEFAULT_UUID}", "alterId": 0, "email": "default@panel" }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/vmess" }
      }
    },
    {
      "tag": "trojan-ws",
      "listen": "127.0.0.1",
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [
          { "password": "${DEFAULT_UUID}", "email": "default@panel" }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "/trojan" }
      }
    },
    {
      "tag": "vless-tcp",
      "listen": "127.0.0.1",
      "port": 10004,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${DEFAULT_UUID}", "email": "default@panel" }
        ],
        "decryption": "none"
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "vmess-tcp",
      "listen": "127.0.0.1",
      "port": 10005,
      "protocol": "vmess",
      "settings": {
        "clients": [
          { "id": "${DEFAULT_UUID}", "alterId": 0, "email": "default@panel" }
        ]
      },
      "streamSettings": { "network": "tcp" }
    },
    {
      "tag": "trojan-tcp",
      "listen": "127.0.0.1",
      "port": 10006,
      "protocol": "trojan",
      "settings": {
        "clients": [
          { "password": "${DEFAULT_UUID}", "email": "default@panel" }
        ]
      },
      "streamSettings": { "network": "tcp" }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} }
  ]
}
EOF

chmod 644 "${XRAY_CFG}"
chmod -R 777 /var/log/xray
systemctl daemon-reload
systemctl enable xray && systemctl restart xray

# 7. Install BadVPN UDPGW on Port 7300
ARCH=$(uname -m)
if [ ! -f /usr/local/bin/badvpn-udpgw ] && [ "$ARCH" = "x86_64" ]; then
  curl -L -o /usr/local/bin/badvpn-udpgw https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw64 2>/dev/null || true
  chmod +x /usr/local/bin/badvpn-udpgw 2>/dev/null || true
fi

if [ -x /usr/local/bin/badvpn-udpgw ]; then
  cat > /etc/systemd/system/badvpn.service <<EOF
[Unit]
Description=BadVPN UDPGW 7300
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
  systemctl enable --now badvpn 2>/dev/null || true
fi

# 8. Install Cloudflared & Configure Dedicated Logfile for URL Detection
if ! command -v cloudflared >/dev/null 2>&1; then
  DEB_ARCH=$(dpkg --print-architecture)
  curl -L --output /tmp/cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${DEB_ARCH}.deb"
  dpkg -i /tmp/cloudflared.deb && rm -f /tmp/cloudflared.deb
fi

CF_BIN=$(command -v cloudflared)
cat > /etc/systemd/system/cf-vless.service <<EOF
[Unit]
Description=Cloudflared Tunnel for SSH-Panel (Port 80 Multiplexer)
After=network.target ssh-ws.service

[Service]
Type=simple
ExecStartPre=/bin/rm -f /etc/ssh-panel/cloudflared.log
ExecStart=${CF_BIN} tunnel --url http://127.0.0.1:80 --protocol http2 --no-autoupdate --logfile /etc/ssh-panel/cloudflared.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 9. Download Panel Scripts (with Cache-Busting Timestamp)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
TS=$(date +%s)
for file in ssh-ws.py limiter.py menu.sh; do
  if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/${file}" ]; then
    cp "${SCRIPT_DIR}/${file}" "${PANEL_DIR}/${file}"
  else
    curl -fsSL "${REPO_URL}/${file}?t=${TS}" -o "${PANEL_DIR}/${file}"
  fi
done

chmod +x "${PANEL_DIR}/ssh-ws.py" "${PANEL_DIR}/limiter.py" "${PANEL_DIR}/menu.sh"
ln -sf "${PANEL_DIR}/menu.sh" /usr/local/bin/menu

# 10. Configure Multiplexer & IP Limiter Services
cat > /etc/systemd/system/ssh-ws.service <<EOF
[Unit]
Description=SSH-Panel Shared Multiplexer (Ports 80 & 443)
After=network.target dropbear.service xray.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/fuser -k 80/tcp
ExecStartPre=-/usr/bin/fuser -k 443/tcp
ExecStart=/usr/bin/python3 /etc/ssh-panel/ssh-ws.py
Restart=always
RestartSec=2
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ssh-limiter.service <<EOF
[Unit]
Description=SSH-Panel Per-User IP Limiter
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/ssh-panel/limiter.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ssh-ws ssh-limiter cf-vless
systemctl restart dropbear xray ssh-ws ssh-limiter cf-vless

echo "Waiting for Cloudflared Quick Tunnel URL..."
for i in {1..15}; do
  CF_URL=$(grep -oE 'https://[-a-zA-Z0-9]+\.trycloudflare\.com' /etc/ssh-panel/cloudflared.log 2>/dev/null | head -n 1 | sed 's|https://||')
  if [ -n "$CF_URL" ]; then
    echo "$CF_URL" > "${PANEL_DIR}/cf_domain"
    break
  fi
  sleep 1
done

echo ""
echo "=================================================================="
echo " Installation Complete! Run 'menu' to open SSH-Panel."
echo " Cloudflared Host: ${CF_URL:-Starting in background...}"
echo "=================================================================="
