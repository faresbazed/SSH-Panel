#!/usr/bin/env bash
set -e

REPO_URL="https://raw.githubusercontent.com/faresbazed/SSH-Panel/main"
PANEL_DIR="/etc/ssh-panel"
XRAY_CFG="/usr/local/etc/xray/config.json"

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo -i)"
  exit 1
fi

echo "=================================================================="
echo "      Installing SSH-Panel (SSH-WS + SSL + Xray + Cloudflared)    "
echo "=================================================================="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl wget jq unzip openssl python3 socat dropbear cron net-tools lsof psmisc

mkdir -p "${PANEL_DIR}" "${PANEL_DIR}/users" "${PANEL_DIR}/xray_users" /var/log/xray

# 1. Detect Public IP & Initialize Default Configs
PUB_IP=$(curl -s4 --max-time 5 https://icanhazip.com || curl -s4 --max-time 5 https://ifconfig.me || hostname -I | awk '{print $1}')
[ ! -f "${PANEL_DIR}/default_sni" ] && echo "${PUB_IP}" > "${PANEL_DIR}/default_sni"

cat > "${PANEL_DIR}/ports.conf" <<EOF
PORT_80_MODE=multiplex
PORT_443_MODE=multiplex
EOF

# 2. Stop/Disable Web Servers Occupying Port 80 or 443
for svc in nginx apache2 httpd caddy lighttpd; do
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
done
fuser -k 80/tcp 2>/dev/null || true
fuser -k 443/tcp 2>/dev/null || true

# 3. Configure Dropbear on Internal Port 109 (and ensure OpenSSH on 22 works as fallback)
cat > /etc/default/dropbear <<EOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 127.0.0.1:109 -W 65536"
DROPBEAR_BANNER="/etc/ssh-panel/banner.txt"
EOF

cat > "${PANEL_DIR}/banner.txt" <<EOF
<font color="green"><b>=== Connected via SSH-Panel Multiplexer ===</b></font>
EOF

grep -qxF "/bin/false" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qxF "/usr/sbin/nologin" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells
systemctl enable dropbear && systemctl restart dropbear

# 4. Generate Self-Signed TLS Certificate for Port 443 Multiplexer
if [ ! -f "${PANEL_DIR}/cert.pem" ] || [ ! -f "${PANEL_DIR}/key.pem" ]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${PANEL_DIR}/key.pem" \
    -out "${PANEL_DIR}/cert.pem" \
    -subj "/C=US/ST=Cloud/L=Edge/O=SSH-Panel/CN=${PUB_IP}"
fi

# 5. Install Official Xray-core & Write Multi-Protocol Config (Ports 10001-10006)
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

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

systemctl enable xray && systemctl restart xray

# 6. Install BadVPN UDPGW on Port 7300
ARCH=$(uname -m)
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
  if [ "$ARCH" = "x86_64" ]; then
    curl -L -o /usr/local/bin/badvpn-udpgw https://github.com/ambrop72/badvpn/releases/download/1.999.130/badvpn-udpgw64 || true
  fi
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

# 7. Install Cloudflared Binary & Configure Tunnel to Port 80 Multiplexer
if ! command -v cloudflared >/dev/null 2>&1; then
  DEB_ARCH=$(dpkg --print-architecture)
  curl -L --output /tmp/cloudflared.deb "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${DEB_ARCH}.deb"
  dpkg -i /tmp/cloudflared.deb && rm -f /tmp/cloudflared.deb
fi

CF_BIN=$(command -v cloudflared)
rm -f /var/log/cloudflared.log
cat > /etc/systemd/system/cf-vless.service <<EOF
[Unit]
Description=Cloudflared Tunnel for SSH-Panel (Port 80 Multiplexer)
After=network-online.target ssh-ws.service
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/rm -f /var/log/cloudflared.log
ExecStart=${CF_BIN} tunnel --url http://127.0.0.1:80 --edge-ip-version 4 --protocol http2 --no-autoupdate --logfile /var/log/cloudflared.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 8. Install Panel Scripts (Local Repo Copy or GitHub Download)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for file in ssh-ws.py limiter.py menu.sh; do
  if [ -f "${SCRIPT_DIR}/${file}" ]; then
    cp "${SCRIPT_DIR}/${file}" "${PANEL_DIR}/${file}"
  else
    curl -fsSL "${REPO_URL}/${file}?v=$(date +%s)" -o "${PANEL_DIR}/${file}"
  fi
done

chmod +x "${PANEL_DIR}/ssh-ws.py" "${PANEL_DIR}/limiter.py" "${PANEL_DIR}/menu.sh"
ln -sf "${PANEL_DIR}/menu.sh" /usr/local/bin/menu

# 9. Create & Start Systemd Services for Multiplexer and Limiter
cat > /etc/systemd/system/ssh-ws.service <<EOF
[Unit]
Description=SSH-Panel Shared Multiplexer (Ports 80 & 443)
After=network.target dropbear.service xray.service

[Service]
Type=simple
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

echo "Waiting 5 seconds for Cloudflare Tunnel URL..."
sleep 5

echo ""
echo "=================================================================="
echo " Installation Complete! Type 'menu' to launch your SSH-Panel."
echo "=================================================================="
