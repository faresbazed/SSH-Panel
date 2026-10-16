#!/usr/bin/env bash

PANEL_DIR="/etc/ssh-panel"
USERS_DIR="${PANEL_DIR}/users"
XRAY_USERS_DIR="${PANEL_DIR}/xray_users"
XRAY_CFG="/usr/local/etc/xray/config.json"
PORTS_CONF="${PANEL_DIR}/ports.conf"

mkdir -p "${USERS_DIR}" "${XRAY_USERS_DIR}"

G="\e[32m"
R="\e[31m"
C="\e[36m"
Y="\e[33m"
N="\e[0m"

get_status() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then
    echo -e "${G}[ACTIVE]${N}"
  else
    echo -e "${R}[INACTIVE]${N}"
  fi
}

get_cf_domain() {
  if [ -f "${PANEL_DIR}/cf_custom_domain" ] && systemctl is-active --quiet cloudflared 2>/dev/null; then
    cat "${PANEL_DIR}/cf_custom_domain"
    return
  fi
  if systemctl is-active --quiet cf-vless 2>/dev/null; then
    CF_URL=""
    if [ -f /var/log/cloudflared.log ]; then
      CF_URL=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -n 1 | sed 's|https://||')
    fi
    if [ -z "$CF_URL" ]; then
      CF_URL=$(journalctl -u cf-vless -n 100 --no-pager 2>/dev/null | grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' | tail -n 1 | sed 's|https://||')
    fi
    echo "${CF_URL:-Starting...}"
    return
  fi
  echo "None"
}

get_cf_status() {
  if systemctl is-active --quiet cf-vless 2>/dev/null || systemctl is-active --quiet cloudflared 2>/dev/null; then
    echo -e "${G}[ACTIVE]${N}"
  else
    echo -e "${R}[INACTIVE]${N}"
  fi
}

print_xray_links() {
  local username="$1"
  local UUID="$2"
  local SNI="$3"
  local PUB_IP
  PUB_IP=$(curl -s4 --max-time 3 https://icanhazip.com || hostname -I | awk '{print $1}')
  local CF_HOST
  CF_HOST=$(get_cf_domain)

  # Build VMess Base64 URIs for Port 443, Port 80, and Cloudflared 443
  local VMESS_443
  VMESS_443=$(jq -n --arg add "$PUB_IP" --arg id "$UUID" --arg sni "$SNI" --arg ps "${username}-VMess-443-TLS" \
    '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"ws",type:"none",host:$sni,path:"/vmess",tls:"tls",sni:$sni}' | base64 -w 0)

  local VMESS_80
  VMESS_80=$(jq -n --arg add "$PUB_IP" --arg id "$UUID" --arg sni "$SNI" --arg ps "${username}-VMess-80-WS" \
    '{v:"2",ps:$ps,add:$add,port:"80",id:$id,aid:"0",net:"ws",type:"none",host:$sni,path:"/vmess",tls:""}' | base64 -w 0)

  echo ""
  echo "=================================================================="
  echo -e " ${C}Xray User : ${username}${N} | UUID/Pass: ${Y}${UUID}${N}"
  echo -e " Server IP : ${PUB_IP} | Custom SNI/Host: ${SNI}"
  echo "=================================================================="
  echo -e " ${G}--- [PORT 443 WS TLS (DIRECT)] ---${N}"
  echo " [VLESS 443 TLS] :"
  echo " vless://${UUID}@${PUB_IP}:443?encryption=none&security=tls&sni=${SNI}&allowInsecure=1&type=ws&host=${SNI}&path=%2Fvless#${username}-VLESS-443"
  echo ""
  echo " [VMess 443 TLS] :"
  echo " vmess://${VMESS_443}"
  echo ""
  echo " [Trojan 443 TLS]:"
  echo " trojan://${UUID}@${PUB_IP}:443?security=tls&sni=${SNI}&allowInsecure=1&type=ws&host=${SNI}&path=%2Ftrojan#${username}-Trojan-443"
  echo "------------------------------------------------------------------"
  echo -e " ${G}--- [PORT 80 WS NON-TLS (DIRECT)] ---${N}"
  echo " [VLESS 80 WS]   :"
  echo " vless://${UUID}@${PUB_IP}:80?encryption=none&security=none&type=ws&host=${SNI}&path=%2Fvless#${username}-VLESS-80"
  echo ""
  echo " [VMess 80 WS]   :"
  echo " vmess://${VMESS_80}"
  echo ""
  echo " [Trojan 80 WS]  :"
  echo " trojan://${UUID}@${PUB_IP}:80?security=none&type=ws&host=${SNI}&path=%2Ftrojan#${username}-Trojan-80"

  if [ "$CF_HOST" != "None" ] && [ "$CF_HOST" != "Starting..." ] && [ -n "$CF_HOST" ]; then
    local VMESS_CF
    VMESS_CF=$(jq -n --arg add "$CF_HOST" --arg id "$UUID" --arg sni "$CF_HOST" --arg ps "${username}-CF-VMess-443" \
      '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"ws",type:"none",host:$sni,path:"/vmess",tls:"tls",sni:$sni,alpn:"http/1.1"}' | base64 -w 0)
    echo "------------------------------------------------------------------"
    echo -e " ${G}--- [CLOUDFLARED TUNNEL PORT 443 TLS (${CF_HOST})] ---${N}"
    echo " [CF VLESS 443]  :"
    echo " vless://${UUID}@${CF_HOST}:443?encryption=none&security=tls&sni=${CF_HOST}&alpn=http%2F1.1&fp=chrome&type=ws&host=${CF_HOST}&path=%2Fvless#${username}-CF-VLESS"
    echo ""
    echo " [CF VMess 443]  :"
    echo " vmess://${VMESS_CF}"
    echo ""
    echo " [CF Trojan 443] :"
    echo " trojan://${UUID}@${CF_HOST}:443?security=tls&sni=${CF_HOST}&alpn=http%2F1.1&fp=chrome&type=ws&host=${CF_HOST}&path=%2Ftrojan#${username}-CF-Trojan"
  fi
  echo "=================================================================="
}

# 1) Create SSH / WS / SSL / Cloudflared User
create_ssh_user() {
  clear
  echo -e "${C}=== Create SSH / WS / SSL / Cloudflared User ===${N}"
  read -p "Username                   : " username
  [ -z "$username" ] && return
  read -p "Password                   : " password
  read -p "Custom SNI / Bug (Optional): " custom_sni
  read -p "IP Limit (default 2)       : " iplimit
  read -p "Validity Days (default 30) : " days

  iplimit=${iplimit:-2}
  days=${days:-30}
  EXPIRY=$(date -d "+${days} days" +"%Y-%m-%d")

  userdel -f "$username" 2>/dev/null || true
  useradd -e "$EXPIRY" -M -N -s /bin/false "$username"
  echo "${username}:${password}" | chpasswd

  cat > "${USERS_DIR}/${username}.conf" <<EOF
PASSWORD=${password}
LIMIT=${iplimit}
EXPIRY=${EXPIRY}
EOF

  PUB_IP=$(curl -s4 --max-time 3 https://icanhazip.com || hostname -I | awk '{print $1}')
  DEF_SNI=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null || echo "$PUB_IP")
  SNI=${custom_sni:-$DEF_SNI}
  CF_HOST=$(get_cf_domain)

  echo ""
  echo "=================================================================="
  echo " SSH / WS / SSL Account Created"
  echo "=================================================================="
  echo " Username         : ${username}"
  echo " Password         : ${password}"
  echo " Expires On       : ${EXPIRY} (IP Limit: ${iplimit})"
  echo " Host / Server IP : ${PUB_IP}"
  echo " SNI / Bug Host   : ${SNI}"
  echo " Ports            : 80 (WS), 443 (SSL/TLS-WS), 22 (OpenSSH), 7300 (UDPGW)"
  echo "------------------------------------------------------------------"
  echo " Payload Port 80 (SSH-WS Non-TLS):"
  echo " GET / HTTP/1.1[crlf]Host: ${SNI}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
  echo "------------------------------------------------------------------"
  echo " Payload Port 443 (SSH-WS SSL/TLS):"
  echo " GET wss://${SNI}/ HTTP/1.1[crlf]Host: ${SNI}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
  if [ "$CF_HOST" != "None" ] && [ "$CF_HOST" != "Starting..." ] && [ -n "$CF_HOST" ]; then
    echo "------------------------------------------------------------------"
    echo " Cloudflared SSH-WS TLS (Port 443):"
    echo " SSH Host / SNI   : ${CF_HOST} (Port: 443 with SSL/TLS)"
    echo " CF SSH Payload   : GET / HTTP/1.1[crlf]Host: ${CF_HOST}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
  fi
  echo "=================================================================="
  read -p "Press Enter to return to menu..."
}

# 2) Delete SSH User
delete_ssh_user() {
  clear
  echo -e "${C}=== Delete SSH User ===${N}"
  ls "${USERS_DIR}" 2>/dev/null | sed 's/\.conf$//'
  echo "------------------------------------------------------------------"
  read -p "Enter Username to Delete: " username
  [ -z "$username" ] && return
  userdel -f "$username" 2>/dev/null || true
  pkill -u "$username" 2>/dev/null || true
  rm -f "${USERS_DIR}/${username}.conf"
  echo "User ${username} deleted."
  read -p "Press Enter to return..."
}

# 3) Update SSH User IP Limit / Validity
update_ssh_user() {
  clear
  echo -e "${C}=== Update SSH User IP Limit / Validity ===${N}"
  ls "${USERS_DIR}" 2>/dev/null | sed 's/\.conf$//'
  echo "------------------------------------------------------------------"
  read -p "Username          : " username
  [ ! -f "${USERS_DIR}/${username}.conf" ] && echo "User not found!" && sleep 2 && return
  read -p "New IP Limit      : " iplimit
  read -p "Extend Days (+days): " days
  EXPIRY=$(date -d "+${days:-30} days" +"%Y-%m-%d")
  chage -E "$EXPIRY" "$username" 2>/dev/null || true
  sed -i "s/^LIMIT=.*/LIMIT=${iplimit:-2}/" "${USERS_DIR}/${username}.conf"
  sed -i "s/^EXPIRY=.*/EXPIRY=${EXPIRY}/" "${USERS_DIR}/${username}.conf"
  echo "Updated ${username} -> Limit: ${iplimit:-2}, Expiry: ${EXPIRY}"
  read -p "Press Enter to return..."
}

# 4) Create Xray User (VLESS / VMess / Trojan - Port 80, 443 & Cloudflared)
create_xray_user() {
  clear
  echo -e "${C}=== Create Xray User (VLESS / VMess / Trojan - 80, 443 & CF) ===${N}"
  read -p "Username                      : " username
  [ -z "$username" ] && return
  read -p "Custom SNI (Enter for default): " custom_sni
  read -p "IP Limit (default 2)          : " iplimit
  read -p "Validity Days (default 30)    : " days

  UUID=$(cat /proc/sys/kernel/random/uuid)
  EXPIRY=$(date -d "+${days:-30} days" +"%Y-%m-%d")
  PUB_IP=$(curl -s4 --max-time 3 https://icanhazip.com || hostname -I | awk '{print $1}')
  DEF_SNI=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null || echo "$PUB_IP")
  SNI=${custom_sni:-$DEF_SNI}

  TMP_JSON=$(mktemp)
  jq --arg id "$UUID" --arg email "${username}@panel" '
    (.inbounds[].settings.clients) |= map(select(.email != $email)) |
    (.inbounds[] | select(.protocol=="vless") | .settings.clients) += [{"id": $id, "email": $email}] |
    (.inbounds[] | select(.protocol=="vmess") | .settings.clients) += [{"id": $id, "alterId": 0, "email": $email}] |
    (.inbounds[] | select(.protocol=="trojan") | .settings.clients) += [{"password": $id, "email": $email}]
  ' "${XRAY_CFG}" > "${TMP_JSON}" && mv "${TMP_JSON}" "${XRAY_CFG}"

  cat > "${XRAY_USERS_DIR}/${username}.conf" <<EOF
UUID=${UUID}
SNI=${SNI}
LIMIT=${iplimit:-2}
EXPIRY=${EXPIRY}
EOF

  systemctl restart xray
  print_xray_links "$username" "$UUID" "$SNI"
  read -p "Press Enter to return to menu..."
}

# 5) Delete Xray User
delete_xray_user() {
  clear
  echo -e "${C}=== Delete Xray User ===${N}"
  ls "${XRAY_USERS_DIR}" 2>/dev/null | sed 's/\.conf$//'
  echo "------------------------------------------------------------------"
  read -p "Username to Delete: " username
  [ -z "$username" ] && return
  TMP_JSON=$(mktemp)
  jq --arg email "${username}@panel" '
    (.inbounds[].settings.clients) |= map(select(.email != $email))
  ' "${XRAY_CFG}" > "${TMP_JSON}" && mv "${TMP_JSON}" "${XRAY_CFG}"
  rm -f "${XRAY_USERS_DIR}/${username}.conf"
  systemctl restart xray
  echo "Xray user ${username} removed."
  read -p "Press Enter to return..."
}

# 6) Update / View Xray User Links
update_xray_user() {
  clear
  echo -e "${C}=== Update or View Xray User (80 / 443 / CF Links) ===${N}"
  ls "${XRAY_USERS_DIR}" 2>/dev/null | sed 's/\.conf$//'
  echo "------------------------------------------------------------------"
  read -p "Username: " username
  [ ! -f "${XRAY_USERS_DIR}/${username}.conf" ] && echo "Not found!" && sleep 2 && return
  UUID=$(grep '^UUID=' "${XRAY_USERS_DIR}/${username}.conf" | cut -d= -f2)
  SNI=$(grep '^SNI=' "${XRAY_USERS_DIR}/${username}.conf" | cut -d= -f2)
  [ -z "$SNI" ] && SNI=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null)

  echo "1) Show All 80 / 443 / Cloudflared Links for ${username}"
  echo "2) Update IP Limit & Validity"
  read -p "Select: " uopt
  if [ "$uopt" = "1" ]; then
    print_xray_links "$username" "$UUID" "$SNI"
    read -p "Press Enter to return..."
  elif [ "$uopt" = "2" ]; then
    read -p "New IP Limit      : " iplimit
    read -p "Extend Days (+days): " days
    EXPIRY=$(date -d "+${days:-30} days" +"%Y-%m-%d")
    sed -i "s/^LIMIT=.*/LIMIT=${iplimit:-2}/" "${XRAY_USERS_DIR}/${username}.conf"
    sed -i "s/^EXPIRY=.*/EXPIRY=${EXPIRY}/" "${XRAY_USERS_DIR}/${username}.conf"
    echo "Updated Xray user ${username}."
    read -p "Press Enter to return..."
  fi
}

# 7) Show Active Connections
show_connections() {
  clear
  echo -e "${C}=== Active SSH & Xray Connections ===${N}"
  echo "--- SSH / Dropbear Sessions ---"
  ps aux | grep -E "sshd:|dropbear" | grep -v grep || echo "No active SSH sessions."
  echo ""
  echo "--- Multiplexer & Xray Listeners ---"
  ss -tulpn | grep -E ':80 |:443 |:109 |:1000'
  echo "=================================================================="
  read -p "Press Enter to return..."
}

# 8) Service Status & Port 80/443 Conflict Manager
conflict_manager() {
  clear
  echo -e "${C}=== Service Status & Port 80/443/Xray Auto-Repair ===${N}"
  echo "1) Auto-Repair All Services (Kill Port 80/443 Conflicts & Restart All)"
  echo "2) Restart SSH-WS, Dropbear, Xray & Cloudflared"
  echo "0) Back"
  read -p "Select: " copt
  if [ "$copt" = "1" ]; then
    for svc in nginx apache2 httpd caddy lighttpd; do
      systemctl stop "$svc" 2>/dev/null || true
      systemctl disable "$svc" 2>/dev/null || true
    done
    fuser -k 80/tcp 2>/dev/null || true
    fuser -k 443/tcp 2>/dev/null || true
    systemctl restart dropbear xray ssh-ws ssh-limiter cf-vless 2>/dev/null || true
    echo "All conflicts cleared and services restarted!"
    sleep 2
  elif [ "$copt" = "2" ]; then
    systemctl restart dropbear xray ssh-ws ssh-limiter cf-vless 2>/dev/null || true
    echo "Services restarted!"
    sleep 2
  fi
}

# 9) SSL Certificate & Custom SNI Manager
ssl_manager() {
  clear
  echo -e "${C}=== SSL Certificate & Default SNI Manager ===${N}"
  echo "Current Default SNI: $(cat ${PANEL_DIR}/default_sni 2>/dev/null)"
  echo "1) Change Default SNI / Bug Host"
  echo "2) Regenerate Self-Signed SSL Certificate"
  echo "0) Back"
  read -p "Select: " sopt
  if [ "$sopt" = "1" ]; then
    read -p "Enter new Default SNI / Bug Host: " newsni
    [ -n "$newsni" ] && echo "$newsni" > "${PANEL_DIR}/default_sni"
  elif [ "$sopt" = "2" ]; then
    DEF_SNI=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null || echo "localhost")
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout "${PANEL_DIR}/key.pem" -out "${PANEL_DIR}/cert.pem" \
      -subj "/C=US/ST=Cloud/L=Edge/O=SSH-Panel/CN=${DEF_SNI}"
    systemctl restart ssh-ws
  fi
}

# 10) Cloudflared Tunnel Manager
cloudflared_manager() {
  clear
  CF_HOST=$(get_cf_domain)
  echo "=================================================================="
  echo -e "   CLOUDFLARED TUNNEL MANAGER (VLESS / VMess / Trojan / SSH-WS)   "
  echo "=================================================================="
  echo -e " Tunnel Status : $(get_cf_status)"
  echo -e " Active Domain : ${Y}${CF_HOST}${N}"
  echo "------------------------------------------------------------------"
  echo " 1) Start / Refresh Free Quick Tunnel (*.trycloudflare.com)"
  echo " 2) Setup Permanent Custom Cloudflare Domain (via Tunnel Token)"
  echo " 3) Show All 80 / 443 / Cloudflared Links for Existing Xray Users"
  echo " 4) View Cloudflared Tunnel Logs (Debug)"
  echo " 5) Stop & Disable Cloudflared Tunnel"
  echo " 0) Back to Main Menu"
  echo "=================================================================="
  read -p "Select an option: " cfopt

  case $cfopt in
    1)
      systemctl disable --now cloudflared 2>/dev/null || true
      rm -f "${PANEL_DIR}/cf_custom_domain" /var/log/cloudflared.log
      CF_BIN=$(command -v cloudflared)
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
      systemctl daemon-reload
      systemctl enable --now cf-vless
      systemctl restart cf-vless
      echo "Waiting up to 15 seconds for Cloudflare to assign hostname..."
      NEW_HOST=""
      for i in {1..15}; do
        NEW_HOST=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log 2>/dev/null | tail -n 1 | sed 's|https://||')
        [ -n "$NEW_HOST" ] && break
        sleep 1
      done
      echo -e "Quick Tunnel Active! Hostname: ${G}${NEW_HOST:-Check Option 4 Logs}${N}"
      read -p "Press Enter to continue..."
      ;;
    2)
      echo "In Cloudflare Zero Trust -> Networks -> Tunnels:"
      echo "Create a tunnel pointing Public Hostname to: http://127.0.0.1:80"
      read -p "Paste your Cloudflare Tunnel Token: " cftoken
      read -p "Enter the Public Hostname you configured (e.g. vless.domain.com): " cfdomain
      if [ -n "$cftoken" ] && [ -n "$cfdomain" ]; then
        systemctl disable --now cf-vless 2>/dev/null || true
        cloudflared service uninstall 2>/dev/null || true
        cloudflared service install "$cftoken"
        systemctl enable --now cloudflared
        echo "$cfdomain" > "${PANEL_DIR}/cf_custom_domain"
        echo -e "${G}Permanent Tunnel Active on ${cfdomain}!${N}"
      fi
      read -p "Press Enter to continue..."
      ;;
    3)
      for ufile in "${XRAY_USERS_DIR}"/*.conf; do
        [ ! -f "$ufile" ] && continue
        uname=$(basename "$ufile" .conf)
        uuid=$(grep '^UUID=' "$ufile" | cut -d= -f2)
        sni=$(grep '^SNI=' "$ufile" | cut -d= -f2)
        [ -z "$sni" ] && sni=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null)
        print_xray_links "$uname" "$uuid" "$sni"
      done
      read -p "Press Enter to continue..."
      ;;
    4)
      echo "--- /var/log/cloudflared.log ---"
      tail -n 35 /var/log/cloudflared.log 2>/dev/null || journalctl -u cf-vless -n 35 --no-pager
      read -p "Press Enter to continue..."
      ;;
    5)
      systemctl disable --now cf-vless 2>/dev/null || true
      systemctl disable --now cloudflared 2>/dev/null || true
      echo "Cloudflared tunnel stopped."
      sleep 1
      ;;
  esac
}

# 11) Uninstall SSH-Panel Completely
uninstall_panel() {
  clear
  echo -e "${R}==================================================================${N}"
  echo -e "${R}             UNINSTALL SSH-PANEL COMPLETELY                       ${N}"
  echo -e "${R}==================================================================${N}"
  read -p "Are you sure you want to completely uninstall SSH-Panel? (y/N): " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Uninstall cancelled."
    sleep 1
    return
  fi

  echo "Stopping and removing services..."
  for svc in ssh-ws ssh-limiter cf-vless badvpn xray; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/${svc}.service"
  done

  cloudflared service uninstall 2>/dev/null || true
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove 2>/dev/null || true

  rm -rf "${PANEL_DIR}" /usr/local/etc/xray /var/log/xray /var/log/cloudflared.log /usr/local/bin/badvpn-udpgw /usr/local/bin/menu
  systemctl daemon-reload

  echo -e "${G}SSH-Panel has been completely uninstalled from your server.${N}"
  exit 0
}

# Main Loop
while true; do
  clear
  OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
  PUB_IP=$(curl -s4 --max-time 2 https://icanhazip.com || hostname -I | awk '{print $1}')
  DEF_SNI=$(cat "${PANEL_DIR}/default_sni" 2>/dev/null || echo "$PUB_IP")
  CF_HOST=$(get_cf_domain)

  echo "=================================================================="
  echo -e "  OS           : ${G}${OS_NAME}${N}"
  echo -e "  Host / IP    : ${C}${PUB_IP}${N}   | Default SNI: ${C}${DEF_SNI}${N}"
  echo -e "  SSH-WS (80)  : $(get_status ssh-ws)   | Xray-core : $(get_status xray)"
  echo -e "  Dropbear     : $(get_status dropbear)   | BadVPN 7300: $(get_status badvpn)"
  echo -e "  IP Limiter   : $(get_status ssh-limiter)   | OpenSSH    : $(get_status ssh)"
  echo -e "  Cloudflared  : $(get_cf_status)   | CF Host: ${Y}${CF_HOST}${N}"
  echo -e "  Port 80 Mode : ${C}Shared Multiplex (SSH-WS + Xray WS/TCP)${N}"
  echo -e "  Port 443 Mode: ${C}Shared Multiplex (SSH-WS + Xray WS/TCP)${N}"
  echo "------------------------------------------------------------------"
  echo -e "  ${C}[SSH / SSH-WS / SSL-WS Management]${N}"
  echo "    1) Create SSH / WS / SSL User (Custom Payload 80 & Custom SNI 443)"
  echo "    2) Delete SSH User"
  echo "    3) Update SSH User IP Limit / Validity"
  echo ""
  echo -e "  ${C}[Xray Management (VLESS, VMess, Trojan - 443 & 80 WS/TCP + CF)]${N}"
  echo "    4) Create Xray User (VLESS / VMess / Trojan - 80, 443 & CF)"
  echo "    5) Delete Xray User"
  echo "    6) View Links / Update Xray User IP Limit & Validity"
  echo ""
  echo -e "  ${C}[Monitoring, Port Modes, Custom SNI & Cloudflared]${N}"
  echo "    7) Show Active Connections & Per-User IP Usage"
  echo "    8) Service Status & Port 80/443 Conflict Manager"
  echo "    9) SSL Certificate & Custom SNI Manager"
  echo "   10) Cloudflared Tunnel Manager (Port 443 TLS for Xray & SSH-WS)"
  echo -e "   ${R}11) Uninstall SSH-Panel Completely${N}"
  echo "    0) Exit"
  echo "=================================================================="
  read -p "Select an option [0-11]: " opt

  case $opt in
    1) create_ssh_user ;;
    2) delete_ssh_user ;;
    3) update_ssh_user ;;
    4) create_xray_user ;;
    5) delete_xray_user ;;
    6) update_xray_user ;;
    7) show_connections ;;
    8) conflict_manager ;;
    9) ssl_manager ;;
    10) cloudflared_manager ;;
    11) uninstall_panel ;;
    0) exit 0 ;;
  esac
done
