#!/usr/bin/env bash
# =============================================================================
# VPS Management Panel CLI (`menu`) for Debian & Ubuntu
# Supports:
#   - SSH & SSH-WS (Port 80 Custom Payload) & SSH-SSL (Port 443 All TLS 1.0-1.3)
#   - Xray-core (VLESS, VMess, Trojan over WebSocket & TCP on Ports 443 & 80)
#   - BadVPN UDPGW (Port 7300)
#   - User Validity (Days), Expiration Cron, User Deletion, Per-User IP Limiter
#   - Service Status Monitor & Port Conflict / Exclusive Mode Switcher
# =============================================================================

set -u

CONFIG_DIR="/etc/vps-panel"
SSH_DB="${CONFIG_DIR}/ssh-users.db"
XRAY_DB="${CONFIG_DIR}/xray-users.db"
PORT_MODE_FILE="${CONFIG_DIR}/port_mode.conf"
DOMAIN_FILE="${CONFIG_DIR}/domain"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
CERT_FILE="${CONFIG_DIR}/ssl/fullchain.pem"
KEY_FILE="${CONFIG_DIR}/ssl/privkey.pem"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

mkdir -p "${CONFIG_DIR}"
touch "${SSH_DB}" "${XRAY_DB}"

get_host() {
    if [[ -s "${DOMAIN_FILE}" ]]; then
        cat "${DOMAIN_FILE}"
    else
        curl -fsSL4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}'
    fi
}

svc_badge() {
    local svc="$1"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "${GREEN}[ACTIVE]${NC}"
    else
        echo -e "${RED}[INACTIVE]${NC}"
    fi
}

get_port_mode_label() {
    local key="$1"
    local val="shared"
    if [[ -f "${PORT_MODE_FILE}" ]]; then
        val=$(grep -E "^${key}=" "${PORT_MODE_FILE}" | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "shared")
    fi
    case "${val}" in
        shared)    echo -e "${GREEN}Shared Multiplex (SSH-WS + Xray WS/TCP)${NC}" ;;
        ssh_only)  echo -e "${YELLOW}SSH-WS Exclusive (Xray Disabled on Port)${NC}" ;;
        xray_only) echo -e "${CYAN}Xray Exclusive (SSH-WS Disabled on Port)${NC}" ;;
        off)       echo -e "${RED}Disabled (Port Closed)${NC}" ;;
        *)         echo -e "${GREEN}Shared Multiplex${NC}" ;;
    esac
}

# -----------------------------------------------------------------------------
# SSH User Management
# -----------------------------------------------------------------------------
create_ssh_user() {
    echo -e "\n${CYAN}--- Create SSH / SSH-WS / SSL User ---${NC}"
    read -rp "Username: " uname
    if [[ -z "${uname}" ]]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        return
    fi
    if id "${uname}" &>/dev/null; then
        echo -e "${RED}User '${uname}' already exists!${NC}"
        return
    fi
    read -rp "Password: " upass
    read -rp "Validity (days, e.g. 30): " days
    read -rp "Max Concurrent IPs (e.g. 2): " max_ip

    days=${days:-30}
    max_ip=${max_ip:-2}
    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")

    useradd -e "${exp_date}" -s /bin/false -M "${uname}"
    echo "${uname}:${upass}" | chpasswd

    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo "${uname}|${upass}|${exp_date}|${max_ip}" >> "${SSH_DB}"

    local host
    host=$(get_host)
    echo -e "\n${GREEN}=== SSH / WebSocket Account Created ===${NC}"
    echo -e "Host / IP          : ${host}"
    echo -e "Username           : ${uname}"
    echo -e "Password           : ${upass}"
    echo -e "Expires On         : ${exp_date} (${days} days)"
    echo -e "Max IP Limit       : ${max_ip} IP(s)"
    echo -e "OpenSSH Port       : 22"
    echo -e "Dropbear Port      : 109"
    echo -e "SSH WS (HTTP) Port : 80 (Supports any custom payload)"
    echo -e "SSH SSL/WS Port    : 443 (Supports TLS 1.0, 1.1, 1.2, 1.3)"
    echo -e "BadVPN UDPGW Port  : 7300"
    echo -e "Sample Payload     : GET / HTTP/1.1[crlf]Host: ${host}[crlf]Upgrade: websocket[crlf][crlf]"
}

delete_ssh_user() {
    echo -e "\n${CYAN}--- Delete SSH User ---${NC}"
    if [[ ! -s "${SSH_DB}" ]]; then
        echo -e "${YELLOW}No SSH users found.${NC}"
        return
    fi
    nl -w2 -s'. ' "${SSH_DB}" | awk -F'|' '{printf "%s %-16s (Expires: %s, Max IP: %s)\n", $1, $2, $3, $4}'
    read -rp "Enter username to delete: " uname
    if [[ -z "${uname}" ]]; then return; fi

    pkill -9 -u "${uname}" 2>/dev/null || true
    userdel -f "${uname}" 2>/dev/null || true
    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo -e "${GREEN}SSH user '${uname}' deleted.${NC}"
}

update_ssh_ip_limit() {
    echo -e "\n${CYAN}--- Update SSH User IP Limit / Validity ---${NC}"
    read -rp "Enter SSH username: " uname
    if ! grep -q "^${uname}|" "${SSH_DB}"; then
        echo -e "${RED}User '${uname}' not found in SSH database.${NC}"
        return
    fi
    read -rp "New Max Concurrent IPs (e.g. 2): " max_ip
    read -rp "Extend validity by days from today (leave blank to keep current): " days

    local line pass cur_exp
    line=$(grep "^${uname}|" "${SSH_DB}" | head -n1)
    pass=$(echo "${line}" | cut -d'|' -f2)
    cur_exp=$(echo "${line}" | cut -d'|' -f3)

    if [[ -n "${days}" ]]; then
        cur_exp=$(date -d "+${days} days" +"%Y-%m-%d")
        chage -E "${cur_exp}" "${uname}" 2>/dev/null || true
    fi
    max_ip=${max_ip:-2}
    sed -i "/^${uname}|/d" "${SSH_DB}"
    echo "${uname}|${pass}|${cur_exp}|${max_ip}" >> "${SSH_DB}"
    echo -e "${GREEN}Updated '${uname}': Expires=${cur_exp}, Max IP=${max_ip}.${NC}"
}

# -----------------------------------------------------------------------------
# Xray User Management (VLESS, VMess, Trojan - Port 443 & 80 WS & TCP)
# -----------------------------------------------------------------------------
create_xray_user() {
    echo -e "\n${CYAN}--- Create Xray User (VLESS / VMess / Trojan on Port 443 & 80 WS + TCP) ---${NC}"
    read -rp "Username: " uname
    if [[ -z "${uname}" ]]; then
        echo -e "${RED}Username cannot be empty.${NC}"
        return
    fi
    if grep -q "^${uname}|" "${XRAY_DB}"; then
        echo -e "${RED}Xray user '${uname}' already exists!${NC}"
        return
    fi
    echo "Select Protocol:"
    echo "  1) VLESS (WS + TCP on 443 & 80)"
    echo "  2) VMess (WS + TCP on 443 & 80)"
    echo "  3) Trojan (WS + TCP on 443 & 80)"
    echo "  4) All Three (VLESS + VMess + Trojan)"
    read -rp "Choice [1-4]: " pchoice
    read -rp "Validity (days, e.g. 30): " days
    read -rp "Max Concurrent IPs (e.g. 2): " max_ip

    days=${days:-30}
    max_ip=${max_ip:-2}
    exp_date=$(date -d "+${days} days" +"%Y-%m-%d")
    uuid=$(cat /proc/sys/kernel/random/uuid)

    local proto="all"
    case "${pchoice}" in
        1) proto="vless" ;;
        2) proto="vmess" ;;
        3) proto="trojan" ;;
        *) proto="all" ;;
    esac

    if [[ -f "${XRAY_CONFIG}" ]]; then
        local tmp_json
        tmp_json=$(mktemp)
        cp "${XRAY_CONFIG}" "${tmp_json}"

        if [[ "${proto}" == "vless" || "${proto}" == "all" ]]; then
            jq --arg id "${uuid}" --arg email "${uname}@vless" \
               '(.inbounds[] | select(.tag=="vless-ws" or .tag=="vless-tcp") | .settings.clients) += [{"id": $id, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi
        if [[ "${proto}" == "vmess" || "${proto}" == "all" ]]; then
            jq --arg id "${uuid}" --arg email "${uname}@vmess" \
               '(.inbounds[] | select(.tag=="vmess-ws" or .tag=="vmess-tcp") | .settings.clients) += [{"id": $id, "alterId": 0, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi
        if [[ "${proto}" == "trojan" || "${proto}" == "all" ]]; then
            jq --arg pw "${uuid}" --arg email "${uname}@trojan" \
               '(.inbounds[] | select(.tag=="trojan-ws" or .tag=="trojan-tcp") | .settings.clients) += [{"password": $pw, "email": $email}]' \
               "${tmp_json}" > "${tmp_json}.2" && mv "${tmp_json}.2" "${tmp_json}"
        fi

        mv "${tmp_json}" "${XRAY_CONFIG}"
        systemctl restart xray 2>/dev/null || true
    fi

    echo "${uname}|${proto}|${uuid}|${exp_date}|${max_ip}" >> "${XRAY_DB}"

    local host
    host=$(get_host)
    echo -e "\n${GREEN}=== Xray Account Created ===${NC}"
    echo -e "Username     : ${uname}"
    echo -e "Protocol(s)  : ${proto^^}"
    echo -e "UUID / Pass  : ${uuid}"
    echo -e "Host / SNI   : ${host}"
    echo -e "Expires On   : ${exp_date} (${days} days)"
    echo -e "Max IP Limit : ${max_ip} IP(s)"
    echo -e "Ports        : 443 (TLS) & 80 (Non-TLS) [WS & TCP]"

    if [[ "${proto}" == "vless" || "${proto}" == "all" ]]; then
        echo -e "\n${YELLOW}[VLESS Links]${NC}"
        echo "VLESS WS TLS (443)  : vless://${uuid}@${host}:443?encryption=none&security=tls&type=ws&host=${host}&path=%2Fvless&sni=${host}#${uname}-VLESS-WS-443"
        echo "VLESS WS HTTP (80)  : vless://${uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=%2Fvless#${uname}-VLESS-WS-80"
        echo "VLESS TCP TLS (443) : vless://${uuid}@${host}:443?encryption=none&security=tls&type=tcp&sni=${host}#${uname}-VLESS-TCP-443"
        echo "VLESS TCP HTTP (80) : vless://${uuid}@${host}:80?encryption=none&security=none&type=tcp#${uname}-VLESS-TCP-80"
    fi

    if [[ "${proto}" == "vmess" || "${proto}" == "all" ]]; then
        local vmess_ws_443 vmess_ws_80 vmess_tcp_443 vmess_tcp_80
        vmess_ws_443=$(jq -n --arg ps "${uname}-VMESS-WS-443" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"ws",type:"none",host:$add,path:"/vmess",tls:"tls",sni:$add}' | base64 -w0)
        vmess_ws_80=$(jq -n --arg ps "${uname}-VMESS-WS-80" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"80",id:$id,aid:"0",net:"ws",type:"none",host:$add,path:"/vmess",tls:"none"}' | base64 -w0)
        vmess_tcp_443=$(jq -n --arg ps "${uname}-VMESS-TCP-443" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"443",id:$id,aid:"0",net:"tcp",type:"none",host:$add,tls:"tls",sni:$add}' | base64 -w0)
        vmess_tcp_80=$(jq -n --arg ps "${uname}-VMESS-TCP-80" --arg add "${host}" --arg id "${uuid}" \
            '{v:"2",ps:$ps,add:$add,port:"80",id:$id,aid:"0",net:"tcp",type:"none",host:$add,tls:"none"}' | base64 -w0)
        echo -e "\n${YELLOW}[VMess Links]${NC}"
        echo "VMess WS TLS (443)  : vmess://${vmess_ws_443}"
        echo "VMess WS HTTP (80)  : vmess://${vmess_ws_80}"
        echo "VMess TCP TLS (443) : vmess://${vmess_tcp_443}"
        echo "VMess TCP HTTP (80) : vmess://${vmess_tcp_80}"
    fi

    if [[ "${proto}" == "trojan" || "${proto}" == "all" ]]; then
        echo -e "\n${YELLOW}[Trojan Links]${NC}"
        echo "Trojan WS TLS (443)  : trojan://${uuid}@${host}:443?security=tls&type=ws&host=${host}&path=%2Ftrojan&sni=${host}#${uname}-TROJAN-WS-443"
        echo "Trojan WS HTTP (80)  : trojan://${uuid}@${host}:80?security=none&type=ws&host=${host}&path=%2Ftrojan#${uname}-TROJAN-WS-80"
        echo "Trojan TCP TLS (443) : trojan://${uuid}@${host}:443?security=tls&type=tcp&sni=${host}#${uname}-TROJAN-TCP-443"
        echo "Trojan TCP HTTP (80) : trojan://${uuid}@${host}:80?security=none&type=tcp#${uname}-TROJAN-TCP-80"
    fi
}

delete_xray_user() {
    echo -e "\n${CYAN}--- Delete Xray User ---${NC}"
    if [[ ! -s "${XRAY_DB}" ]]; then
        echo -e "${YELLOW}No Xray users found.${NC}"
        return
    fi
    nl -w2 -s'. ' "${XRAY_DB}" | awk -F'|' '{printf "%s %-16s [%-6s] (Expires: %s, Max IP: %s)\n", $1, $2, $3, $4, $5}'
    read -rp "Enter Xray username to delete: " uname
    if [[ -z "${uname}" ]]; then return; fi

    if [[ -f "${XRAY_CONFIG}" ]]; then
        local tmp_json
        tmp_json=$(mktemp)
        jq --arg u1 "${uname}@vless" --arg u2 "${uname}@vmess" --arg u3 "${uname}@trojan" \
           '(.inbounds[].settings.clients) |= map(select(.email != $u1 and .email != $u2 and .email != $u3))' \
           "${XRAY_CONFIG}" > "${tmp_json}" && mv "${tmp_json}" "${XRAY_CONFIG}"
        systemctl restart xray 2>/dev/null || true
    fi
    sed -i "/^${uname}|/d" "${XRAY_DB}"
    echo -e "${GREEN}Xray user '${uname}' deleted.${NC}"
}

update_xray_ip_limit() {
    echo -e "\n${CYAN}--- Update Xray User IP Limit / Validity ---${NC}"
    read -rp "Enter Xray username: " uname
    if ! grep -q "^${uname}|" "${XRAY_DB}"; then
        echo -e "${RED}User '${uname}' not found in Xray database.${NC}"
        return
    fi
    read -rp "New Max Concurrent IPs (e.g. 2): " max_ip
    read -rp "Extend validity by days from today (leave blank to keep current): " days

    local line proto secret cur_exp
    line=$(grep "^${uname}|" "${XRAY_DB}" | head -n1)
    proto=$(echo "${line}" | cut -d'|' -f2)
    secret=$(echo "${line}" | cut -d'|' -f3)
    cur_exp=$(echo "${line}" | cut -d'|' -f4)

    if [[ -n "${days}" ]]; then
        cur_exp=$(date -d "+${days} days" +"%Y-%m-%d")
    fi
    max_ip=${max_ip:-2}
    sed -i "/^${uname}|/d" "${XRAY_DB}"
    echo "${uname}|${proto}|${secret}|${cur_exp}|${max_ip}" >> "${XRAY_DB}"
    echo -e "${GREEN}Updated '${uname}': Expires=${cur_exp}, Max IP=${max_ip}.${NC}"
}

# -----------------------------------------------------------------------------
# Service Status & Port Mode / Deactivation Manager
# -----------------------------------------------------------------------------
service_and_port_menu() {
    while true; do
        echo -e "\n${CYAN}============================================================${NC}"
        echo -e "${CYAN}         Service Status & Port Deactivation Manager         ${NC}"
        echo -e "${CYAN}============================================================${NC}"
        echo -e "  OpenSSH (Port 22)          : $(svc_badge ssh)"
        echo -e "  Dropbear SSH (Port 109)    : $(svc_badge dropbear)"
        echo -e "  SSH-WS & Multiplexer (80/443): $(svc_badge ssh-ws)"
        echo -e "  Xray-core (VLESS/VMess/Trojan): $(svc_badge xray)"
        echo -e "  BadVPN UDPGW (Port 7300)   : $(svc_badge badvpn-udpgw)"
        echo -e "  Nginx (ACME / Web)         : $(svc_badge nginx)"
        echo -e "  IP & Conn Limiter Daemon   : $(svc_badge vps-limiter)"
        echo -e "------------------------------------------------------------"
        echo -e "  Port 80 Mode  : $(get_port_mode_label PORT_80_MODE)"
        echo -e "  Port 443 Mode : $(get_port_mode_label PORT_443_MODE)"
        echo -e "------------------------------------------------------------"
        echo "  1) Set Port 80 to SHARED Mode (SSH-WS + Xray WS/TCP)"
        echo "  2) Set Port 80 to SSH-WS EXCLUSIVE (Disable Xray on Port 80)"
        echo "  3) Set Port 80 to XRAY EXCLUSIVE (Disable SSH-WS on Port 80)"
        echo "  4) Set Port 443 to SHARED Mode (SSH-SSL/WS + Xray TLS WS/TCP)"
        echo "  5) Set Port 443 to SSH-SSL/WS EXCLUSIVE (Disable Xray on Port 443)"
        echo "  6) Set Port 443 to XRAY EXCLUSIVE (Disable SSH-SSL/WS on Port 443)"
        echo "  7) Stop / Disable an Individual Service (xray, ssh-ws, dropbear, badvpn-udpgw)"
        echo "  8) Start / Enable an Individual Service"
        echo "  0) Back to Main Menu"
        read -rp "Select option: " sopt

        local p80 p443
        p80=$(grep -E "^PORT_80_MODE=" "${PORT_MODE_FILE}" 2>/dev/null | cut -d'=' -f2 || echo "shared")
        p443=$(grep -E "^PORT_443_MODE=" "${PORT_MODE_FILE}" 2>/dev/null | cut -d'=' -f2 || echo "shared")

        case "${sopt}" in
            1) p80="shared" ;;
            2) p80="ssh_only" ;;
            3) p80="xray_only" ;;
            4) p443="shared" ;;
            5) p443="ssh_only" ;;
            6) p443="xray_only" ;;
            7)
                read -rp "Enter service name to stop/disable (xray / ssh-ws / dropbear / badvpn-udpgw / vps-limiter): " tsvc
                systemctl stop "${tsvc}" 2>/dev/null && systemctl disable "${tsvc}" 2>/dev/null
                echo -e "${YELLOW}Service '${tsvc}' stopped and disabled.${NC}"
                continue
                ;;
            8)
                read -rp "Enter service name to start/enable (xray / ssh-ws / dropbear / badvpn-udpgw / vps-limiter): " tsvc
                systemctl enable "${tsvc}" 2>/dev/null && systemctl restart "${tsvc}" 2>/dev/null
                echo -e "${GREEN}Service '${tsvc}' enabled and started.${NC}"
                continue
                ;;
            0) break ;;
            *) continue ;;
        esac

        cat > "${PORT_MODE_FILE}" <<EOF
PORT_80_MODE=${p80}
PORT_443_MODE=${p443}
EOF
        systemctl restart ssh-ws 2>/dev/null || true
        echo -e "${GREEN}Port routing mode updated and applied cleanly!${NC}"
    done
}

# -----------------------------------------------------------------------------
# SSL Certificate Manager (Domain Let's Encrypt OR IP Self-Signed)
# -----------------------------------------------------------------------------
ssl_menu() {
    echo -e "\n${CYAN}--- SSL Certificate Setup (Domain Let's Encrypt or IP Self-Signed) ---${NC}"
    echo "  1) Issue Free Let's Encrypt Certificate for a Domain (via acme.sh)"
    echo "  2) Generate Self-Signed Certificate for VPS IP (No Domain Needed)"
    echo "  0) Back"
    read -rp "Select option: " copt
    mkdir -p "${CONFIG_DIR}/ssl"
    case "${copt}" in
        1)
            read -rp "Enter your domain name (pointing to this VPS IP): " dom
            if [[ -z "${dom}" ]]; then return; fi
            echo "${dom}" > "${DOMAIN_FILE}"
            systemctl start nginx 2>/dev/null || true
            if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
                curl -fsSL https://get.acme.sh | sh -s email="admin@${dom}"
            fi
            "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt
            "$HOME/.acme.sh/acme.sh" --issue -d "${dom}" --webroot /var/www/html --keylength ec-256 --force
            "$HOME/.acme.sh/acme.sh" --install-cert -d "${dom}" --ecc \
                --fullchain-file "${CERT_FILE}" \
                --key-file "${KEY_FILE}"
            chmod 600 "${KEY_FILE}"
            systemctl restart ssh-ws xray 2>/dev/null || true
            echo -e "${GREEN}Let's Encrypt SSL certificate installed for ${dom}!${NC}"
            ;;
        2)
            local vip
            vip=$(curl -fsSL4 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
            rm -f "${DOMAIN_FILE}"
            openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${vip}" \
                -addext "subjectAltName=IP:${vip}" 2>/dev/null || \
            openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=Cloud/L=VPS/O=VPS-Panel/CN=${vip}"
            chmod 600 "${KEY_FILE}"
            systemctl restart ssh-ws xray 2>/dev/null || true
            echo -e "${GREEN}Self-signed IP certificate generated for ${vip} (TLS 1.0-1.3 supported)!${NC}"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Main Interactive CLI Loop
# -----------------------------------------------------------------------------
main_menu() {
    while true; do
        local host os_name
        host=$(get_host)
        os_name=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)

        echo -e "\n${BLUE}============================================================${NC}"
        echo -e "${CYAN}         DEBIAN / UBUNTU VPS MANAGEMENT PANEL (CLI)         ${NC}"
        echo -e "${BLUE}============================================================${NC}"
        echo -e "  OS           : ${os_name}"
        echo -e "  Host / IP    : ${host}"
        echo -e "  SSH-WS (80)  : $(svc_badge ssh-ws)   | Xray-core : $(svc_badge xray)"
        echo -e "  Dropbear     : $(svc_badge dropbear)   | BadVPN 7300: $(svc_badge badvpn-udpgw)"
        echo -e "  IP Limiter   : $(svc_badge vps-limiter)   | OpenSSH   : $(svc_badge ssh)"
        echo -e "  Port 80 Mode : $(get_port_mode_label PORT_80_MODE)"
        echo -e "  Port 443 Mode: $(get_port_mode_label PORT_443_MODE)"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        echo "  [SSH / SSH-WS / SSL-WS Management]"
        echo "    1) Create SSH / WS / SSL User (Custom Payload 80 & SSL 443)"
        echo "    2) Delete SSH User"
        echo "    3) Update SSH User IP Limit / Validity"
        echo ""
        echo "  [Xray Management (VLESS, VMess, Trojan - 443 & 80 WS/TCP)]"
        echo "    4) Create Xray User (VLESS / VMess / Trojan)"
        echo "    5) Delete Xray User"
        echo "    6) Update Xray User IP Limit / Validity"
        echo ""
        echo "  [Monitoring, Port Modes & SSL]"
        echo "    7) Show Active Connections & Per-User IP Usage"
        echo "    8) Service Status & Port 80/443 Conflict Manager"
        echo "    9) SSL Certificate Manager (Domain Let's Encrypt / IP Self-Signed)"
        echo "   10) Run Expired Account Cleanup Now"
        echo "    0) Exit"
        echo -e "${BLUE}------------------------------------------------------------${NC}"
        read -rp "Select an option [0-10]: " opt

        case "${opt}" in
            1) create_ssh_user ;;
            2) delete_ssh_user ;;
            3) update_ssh_ip_limit ;;
            4) create_xray_user ;;
            5) delete_xray_user ;;
            6) update_xray_ip_limit ;;
            7) python3 /usr/local/share/vps-panel/limiter.py --status ;;
            8) service_and_port_menu ;;
            9) ssl_menu ;;
            10) /usr/local/bin/xp-vps && echo -e "${GREEN}Expired users cleaned up.${NC}" ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid selection.${NC}" ;;
        esac
    done
}

main_menu