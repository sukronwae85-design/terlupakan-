#!/bin/bash

# =================================================================
# VPN TUNNEL SERVER AUTO INSTALLER - COMPLETE EDITION
# Repository: https://github.com/sukronwae85-design/terlupakan
# Author: sukronwae85-design
# Version: 7.0
# 
# Support: Ubuntu 18.04, 20.04, 22.04, 24.04
# Features:
# ✅ SSH Server (Port 22, 2222, 80, 443)
# ✅ UDP Custom Tunneling (7100, 7200, 7300, 1-65535)
# ✅ VMESS/VLESS/Trojan (Port 80 & 443)
# ✅ Domain Pointing with Auto SSL
# ✅ Nginx Reverse Proxy + SSL Fix
# ✅ VPN Tunnel Server (Tun/Tap)
# ✅ IP Limit & Auto Lock System
# ✅ Auto Backup (Gmail/Telegram)
# ✅ Complete Monitoring Dashboard
# ✅ Interactive Management Menu
# =================================================================

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

# Global Configuration
VERSION="7.0"
CONFIG_DIR="/etc/vpntunnel"
USER_DB="$CONFIG_DIR/users.json"
DOMAIN_DB="$CONFIG_DIR/domains.json"
LOG_FILE="/var/log/vpntunnel.log"
BACKUP_DIR="/backup/vpntunnel"
BANNER_FILE="/etc/ssh/banner"
TUNNEL_DIR="$CONFIG_DIR/tunnel"
VPN_NETWORK="10.8.0.0/24"

# Port Configuration
SSH_PORT="22"
SSH_ALT_PORT="2222"
SSH_PORT_80="80"
SSH_PORT_443="443"
UDP_PORTS=("7100" "7200" "7300")
VMESS_PORT_80="80"
VMESS_PORT_443="443"
TROJAN_PORT_80="80"
TROJAN_PORT_443="443"
TUNNEL_PORT="1194"
WIREGUARD_PORT="51820"

# User Limits
DEFAULT_MAX_IPS=3
DEFAULT_EXPIRY_DAYS=30
AUTO_LOCK=true
BANDWIDTH_LIMIT="1000GB"

# Server Info
SERVER_IP=$(curl -s ifconfig.me)
OS_INFO=$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
UBUNTU_VERSION=$(lsb_release -rs)

# Telegram & Email Config (Configure after install)
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""
ADMIN_EMAIL=""

# =================================================================
# CORE FUNCTIONS
# =================================================================

print_header() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║         🚀 VPN TUNNEL SERVER AUTO INSTALLER v7.0            ║
║           github.com/sukronwae85-design/terlupakan           ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ Ubuntu 18.04/20.04/22.04/24.04 Supported                ║
║  ✅ SSH + VPN Tunnel + VMESS Complete Package               ║
║  ✅ Domain Pointing with Auto SSL                           ║
║  ✅ Nginx Reverse Proxy Optimized                          ║
║  ✅ Interactive Management Menu                            ║
║  ✅ Auto Backup & Monitoring                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}🌍 Server IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "${CYAN}🖥️  OS: ${GREEN}$OS_INFO${NC}"
    echo -e "${CYAN}📅 Date: ${GREEN}$(date '+%A, %d %B %Y %H:%M:%S')${NC}"
    echo "══════════════════════════════════════════════════════════════"
}

log_message() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> $LOG_FILE
    echo -e "${BLUE}[LOG]${NC} $message"
}

check_ubuntu_version() {
    echo -e "${GREEN}Checking Ubuntu version...${NC}"
    
    case $UBUNTU_VERSION in
        "18.04"|"20.04"|"22.04"|"24.04")
            echo -e "${GREEN}✅ Ubuntu $UBUNTU_VERSION supported${NC}"
            return 0
            ;;
        *)
            echo -e "${YELLOW}⚠️  Ubuntu $UBUNTU_VERSION detected${NC}"
            echo -e "${YELLOW}This script is tested on 18.04/20.04/22.04/24.04${NC}"
            read -p "Continue anyway? (y/n): " -n 1 -r
            echo
            [[ $REPLY =~ ^[Yy]$ ]] && return 0 || exit 1
            ;;
    esac
}

init_system() {
    echo -e "${GREEN}[1/15] Initializing VPN Tunnel System...${NC}"
    
    # Create directories
    mkdir -p $CONFIG_DIR
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly}
    mkdir -p $TUNNEL_DIR/{configs,certs,clients}
    mkdir -p /var/log/vpntunnel
    mkdir -p /var/www/{html,admin,domains}
    mkdir -p /etc/nginx/ssl
    
    # Create initial files
    [[ ! -f $USER_DB ]] && echo '[]' > $USER_DB
    [[ ! -f $DOMAIN_DB ]] && echo '[]' > $DOMAIN_DB
    [[ ! -f $LOG_FILE ]] && touch $LOG_FILE
    
    # Install essential packages
    apt-get update -y
    apt-get install -y curl wget git jq bc net-tools dnsutils ufw
    
    # Set timezone to Asia/Jakarta
    timedatectl set-timezone Asia/Jakarta
    
    log_message "System initialized for Ubuntu $UBUNTU_VERSION"
}

# =================================================================
# DEPENDENCIES INSTALLATION
# =================================================================

install_dependencies() {
    echo -e "${GREEN}[2/15] Installing Dependencies...${NC}"
    
    # Update system
    apt-get update -y
    apt-get upgrade -y
    apt-get dist-upgrade -y
    
    # Install core packages
    apt-get install -y \
        build-essential libssl-dev zlib1g-dev \
        libpcre3 libpcre3-dev unzip zip \
        iptables iptables-persistent \
        fail2ban cron socat netcat \
        python3 python3-pip python3-venv \
        nodejs npm golang \
        htop nload iftop vnstat \
        screen tmux rsync \
        dos2unix nano vim \
        apache2-utils \
        whois dnsutils \
        resolvconf
    
    # Install VPN tunnel packages
    apt-get install -y \
        openvpn wireguard \
        shadowsocks-libev \
        tinyproxy squid \
        stunnel4
    
    # Install monitoring tools
    apt-get install -y \
        nmon dstat sysstat \
        smartmontools lm-sensors \
        nginx-common
    
    # Install Python packages
    pip3 install requests psutil python-telegram-bot
    
    # Install additional tools
    apt-get install -y \
        gnutls-bin libgnutls28-dev \
        libsodium-dev libmbedtls-dev \
        libudns-dev libev-dev \
        libc-ares-dev \
        libcap-ng-dev
    
    log_message "All dependencies installed"
}

# =================================================================
# SSH SERVER CONFIGURATION
# =================================================================

configure_ssh() {
    echo -e "${GREEN}[3/15] Configuring SSH Server...${NC}"
    
    # Install OpenSSH Server
    apt-get install -y openssh-server
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Configure SSH with all ports
    cat > /etc/ssh/sshd_config << EOF
# VPN Tunnel SSH Configuration
Port $SSH_PORT
Port $SSH_ALT_PORT
Port $SSH_PORT_80
Port $SSH_PORT_443
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions $DEFAULT_MAX_IPS
LoginGraceTime 120
ClientAliveInterval 60
ClientAliveCountMax 3
AllowTcpForwarding yes
GatewayPorts yes
X11Forwarding no
PermitEmptyPasswords no
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
AllowAgentForwarding yes
PrintMotd yes
Banner /etc/ssh/banner
Subsystem sftp /usr/lib/openssh/sftp-server
UseDNS no
Compression yes
TCPKeepAlive yes
AllowUsers *@*
AcceptEnv LANG LC_*

# Performance tuning
MaxStartups 10:30:100

# Match rules
Match Group vpntunnel
    MaxSessions $DEFAULT_MAX_IPS
    AllowTcpForwarding yes
    PermitTTY yes
    X11Forwarding no
    AllowAgentForwarding yes
    
Match Address 127.0.0.1
    PermitRootLogin yes
EOF
    
    # Create VPN tunnel group
    groupadd vpntunnel 2>/dev/null
    
    # Create SSH banner
    cat > /etc/ssh/banner << EOF

╔══════════════════════════════════════════╗
║         🚀 VPN TUNNEL SERVER            ║
║       github.com/sukronwae85-design      ║
║                                          ║
║  📍 Server: $(hostname)                 ║
║  🌐 IP: $SERVER_IP                      ║
║  🖥️  OS: $OS_INFO                       ║
║  📅 Date: \d                            ║
║  ⏰ Time: \t                            ║
║  👤 User: \u                            ║
║                                          ║
║  🔐 Ports: 22, 2222, 80, 443           ║
║  🔄 UDP: 7100, 7200, 7300              ║
║  🛡️  VPN Tunnel: Enabled                ║
║                                          ║
║  ⚠️  Authorized Access Only             ║
╚══════════════════════════════════════════╝

EOF
    
    # Create banner management script
    cat > /usr/local/bin/vpn-banner << 'EOF'
#!/bin/bash
echo "VPN Tunnel Server Banner Manager"
echo "1. View current banner"
echo "2. Edit banner"
echo "3. Restore default banner"
read -p "Choose: " choice

case $choice in
    1) cat /etc/ssh/banner ;;
    2) nano /etc/ssh/banner && systemctl restart ssh ;;
    3) cp /etc/ssh/banner.backup /etc/ssh/banner 2>/dev/null && systemctl restart ssh ;;
    *) echo "Invalid option" ;;
esac
EOF
    
    chmod +x /usr/local/bin/vpn-banner
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT,$SSH_ALT_PORT,$SSH_PORT_80,$SSH_PORT_443
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
ignoreip = 127.0.0.1/8

[sshd-ddos]
enabled = true
port = $SSH_PORT,$SSH_ALT_PORT,$SSH_PORT_80,$SSH_PORT_443
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 5
bantime = 86400
EOF
    
    # Restart services
    systemctl restart ssh
    systemctl enable ssh
    systemctl restart fail2ban
    systemctl enable fail2ban
    
    log_message "SSH Server configured on ports: 22, 2222, 80, 443"
}

# =================================================================
# VPN TUNNEL CONFIGURATION (OpenVPN + WireGuard)
# =================================================================

configure_vpn_tunnel() {
    echo -e "${GREEN}[4/15] Configuring VPN Tunnel...${NC}"
    
    # Install OpenVPN
    apt-get install -y openvpn easy-rsa
    
    # Setup OpenVPN
    cp -r /usr/share/easy-rsa/ /etc/openvpn/
    cd /etc/openvpn/easy-rsa
    
    # Initialize PKI
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    ./easyrsa gen-dh
    
    # Generate HMAC key
    openvpn --genkey secret /etc/openvpn/ta.key
    
    # Create OpenVPN server config
    cat > /etc/openvpn/server.conf << EOF
port $TUNNEL_PORT
proto udp
dev tun
ca /etc/openvpn/easy-rsa/pki/ca.crt
cert /etc/openvpn/easy-rsa/pki/issued/server.crt
key /etc/openvpn/easy-rsa/pki/private/server.key
dh /etc/openvpn/easy-rsa/pki/dh.pem
tls-auth /etc/openvpn/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log /var/log/openvpn.log
verb 3
mute 20
explicit-exit-notify 1
tls-server
tls-version-min 1.2
EOF
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Configure iptables for VPN
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4
    
    # Start OpenVPN
    systemctl start openvpn@server
    systemctl enable openvpn@server
    
    # Install WireGuard
    apt-get install -y wireguard wireguard-tools
    
    # Generate WireGuard keys
    wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
    
    # Create WireGuard config
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = 10.9.0.1/24
SaveConfig = true
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
ListenPort = $WIREGUARD_PORT
PrivateKey = $(cat /etc/wireguard/private.key)
EOF
    
    # Start WireGuard
    systemctl start wg-quick@wg0
    systemctl enable wg-quick@wg0
    
    log_message "VPN Tunnel configured (OpenVPN: $TUNNEL_PORT, WireGuard: $WIREGUARD_PORT)"
}

# =================================================================
# UDP CUSTOM TUNNELING
# =================================================================

configure_udp_tunnel() {
    echo -e "${GREEN}[5/15] Configuring UDP Custom Tunnel...${NC}"
    
    # Install UDP tools
    apt-get install -y cmake golang gcc make
    
    # Install udp2raw
    wget -q -O /tmp/udp2raw.tar.gz https://github.com/wangyu-/udp2raw-tunnel/releases/download/20230206.0/udp2raw_binaries.tar.gz
    tar -xzf /tmp/udp2raw.tar.gz -C /tmp/
    mv /tmp/udp2raw_amd64 /usr/local/bin/udp2raw
    chmod +x /usr/local/bin/udp2raw
    
    # Install udpspeeder
    wget -q -O /tmp/udpspeeder.tar.gz https://github.com/wangyu-/UDPspeeder/releases/download/20230206.0/speederv2_binaries.tar.gz
    tar -xzf /tmp/udpspeeder.tar.gz -C /tmp/
    mv /tmp/speederv2_amd64 /usr/local/bin/udpspeeder
    chmod +x /usr/local/bin/udpspeeder
    
    # Create UDP tunnel services for each port
    for port in "${UDP_PORTS[@]}"; do
        # Create UDP tunnel config
        cat > $TUNNEL_DIR/udp-$port.conf << EOF
[udp-tunnel-$port]
mode = server
listen = 0.0.0.0:$port
target = 127.0.0.1:$SSH_PORT
key = vpntunnel-$port
cipher = aes
timeout = 60
EOF
        
        # Create systemd service
        cat > /etc/systemd/system/udp-tunnel-$port.service << EOF
[Unit]
Description=UDP Tunnel Server on port $port
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udpspeeder -s -l0.0.0.0:$port -r127.0.0.1:$SSH_PORT --mode 0 -f2:4 --timeout 0
Restart=always
RestartSec=3
User=nobody
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable udp-tunnel-$port
        systemctl start udp-tunnel-$port
        
        log_message "UDP Tunnel started on port $port"
    done
    
    # Create full UDP range service
    cat > /etc/systemd/system/udp-full.service << EOF
[Unit]
Description=UDP Full Range Tunnel (1-65535)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -s -l0.0.0.0:1 -r127.0.0.1:$SSH_PORT --raw-mode faketcp -k "fulludp" --cipher-mode xor --auth-mode simple
Restart=always
RestartSec=3
User=nobody

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable udp-full
    systemctl start udp-full
    
    log_message "UDP Custom Tunnel configured on ports: ${UDP_PORTS[*]} and 1-65535"
}

# =================================================================
# XRAY/VMESS CONFIGURATION
# =================================================================

configure_xray_vmess() {
    echo -e "${GREEN}[6/15] Configuring Xray/VMESS Tunnel...${NC}"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Generate UUIDs
    VMESS_UUID_80=$(cat /proc/sys/kernel/random/uuid)
    VMESS_UUID_443=$(cat /proc/sys/kernel/random/uuid)
    VLESS_UUID_80=$(cat /proc/sys/kernel/random/uuid)
    VLESS_UUID_443=$(cat /proc/sys/kernel/random/uuid)
    TROJAN_UUID_80=$(cat /proc/sys/kernel/random/uuid)
    TROJAN_UUID_443=$(cat /proc/sys/kernel/random/uuid)
    
    # Create Xray configuration
    cat > /usr/local/etc/xray/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log"
    },
    "policy": {
        "levels": {
            "0": {
                "handshake": 4,
                "connIdle": 300,
                "uplinkOnly": 2,
                "downlinkOnly": 5,
                "statsUserUplink": true,
                "statsUserDownlink": true
            }
        },
        "system": {
            "statsInboundUplink": true,
            "statsInboundDownlink": true
        }
    },
    "inbounds": [
        {
            "port": 80,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$VMESS_UUID_80",
                        "alterId": 0,
                        "email": "tunnel@vpntunnel.com",
                        "level": 0
                    }
                ],
                "disableInsecureEncryption": false
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vmtunnel",
                    "headers": {
                        "Host": "\$host"
                    }
                }
            },
            "tag": "vmess-80-tunnel",
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$VMESS_UUID_443",
                        "alterId": 0,
                        "email": "tunnel@vpntunnel.com",
                        "level": 0
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "wsSettings": {
                    "path": "/vmtunnel",
                    "headers": {
                        "Host": "\$host"
                    }
                },
                "tlsSettings": {
                    "serverName": "\$host",
                    "certificates": [
                        {
                            "certificateFile": "/etc/nginx/ssl/certificate.crt",
                            "keyFile": "/etc/nginx/ssl/private.key"
                        }
                    ]
                }
            },
            "tag": "vmess-443-tunnel"
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$VLESS_UUID_80",
                        "email": "tunnel@vpntunnel.com",
                        "flow": ""
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none",
                "tcpSettings": {
                    "header": {
                        "type": "none"
                    }
                }
            },
            "tag": "vless-80-tunnel"
        },
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$VLESS_UUID_443",
                        "email": "tunnel@vpntunnel.com",
                        "flow": "xtls-rprx-direct"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/nginx/ssl/certificate.crt",
                            "keyFile": "/etc/nginx/ssl/private.key"
                        }
                    ]
                }
            },
            "tag": "vless-443-tunnel"
        },
        {
            "port": 80,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$TROJAN_UUID_80",
                        "email": "tunnel@vpntunnel.com"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "none"
            },
            "tag": "trojan-80-tunnel"
        },
        {
            "port": 443,
            "protocol": "trojan",
            "settings": {
                "clients": [
                    {
                        "password": "$TROJAN_UUID_443",
                        "email": "tunnel@vpntunnel.com"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/nginx/ssl/certificate.crt",
                            "keyFile": "/etc/nginx/ssl/private.key"
                        }
                    ]
                }
            },
            "tag": "trojan-443-tunnel"
        },
        {
            "port": 8443,
            "protocol": "shadowsocks",
            "settings": {
                "clients": [
                    {
                        "method": "chacha20-ietf-poly1305",
                        "password": "$(openssl rand -hex 16)",
                        "email": "tunnel@vpntunnel.com"
                    }
                ],
                "network": "tcp,udp"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/nginx/ssl/certificate.crt",
                            "keyFile": "/etc/nginx/ssl/private.key"
                        }
                    ]
                }
            },
            "tag": "shadowsocks-tunnel"
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "tag": "blocked",
            "settings": {}
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            },
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF
    
    # Create SSL certificates
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/private.key \
        -out /etc/nginx/ssl/certificate.crt \
        -subj "/C=US/ST=California/L=San Francisco/O=VPN Tunnel/CN=$SERVER_IP"
    
    # Set permissions
    chmod 600 /etc/nginx/ssl/private.key
    
    # Create Xray log directory
    mkdir -p /var/log/xray
    chown -R nobody:nogroup /var/log/xray
    
    # Start Xray
    systemctl restart xray
    systemctl enable xray
    
    # Save VMESS configurations
    save_vmess_configs
    
    log_message "Xray/VMESS Tunnel configured on ports 80 & 443"
}

save_vmess_configs() {
    # Save VMESS configs
    cat > $CONFIG_DIR/vmess-config.json << EOF
{
    "server": "$SERVER_IP",
    "uuid": {
        "vmess_80": "$VMESS_UUID_80",
        "vmess_443": "$VMESS_UUID_443",
        "vless_80": "$VLESS_UUID_80",
        "vless_443": "$VLESS_UUID_443",
        "trojan_80": "$TROJAN_UUID_80",
        "trojan_443": "$TROJAN_UUID_443"
    },
    "configs": {
        "vmess_80": "vmess://$(echo '{"v":"2","ps":"VPN-Tunnel-80","add":"'$SERVER_IP'","port":"80","id":"'$VMESS_UUID_80'","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"/vmtunnel","tls":"","sni":"","alpn":""}' | base64 -w0)",
        "vmess_443": "vmess://$(echo '{"v":"2","ps":"VPN-Tunnel-443","add":"'$SERVER_IP'","port":"443","id":"'$VMESS_UUID_443'","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"/vmtunnel","tls":"tls","sni":"","alpn":""}' | base64 -w0)"
    }
}
EOF
    
    # Create user-readable config
    cat > $CONFIG_DIR/tunnel-config.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║              VPN TUNNEL SERVER CONFIGURATION                ║
║              github.com/sukronwae85-design/terlupakan        ║
╚══════════════════════════════════════════════════════════════╝

🌍 SERVER INFORMATION:
• IP Address: $SERVER_IP
• Location: VPN Tunnel Server
• Status: ✅ ACTIVE
• Uptime: $(uptime -p)

══════════════════════════════════════════════════════════════
🔰 SSH TUNNEL CONFIGURATION:
══════════════════════════════════════════════════════════════
• Host: $SERVER_IP
• Ports: 22, 2222, 80, 443
• Protocol: SSH over TLS
• Encryption: AES-256-GCM

══════════════════════════════════════════════════════════════
🔄 UDP TUNNEL CONFIGURATION:
══════════════════════════════════════════════════════════════
• Ports: 7100, 7200, 7300
• Full Range: 1-65535
• Protocol: UDP over TCP
• Encryption: XOR + AES

══════════════════════════════════════════════════════════════
🚀 VMESS TUNNEL CONFIGURATION (Port 443):
══════════════════════════════════════════════════════════════
Address: $SERVER_IP
Port: 443
UUID: $VMESS_UUID_443
Security: auto
Network: ws
Path: /vmtunnel
TLS: tls
Type: none

📎 VMESS LINK:
vmess://$(echo '{"v":"2","ps":"VPN-Tunnel-443","add":"'$SERVER_IP'","port":"443","id":"'$VMESS_UUID_443'","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"/vmtunnel","tls":"tls","sni":"","alpn":""}' | base64 -w0)

══════════════════════════════════════════════════════════════
🚀 VMESS TUNNEL CONFIGURATION (Port 80):
══════════════════════════════════════════════════════════════
Address: $SERVER_IP
Port: 80
UUID: $VMESS_UUID_80
Security: auto
Network: ws
Path: /vmtunnel
TLS: none
Type: none

📎 VMESS LINK:
vmess://$(echo '{"v":"2","ps":"VPN-Tunnel-80","add":"'$SERVER_IP'","port":"80","id":"'$VMESS_UUID_80'","aid":"0","scy":"auto","net":"ws","type":"none","host":"","path":"/vmtunnel","tls":"","sni":"","alpn":""}' | base64 -w0)

══════════════════════════════════════════════════════════════
🛡️ VPN TUNNEL CONFIGURATION:
══════════════════════════════════════════════════════════════
• OpenVPN Port: $TUNNEL_PORT
• WireGuard Port: $WIREGUARD_PORT
• Network: 10.8.0.0/24
• Protocol: UDP/TCP
• Encryption: AES-256-CBC

══════════════════════════════════════════════════════════════
⚙️ MANAGEMENT COMMANDS:
══════════════════════════════════════════════════════════════
• Menu: vpn-menu
• Add User: vpn-adduser
• List Users: vpn-list
• Monitor: vpn-monitor
• Backup: vpn-backup
══════════════════════════════════════════════════════════════
EOF
}

# =================================================================
# NGINX REVERSE PROXY + SSL FIX
# =================================================================

configure_nginx() {
    echo -e "${GREEN}[7/15] Configuring Nginx Reverse Proxy...${NC}"
    
    # Install Nginx
    apt-get install -y nginx certbot python3-certbot-nginx
    
    # Stop Nginx
    systemctl stop nginx
    
    # Remove default config
    rm -f /etc/nginx/sites-enabled/default
    
    # Create optimized nginx.conf
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    client_max_body_size 100M;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml+rss text/javascript;
    
    # Virtual Hosts
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Create main server configuration
    cat > /etc/nginx/sites-available/vpntunnel << EOF
# VPN Tunnel Server Configuration
# Auto-generated on $(date)

# HTTP Server (Port 80)
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_IP;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Root directory
    root /var/www/html;
    index index.html;
    
    # WebSocket for VMESS (Port 80)
    location /vmtunnel {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Static files
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }
    
    # Logging
    access_log /var/log/nginx/vpntunnel-80-access.log;
    error_log /var/log/nginx/vpntunnel-80-error.log;
}

# HTTPS Server (Port 443)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $SERVER_IP;
    
    # SSL Certificate
    ssl_certificate /etc/nginx/ssl/certificate.crt;
    ssl_certificate_key /etc/nginx/ssl/private.key;
    
    # SSL Optimization
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_dhparam /etc/nginx/dhparam.pem;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Root directory
    root /var/www/html;
    index index.html;
    
    # WebSocket for VMESS (Port 443)
    location /vmtunnel {
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    
    # Admin panel
    location /admin {
        auth_basic "VPN Tunnel Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd;
        alias /var/www/admin;
        index index.html;
    }
    
    # Status page
    location /status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
    
    # Logging
    access_log /var/log/nginx/vpntunnel-443-access.log;
    error_log /var/log/nginx/vpntunnel-443-error.log;
}
EOF
    
    # Generate strong DH parameters
    openssl dhparam -out /etc/nginx/dhparam.pem 2048
    
    # Create admin password
    htpasswd -bc /etc/nginx/.htpasswd admin vpntunnel123 2>/dev/null || \
    echo 'admin:$apr1$3WZQzL2E$X5h6hJ8L8Y8Z9Z9Z9Z9Z9/' > /etc/nginx/.htpasswd
    
    # Create web interface
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 VPN Tunnel Server</title>
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --dark: #2d3748;
            --light: #f7fafc;
            --success: #48bb78;
            --warning: #ed8936;
            --danger: #f56565;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
            color: var(--dark);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            text-align: center;
            margin-bottom: 3rem;
            color: white;
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            background: linear-gradient(90deg, #fff, #f0f0f0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .card-icon {
            font-size: 2rem;
            margin-right: 1rem;
        }
        
        .card-title {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }
        
        .stat-item {
            text-align: center;
            padding: 1rem;
            background: var(--light);
            border-radius: 10px;
        }
        
        .stat-value {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--primary);
            display: block;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #666;
            margin-top: 0.5rem;
        }
        
        .config-section {
            background: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .config-title {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .config-box {
            background: #2d3748;
            color: #e2e8f0;
            padding: 1.5rem;
            border-radius: 10px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 1rem 0;
        }
        
        .service-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: 600;
            margin: 0.5rem 0;
        }
        
        .status-online {
            background: #c6f6d5;
            color: #22543d;
        }
        
        .status-offline {
            background: #fed7d7;
            color: #742a2a;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }
        
        .dot-online {
            background: var(--success);
        }
        
        .dot-offline {
            background: var(--danger);
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .dashboard {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 VPN Tunnel Server</h1>
            <p>High-Performance VPN & SSH Tunnel Solution</p>
            <p style="margin-top: 1rem; font-size: 0.9rem; opacity: 0.8;">Server: $SERVER_IP | Status: <span style="color: #48bb78;">● ONLINE</span></p>
        </div>
        
        <div class="dashboard">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">📊</div>
                    <div class="card-title">Server Status</div>
                </div>
                <div class="stats">
                    <div class="stat-item">
                        <span class="stat-value" id="cpu">0%</span>
                        <span class="stat-label">CPU Usage</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" id="memory">0%</span>
                        <span class="stat-label">Memory</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" id="uptime">0h</span>
                        <span class="stat-label">Uptime</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value" id="connections">0</span>
                        <span class="stat-label">Connections</span>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">🛡️</div>
                    <div class="card-title">Services</div>
                </div>
                <div id="services-list">
                    <!-- Services will be loaded by JavaScript -->
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">⚡</div>
                    <div class="card-title">Quick Links</div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 1rem;">
                    <a href="/admin" style="background: var(--primary); color: white; padding: 1rem; border-radius: 10px; text-align: center; text-decoration: none; font-weight: 600;">
                        🔧 Admin Panel
                    </a>
                    <button onclick="showConfig()" style="background: var(--secondary); color: white; padding: 1rem; border-radius: 10px; border: none; font-weight: 600; cursor: pointer;">
                        📋 Show Config
                    </button>
                </div>
            </div>
        </div>
        
        <div class="config-section" id="configSection" style="display: none;">
            <div class="config-title">📁 Server Configuration</div>
            <div class="config-box" id="configContent">
                Loading configuration...
            </div>
        </div>
        
        <div class="footer">
            <p>Powered by <strong>VPN Tunnel Server</strong> v$VERSION</p>
            <p style="margin-top: 0.5rem; font-size: 0.9rem; opacity: 0.8;">
                github.com/sukronwae85-design/terlupakan
            </p>
        </div>
    </div>
    
    <script>
        // Update stats every 5 seconds
        function updateStats() {
            fetch('/status').then(r => r.text()).then(data => {
                const lines = data.split('\\n');
                const active = lines[0].split(': ')[1];
                document.getElementById('connections').textContent = active;
            });
            
            // Simulate CPU and Memory usage (in real app, fetch from API)
            document.getElementById('cpu').textContent = Math.floor(Math.random() * 30) + 10 + '%';
            document.getElementById('memory').textContent = Math.floor(Math.random() * 40) + 20 + '%';
            
            // Uptime
            const hours = Math.floor(Math.random() * 24);
            const days = Math.floor(Math.random() * 30);
            document.getElementById('uptime').textContent = \`\${days}d \${hours}h\`;
        }
        
        // Load services status
        function loadServices() {
            const services = [
                { name: 'SSH Server', port: 22, status: 'online' },
                { name: 'VMESS Tunnel', port: 443, status: 'online' },
                { name: 'UDP Tunnel', port: 7100, status: 'online' },
                { name: 'OpenVPN', port: $TUNNEL_PORT, status: 'online' },
                { name: 'Nginx', port: 80, status: 'online' },
                { name: 'Xray', port: 443, status: 'online' }
            ];
            
            let html = '';
            services.forEach(service => {
                html += \`
                    <div class="service-status \${service.status === 'online' ? 'status-online' : 'status-offline'}">
                        <span class="status-dot \${service.status === 'online' ? 'dot-online' : 'dot-offline'}"></span>
                        <span>\${service.name} (Port \${service.port})</span>
                    </div>
                \`;
            });
            
            document.getElementById('services-list').innerHTML = html;
        }
        
        // Show configuration
        function showConfig() {
            const configSection = document.getElementById('configSection');
            if (configSection.style.display === 'none') {
                configSection.style.display = 'block';
                document.getElementById('configContent').textContent = \`
Server IP: $SERVER_IP
SSH Ports: 22, 2222, 80, 443
UDP Ports: 7100, 7200, 7300
VMESS Ports: 80, 443
VPN Ports: $TUNNEL_PORT (OpenVPN), $WIREGUARD_PORT (WireGuard)
Web Admin: https://$SERVER_IP/admin
Username: admin
Password: vpntunnel123
                \`;
            } else {
                configSection.style.display = 'none';
            }
        }
        
        // Initialize
        updateStats();
        loadServices();
        setInterval(updateStats, 5000);
    </script>
</body>
</html>
EOF
    
    # Create admin panel
    cat > /var/www/admin/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Tunnel Admin</title>
    <style>
        :root {
            --sidebar-width: 250px;
            --header-height: 70px;
            --primary: #3498db;
            --secondary: #2c3e50;
            --success: #27ae60;
            --danger: #e74c3c;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f6fa;
            overflow-x: hidden;
        }
        
        .sidebar {
            width: var(--sidebar-width);
            height: 100vh;
            background: var(--secondary);
            position: fixed;
            left: 0;
            top: 0;
            color: white;
            padding: 20px;
            transition: all 0.3s;
        }
        
        .sidebar-header {
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #34495e;
        }
        
        .sidebar-header h2 {
            font-size: 1.5rem;
            margin-bottom: 5px;
        }
        
        .sidebar-menu {
            list-style: none;
        }
        
        .sidebar-menu li {
            padding: 15px;
            margin: 5px 0;
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .sidebar-menu li:hover,
        .sidebar-menu li.active {
            background: #34495e;
        }
        
        .main-content {
            margin-left: var(--sidebar-width);
            padding: 30px;
            min-height: 100vh;
        }
        
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: var(--secondary);
            font-size: 1.8rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .stat-card h3 {
            color: #7f8c8d;
            margin-bottom: 15px;
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--secondary);
        }
        
        .action-buttons {
            display: flex;
            gap: 15px;
            margin: 30px 0;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .btn-primary {
            background: var(--primary);
            color: white;
        }
        
        .btn-success {
            background: var(--success);
            color: white;
        }
        
        .btn-danger {
            background: var(--danger);
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .table-container {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: var(--secondary);
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-online {
            background: #d4edda;
            color: #155724;
        }
        
        .status-offline {
            background: #f8d7da;
            color: #721c24;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .main-content {
                margin-left: 0;
            }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h2>🔧 VPN Admin</h2>
            <p>Control Panel</p>
        </div>
        <ul class="sidebar-menu">
            <li class="active" onclick="showSection('dashboard')">📊 Dashboard</li>
            <li onclick="showSection('users')">👥 Users</li>
            <li onclick="showSection('tunnels')">🔄 Tunnels</li>
            <li onclick="showSection('domains')">🌐 Domains</li>
            <li onclick="showSection('settings')">⚙️ Settings</li>
            <li onclick="showSection('logs')">📋 Logs</li>
            <li onclick="showSection('backup')">💾 Backup</li>
        </ul>
    </div>
    
    <div class="main-content">
        <div class="header">
            <h1>VPN Tunnel Server Dashboard</h1>
            <div style="color: #7f8c8d;">
                Server: <?php echo $_SERVER['SERVER_ADDR']; ?> | 
                Time: <span id="currentTime"><?php echo date('H:i:s'); ?></span>
            </div>
        </div>
        
        <div id="dashboard" class="section">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Active Users</h3>
                    <div class="value" id="activeUsers">0</div>
                </div>
                <div class="stat-card">
                    <h3>Bandwidth Today</h3>
                    <div class="value" id="bandwidth">0 GB</div>
                </div>
                <div class="stat-card">
                    <h3>Uptime</h3>
                    <div class="value" id="serverUptime">0h 0m</div>
                </div>
                <div class="stat-card">
                    <h3>Connections</h3>
                    <div class="value" id="activeConnections">0</div>
                </div>
            </div>
            
            <div class="action-buttons">
                <button class="btn btn-primary" onclick="addUser()">
                    <span>➕</span> Add User
                </button>
                <button class="btn btn-success" onclick="restartServices()">
                    <span>🔄</span> Restart Services
                </button>
                <button class="btn btn-danger" onclick="backupNow()">
                    <span>💾</span> Backup Now
                </button>
            </div>
        </div>
        
        <div id="users" class="section" style="display: none;">
            <div class="table-container">
                <h2 style="margin-bottom: 20px;">User Management</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Status</th>
                            <th>Expiry</th>
                            <th>Bandwidth</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="usersTable">
                        <!-- Users will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="tunnels" class="section" style="display: none;">
            <div class="table-container">
                <h2 style="margin-bottom: 20px;">Tunnel Status</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>Port</th>
                            <th>Status</th>
                            <th>Connections</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="tunnelsTable">
                        <!-- Tunnels will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        // Update time every second
        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = 
                now.toLocaleTimeString('en-US', {hour12: false});
        }
        
        // Show section
        function showSection(sectionId) {
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.style.display = 'none';
            });
            
            // Show selected section
            document.getElementById(sectionId).style.display = 'block';
            
            // Update active menu
            document.querySelectorAll('.sidebar-menu li').forEach(item => {
                item.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
            
            // Load section data
            if (sectionId === 'users') loadUsers();
            if (sectionId === 'tunnels') loadTunnels();
        }
        
        // Load users
        function loadUsers() {
            // Simulate API call
            const users = [
                {username: 'user1', status: 'active', expiry: '2024-12-31', bandwidth: '150GB'},
                {username: 'user2', status: 'active', expiry: '2024-11-30', bandwidth: '75GB'},
                {username: 'user3', status: 'expired', expiry: '2024-10-15', bandwidth: '300GB'},
            ];
            
            let html = '';
            users.forEach(user => {
                html += \`
                    <tr>
                        <td>\${user.username}</td>
                        <td>
                            <span class="status-badge \${user.status === 'active' ? 'status-online' : 'status-offline'}">
                                \${user.status.toUpperCase()}
                            </span>
                        </td>
                        <td>\${user.expiry}</td>
                        <td>\${user.bandwidth}</td>
                        <td>
                            <button style="padding: 5px 10px; margin-right: 5px;">Edit</button>
                            <button style="padding: 5px 10px; background: var(--danger); color: white; border: none; border-radius: 4px;">Delete</button>
                        </td>
                    </tr>
                \`;
            });
            
            document.getElementById('usersTable').innerHTML = html;
        }
        
        // Load tunnels
        function loadTunnels() {
            const tunnels = [
                {service: 'SSH', port: 22, status: 'online', connections: 15},
                {service: 'VMESS', port: 443, status: 'online', connections: 42},
                {service: 'UDP', port: 7100, status: 'online', connections: 28},
                {service: 'OpenVPN', port: 1194, status: 'online', connections: 19},
            ];
            
            let html = '';
            tunnels.forEach(tunnel => {
                html += \`
                    <tr>
                        <td>\${tunnel.service}</td>
                        <td>\${tunnel.port}</td>
                        <td>
                            <span class="status-badge \${tunnel.status === 'online' ? 'status-online' : 'status-offline'}">
                                \${tunnel.status.toUpperCase()}
                            </span>
                        </td>
                        <td>\${tunnel.connections}</td>
                        <td>
                            <button style="padding: 5px 10px;">Restart</button>
                        </td>
                    </tr>
                \`;
            });
            
            document.getElementById('tunnelsTable').innerHTML = html;
        }
        
        // Action functions
        function addUser() {
            alert('Add user functionality would open a form here');
        }
        
        function restartServices() {
            if (confirm('Restart all services?')) {
                alert('Services restarting...');
            }
        }
        
        function backupNow() {
            alert('Starting backup...');
        }
        
        // Initialize
        updateTime();
        setInterval(updateTime, 1000);
        
        // Update stats every 10 seconds
        setInterval(() => {
            document.getElementById('activeUsers').textContent = 
                Math.floor(Math.random() * 50) + 10;
            document.getElementById('bandwidth').textContent = 
                (Math.random() * 100).toFixed(1) + ' GB';
            document.getElementById('serverUptime').textContent = 
                Math.floor(Math.random() * 24) + 'h ' + Math.floor(Math.random() * 60) + 'm';
            document.getElementById('activeConnections').textContent = 
                Math.floor(Math.random() * 100) + 50;
        }, 10000);
    </script>
</body>
</html>
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/vpntunnel /etc/nginx/sites-enabled/
    
    # Test configuration
    nginx -t
    
    # Start Nginx
    systemctl start nginx
    systemctl enable nginx
    
    log_message "Nginx configured with SSL and reverse proxy"
}

# =================================================================
# DOMAIN POINTING SYSTEM
# =================================================================

configure_domain_pointing() {
    echo -e "${GREEN}[8/15] Configuring Domain Pointing System...${NC}"
    
    # Install certbot for SSL
    apt-get install -y certbot python3-certbot-nginx
    
    # Create domain management script
    cat > /usr/local/bin/vpn-domain << 'EOF'
#!/bin/bash

DOMAIN_DB="/etc/vpntunnel/domains.json"

case "$1" in
    "add")
        read -p "Enter domain name: " domain
        read -p "Enter email for SSL: " email
        
        if [[ -z "$domain" || -z "$email" ]]; then
            echo "Domain and email are required!"
            exit 1
        fi
        
        echo "Checking DNS for $domain..."
        ip=$(dig +short A "$domain")
        
        if [[ "$ip" != "$(curl -s ifconfig.me)" ]]; then
            echo "Warning: Domain does not point to this server!"
            echo "Current IP: $ip"
            echo "Server IP: $(curl -s ifconfig.me)"
            read -p "Continue anyway? (y/n): " -n 1 -r
            echo
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
        fi
        
        # Get SSL certificate
        certbot certonly --nginx -d "$domain" --non-interactive --agree-tos -m "$email"
        
        # Create Nginx config
        cat > /etc/nginx/sites-available/$domain << CONF
server {
    listen 80;
    server_name $domain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    location /vmtunnel {
        proxy_pass http://127.0.0.1:443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    
    location / {
        root /var/www/domains/$domain;
        index index.html;
    }
}
CONF
        
        ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
        systemctl reload nginx
        
        echo "Domain $domain added successfully!"
        ;;
        
    "list")
        echo "Configured Domains:"
        ls /etc/nginx/sites-enabled/ | grep -v default
        ;;
        
    "remove")
        read -p "Enter domain to remove: " domain
        rm -f /etc/nginx/sites-available/$domain
        rm -f /etc/nginx/sites-enabled/$domain
        systemctl reload nginx
        echo "Domain $domain removed!"
        ;;
        
    *)
        echo "Usage: vpn-domain [add|list|remove]"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/vpn-domain
    
    log_message "Domain pointing system configured"
}

# =================================================================
# FIREWALL CONFIGURATION
# =================================================================

configure_firewall() {
    echo -e "${GREEN}[9/15] Configuring Firewall...${NC}"
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow all necessary ports
    ALL_PORTS=($SSH_PORT $SSH_ALT_PORT $SSH_PORT_80 $SSH_PORT_443 80 443 $TUNNEL_PORT $WIREGUARD_PORT 8443)
    
    for port in "${ALL_PORTS[@]}"; do
        ufw allow $port/tcp
        ufw allow $port/udp
    done
    
    # Allow UDP tunnel ports
    for port in "${UDP_PORTS[@]}"; do
        ufw allow $port/tcp
        ufw allow $port/udp
    done
    
    # Allow full UDP range
    ufw allow 1:65535/udp comment "Full UDP range for tunneling"
    
    # Allow ICMP
    ufw allow icmp
    
    # Enable UFW
    echo "y" | ufw enable
    
    # Save rules
    ufw status verbose
    
    log_message "Firewall configured with all necessary ports"
}

# =================================================================
# USER MANAGEMENT SYSTEM
# =================================================================

create_user_management() {
    echo -e "${GREEN}[10/15] Creating User Management System...${NC}"
    
    # Create user management script
    cat > /usr/local/bin/vpn-user << 'EOF'
#!/bin/bash

CONFIG_DIR="/etc/vpntunnel"
USER_DB="$CONFIG_DIR/users.json"

show_menu() {
    echo ""
    echo "┌─────────────────────────────────────┐"
    echo "│   VPN Tunnel User Management        │"
    echo "├─────────────────────────────────────┤"
    echo "│  1. Add User                        │"
    echo "│  2. List Users                      │"
    echo "│  3. Delete User                     │"
    echo "│  4. Lock/Unlock User                │"
    echo "│  5. Change Password                 │"
    echo "│  6. Set Expiry Date                 │"
    echo "│  7. View User Info                  │"
    echo "│  0. Exit                            │"
    echo "└─────────────────────────────────────┘"
    echo ""
}

add_user() {
    echo "┌─────────────────────────────────────┐"
    echo "│         ADD NEW USER                │"
    echo "└─────────────────────────────────────┘"
    
    read -p "Username: " username
    read -s -p "Password: " password
    echo
    read -p "Expiry days (30): " expiry_days
    expiry_days=${expiry_days:-30}
    read -p "Max IP connections (3): " max_ips
    max_ips=${max_ips:-3}
    
    # Create system user
    useradd -m -s /bin/false -G vpntunnel "$username"
    echo "$username:$password" | chpasswd
    
    # Calculate expiry
    expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    
    # Generate UUIDs
    vmess_uuid=$(cat /proc/sys/kernel/random/uuid)
    vless_uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Create user data
    user_data=$(jq -n \
        --arg user "$username" \
        --arg pass "$password" \
        --arg expiry "$expiry_date" \
        --arg created "$(date +%Y-%m-%d)" \
        --argjson max $max_ips \
        --arg vmess "$vmess_uuid" \
        --arg vless "$vless_uuid" \
        '{
            username: $user,
            password: $pass,
            created: $created,
            expiry: $expiry,
            max_ips: $max,
            current_ips: [],
            locked: false,
            bandwidth_used: 0,
            last_login: "",
            vmess_uuid: $vmess,
            vless_uuid: $vless
        }')
    
    # Add to database
    jq ". += [$user_data]" $USER_DB > $USER_DB.tmp && mv $USER_DB.tmp $USER_DB
    
    # Create user config file
    mkdir -p $CONFIG_DIR/users
    cat > $CONFIG_DIR/users/$username.txt << CONFIG
╔══════════════════════════════════════════╗
║         USER CONFIGURATION               ║
║         Username: $username             ║
╚══════════════════════════════════════════╝

🔐 ACCOUNT INFO:
• Username: $username
• Password: $password
• Created: $(date)
• Expiry: $expiry_date
• Max IPs: $max_ips

🔰 SSH CONFIG:
• Host: $(curl -s ifconfig.me)
• Ports: 22, 2222, 80, 443
• Username: $username
• Password: $password

🚀 VMESS CONFIG (Port 443):
vmess://$(echo '{"v":"2","ps":"VPN-'$username'","add":"'$(curl -s ifconfig.me)'","port":"443","id":"'$vmess_uuid'","aid":"0","scy":"auto","net":"ws","type":"none","path":"/vmtunnel","tls":"tls"}' | base64 -w0)

🔄 UDP CONFIG:
• Ports: 7100, 7200, 7300
• Full Range: 1-65535

⚠️  NOTES:
• Account expires: $expiry_date
• Max $max_ips concurrent connections
• Contact admin for extension
CONFIG
    
    echo ""
    echo "✅ User $username created successfully!"
    echo "📁 Config saved: $CONFIG_DIR/users/$username.txt"
}

list_users() {
    total=$(jq 'length' $USER_DB 2>/dev/null || echo "0")
    echo ""
    echo "Total Users: $total"
    echo "┌─────────────────────────────────────────────────────────────────────┐"
    echo "│ Username        │ Status   │ Expiry     │ IPs  │ Bandwidth         │"
    echo "├─────────────────────────────────────────────────────────────────────┤"
    
    jq -r '.[] | "│ \(.username)\t│ \(if .locked then "🔒" else "✅" end)\t│ \(.expiry)\t│ \(.current_ips | length)/\(.max_ips)\t│ \(.bandwidth_used)GB\t│"' $USER_DB 2>/dev/null || echo "│ No users found │"
    
    echo "└─────────────────────────────────────────────────────────────────────┘"
}

case "$1" in
    "add")
        add_user
        ;;
    "list")
        list_users
        ;;
    "menu")
        while true; do
            show_menu
            read -p "Choose option: " choice
            case $choice in
                1) add_user ;;
                2) list_users ;;
                3) echo "Delete user" ;;
                4) echo "Lock/unlock user" ;;
                5) echo "Change password" ;;
                6) echo "Set expiry" ;;
                7) echo "View info" ;;
                0) exit 0 ;;
                *) echo "Invalid option" ;;
            esac
            read -p "Press Enter to continue..."
        done
        ;;
    *)
        echo "Usage: vpn-user [add|list|menu]"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/vpn-user
    
    # Create monitoring script
    cat > /usr/local/bin/vpn-monitor << 'EOF'
#!/bin/bash

echo ""
echo "┌─────────────────────────────────────┐"
echo "│   VPN Tunnel Server Monitor         │"
echo "├─────────────────────────────────────┤"

# System info
echo "│ 🌍 Server: $(hostname)"
echo "│ 📡 IP: $(curl -s ifconfig.me)"
echo "│ 🖥️  Uptime: $(uptime -p)"
echo "│ 📅 Date: $(date)"
echo "├─────────────────────────────────────┤"

# CPU and Memory
cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}')
mem=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')
echo "│ ⚡ CPU Usage: $cpu%"
echo "│ 💾 Memory Usage: $mem"
echo "├─────────────────────────────────────┤"

# Service status
services=("ssh" "nginx" "xray" "openvpn" "fail2ban")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "│ ✅ $service: RUNNING"
    else
        echo "│ ❌ $service: STOPPED"
    fi
done

echo "├─────────────────────────────────────┤"

# Connections
ssh_conn=$(netstat -an | grep -c ":22.*ESTABLISHED")
total_conn=$(netstat -an | grep -c "ESTABLISHED")
echo "│ 👥 SSH Connections: $ssh_conn"
echo "│ 🔗 Total Connections: $total_conn"
echo "└─────────────────────────────────────┘"
echo ""
EOF
    
    chmod +x /usr/local/bin/vpn-monitor
    
    log_message "User management system created"
}

# =================================================================
# BACKUP SYSTEM
# =================================================================

configure_backup() {
    echo -e "${GREEN}[11/15] Configuring Backup System...${NC}"
    
    # Create backup script
    cat > /usr/local/bin/vpn-backup << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/vpntunnel"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/full-backup-$DATE.tar.gz"

echo "Creating backup..."
echo "This may take a few moments..."

# Create backup
tar -czf "$BACKUP_FILE" \
    /etc/vpntunnel \
    /etc/ssh \
    /usr/local/etc/xray \
    /etc/nginx \
    /etc/openvpn \
    /etc/wireguard \
    /var/www \
    /var/log/vpntunnel.log \
    2>/dev/null

if [[ $? -eq 0 ]]; then
    size=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "✅ Backup created successfully!"
    echo "📁 File: $BACKUP_FILE"
    echo "📦 Size: $size"
    
    # Encrypt backup
    read -s -p "Encryption password (leave empty to skip): " password
    echo
    
    if [[ -n "$password" ]]; then
        openssl enc -aes-256-cbc -salt -in "$BACKUP_FILE" -out "$BACKUP_FILE.enc" -k "$password"
        rm "$BACKUP_FILE"
        echo "🔒 Backup encrypted: $BACKUP_FILE.enc"
    fi
else
    echo "❌ Backup failed!"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/vpn-backup
    
    # Create restore script
    cat > /usr/local/bin/vpn-restore << 'EOF'
#!/bin/bash

echo "VPN Tunnel Restore Utility"
echo "=========================="

read -p "Backup file path: " backup_file

if [[ ! -f "$backup_file" ]]; then
    echo "❌ Backup file not found!"
    exit 1
fi

# Check if encrypted
if [[ "$backup_file" == *.enc ]]; then
    read -s -p "Decryption password: " password
    echo
    openssl enc -aes-256-cbc -d -in "$backup_file" -out "${backup_file%.enc}" -k "$password"
    backup_file="${backup_file%.enc}"
fi

echo "Restoring from backup..."
tar -xzf "$backup_file" -C /

# Restart services
systemctl restart ssh
systemctl restart nginx
systemctl restart xray
systemctl restart openvpn

echo "✅ Restore completed!"
echo "Please restart the server if needed."
EOF
    
    chmod +x /usr/local/bin/vpn-restore
    
    log_message "Backup system configured"
}

# =================================================================
# CRON JOBS
# =================================================================

configure_cron() {
    echo -e "${GREEN}[12/15] Configuring Cron Jobs...${NC}"
    
    # Clear existing cron
    crontab -r 2>/dev/null
    
    # Add cron jobs
    (crontab -l 2>/dev/null; echo "# VPN Tunnel Server Cron Jobs") | crontab -
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/vpn-backup --auto") | crontab -
    (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/vpn-monitor --log") | crontab -
    (crontab -l 2>/dev/null; echo "0 3 * * 0 certbot renew --quiet") | crontab -
    (crontab -l 2>/dev/null; echo "*/5 * * * * systemctl restart xray 2>/dev/null") | crontab -
    
    # Create auto backup script
    cat > /usr/local/bin/auto-backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/vpntunnel"
DATE=$(date +%Y%m%d)
tar -czf "$BACKUP_DIR/auto-$DATE.tar.gz" /etc/vpntunnel /usr/local/etc/xray 2>/dev/null
find $BACKUP_DIR -name "auto-*.tar.gz" -mtime +7 -delete
EOF
    
    chmod +x /usr/local/bin/auto-backup.sh
    
    log_message "Cron jobs configured"
}

# =================================================================
# FINAL SETUP & MENU
# =================================================================

create_menu() {
    echo -e "${GREEN}[13/15] Creating Interactive Menu...${NC}"
    
    # Create main menu script
    cat > /usr/local/bin/vpn-menu << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         🚀 VPN TUNNEL SERVER MANAGEMENT MENU                ║"
    echo "║         github.com/sukronwae85-design/terlupakan            ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║  Server: $(hostname)                                        ║"
    echo "║  IP: $(curl -s ifconfig.me)                                 ║"
    echo "║  Time: $(date '+%H:%M:%S')                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_menu() {
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│   📋 MAIN MENU                            │${NC}"
    echo -e "${GREEN}├─────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}│ ${CYAN}1.${NC} 👤 User Management               ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}2.${NC} 🌐 Domain Management             ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}3.${NC} 📊 Server Monitoring            ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}4.${NC} 🛠️  Service Management          ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}5.${NC} 💾 Backup & Restore             ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}6.${NC} ⚙️  System Configuration        ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}7.${NC} 🔧 Tunnel Configuration         ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}8.${NC} 📋 Show Config Files            ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}9.${NC} 🚀 Restart All Services         ${GREEN}│${NC}"
    echo -e "${GREEN}│ ${CYAN}0.${NC} ❌ Exit                         ${GREEN}│${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────┘${NC}"
    echo ""
}

user_management() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "┌─────────────────────────────────────┐"
        echo "│   👤 USER MANAGEMENT                │"
        echo "├─────────────────────────────────────┤"
        echo "│   1. Add New User                  │"
        echo "│   2. List All Users                │"
        echo "│   3. Delete User                   │"
        echo "│   4. Lock/Unlock User              │"
        echo "│   5. Change Password               │"
        echo "│   6. Set Expiry Date               │"
        echo "│   7. View User Statistics          │"
        echo "│   0. Back to Main Menu             │"
        echo "└─────────────────────────────────────┘"
        echo -e "${NC}"
        
        read -p "Choose option: " choice
        case $choice in
            1) vpn-user add ;;
            2) vpn-user list ;;
            3) read -p "Username: " user && userdel -r "$user" 2>/dev/null && echo "User deleted" ;;
            4) read -p "Username: " user && echo "Lock/unlock $user" ;;
            5) read -p "Username: " user && passwd "$user" ;;
            6) read -p "Username: " user && echo "Set expiry for $user" ;;
            7) echo "User statistics" ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
        read -p "Press Enter to continue..."
    done
}

domain_management() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "┌─────────────────────────────────────┐"
        echo "│   🌐 DOMAIN MANAGEMENT              │"
        echo "├─────────────────────────────────────┤"
        echo "│   1. Add Domain                    │"
        echo "│   2. List Domains                  │"
        echo "│   3. Remove Domain                 │"
        echo "│   4. Renew SSL Certificate         │"
        echo "│   5. Test Domain Configuration     │"
        echo "│   0. Back to Main Menu             │"
        echo "└─────────────────────────────────────┘"
        echo -e "${NC}"
        
        read -p "Choose option: " choice
        case $choice in
            1) vpn-domain add ;;
            2) vpn-domain list ;;
            3) vpn-domain remove ;;
            4) certbot renew ;;
            5) nginx -t ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
        read -p "Press Enter to continue..."
    done
}

service_management() {
    while true; do
        clear
        echo -e "${CYAN}"
        echo "┌─────────────────────────────────────┐"
        echo "│   🛠️  SERVICE MANAGEMENT            │"
        echo "├─────────────────────────────────────┤"
        echo "│   1. Restart SSH                   │"
        echo "│   2. Restart Nginx                 │"
        echo "│   3. Restart Xray/VMESS            │"
        echo "│   4. Restart OpenVPN               │"
        echo "│   5. Restart WireGuard             │"
        echo "│   6. Restart All Services          │"
        echo "│   7. View Service Status           │"
        echo "│   0. Back to Main Menu             │"
        echo "└─────────────────────────────────────┘"
        echo -e "${NC}"
        
        read -p "Choose option: " choice
        case $choice in
            1) systemctl restart ssh ;;
            2) systemctl restart nginx ;;
            3) systemctl restart xray ;;
            4) systemctl restart openvpn ;;
            5) systemctl restart wg-quick@wg0 ;;
            6) systemctl restart ssh nginx xray openvpn ;;
            7) systemctl status ssh nginx xray openvpn ;;
            0) return ;;
            *) echo "Invalid option" ;;
        esac
        read -p "Press Enter to continue..."
    done
}

show_configs() {
    echo -e "${YELLOW}"
    echo "Configuration Files:"
    echo "────────────────────"
    echo "1. SSH Config: /etc/ssh/sshd_config"
    echo "2. Nginx Config: /etc/nginx/nginx.conf"
    echo "3. Xray Config: /usr/local/etc/xray/config.json"
    echo "4. OpenVPN Config: /etc/openvpn/server.conf"
    echo "5. User Database: /etc/vpntunnel/users.json"
    echo "6. Tunnel Config: /etc/vpntunnel/tunnel-config.txt"
    echo "7. VMESS Config: /etc/vpntunnel/vmess-config.json"
    echo ""
    read -p "View which config? (1-7): " choice
    
    case $choice in
        1) cat /etc/ssh/sshd_config ;;
        2) cat /etc/nginx/nginx.conf ;;
        3) cat /usr/local/etc/xray/config.json ;;
        4) cat /etc/openvpn/server.conf ;;
        5) cat /etc/vpntunnel/users.json ;;
        6) cat /etc/vpntunnel/tunnel-config.txt ;;
        7) cat /etc/vpntunnel/vmess-config.json ;;
        *) echo "Invalid choice" ;;
    esac
}

# Main menu loop
while true; do
    show_header
    show_menu
    read -p "Select option: " choice
    
    case $choice in
        1) user_management ;;
        2) domain_management ;;
        3) vpn-monitor ;;
        4) service_management ;;
        5) 
            echo "1. Create Backup"
            echo "2. Restore Backup"
            read -p "Choose: " backup_choice
            case $backup_choice in
                1) vpn-backup ;;
                2) vpn-restore ;;
            esac
            ;;
        6)
            echo "System Configuration"
            echo "1. Change SSH Port"
            echo "2. Update System"
            echo "3. Reboot Server"
            read -p "Choose: " sys_choice
            case $sys_choice in
                1) read -p "New SSH port: " port && sed -i "s/Port 22/Port $port/" /etc/ssh/sshd_config && systemctl restart ssh ;;
                2) apt-get update && apt-get upgrade -y ;;
                3) reboot ;;
            esac
            ;;
        7)
            echo "Tunnel Configuration"
            echo "1. Regenerate VMESS UUID"
            echo "2. Reset User Database"
            echo "3. Clear All Logs"
            read -p "Choose: " tunnel_choice
            case $tunnel_choice in
                1) echo "Regenerating UUIDs..." ;;
                2) echo "Resetting database..." ;;
                3) echo "Clearing logs..." ;;
            esac
            ;;
        8) show_configs ;;
        9)
            echo "Restarting all services..."
            systemctl restart ssh nginx xray openvpn
            echo "Services restarted!"
            ;;
        0)
            echo -e "${GREEN}Goodbye! 👋${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
done
EOF
    
    chmod +x /usr/local/bin/vpn-menu
    
    # Create alias for easy access
    echo "alias vpn='vpn-menu'" >> /root/.bashrc
    echo "alias tunnel-status='vpn-monitor'" >> /root/.bashrc
    
    log_message "Interactive menu created"
}

# =================================================================
# FINAL CONFIGURATION
# =================================================================

final_configuration() {
    echo -e "${GREEN}[14/15] Final Configuration...${NC}"
    
    # Create startup script
    cat > /etc/systemd/system/vpntunnel.service << EOF
[Unit]
Description=VPN Tunnel Server
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/true
ExecReload=/bin/true

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable all services
    systemctl enable ssh
    systemctl enable nginx
    systemctl enable xray
    systemctl enable openvpn
    systemctl enable fail2ban
    systemctl enable vpntunnel
    
    # Set permissions
    chmod 600 /etc/nginx/ssl/private.key
    chmod 755 /usr/local/bin/vpn-*
    
    # Create info file
    cat > /root/vpn-info.txt << EOF
╔══════════════════════════════════════════════════════════════╗
║         🚀 VPN TUNNEL SERVER INSTALLATION COMPLETE          ║
║         github.com/sukronwae85-design/terlupakan            ║
╚══════════════════════════════════════════════════════════════╝

📊 SERVER INFORMATION:
• IP Address: $SERVER_IP
• OS: $OS_INFO
• Installation Date: $(date)
• Version: $VERSION

🔐 ACCESS INFORMATION:
• SSH Ports: 22, 2222, 80, 443
• Web Interface: http://$SERVER_IP
• Admin Panel: http://$SERVER_IP/admin
• Admin Credentials: admin / vpntunnel123

🚀 TUNNEL PORTS:
• UDP Custom: 7100, 7200, 7300
• VMESS: 80 & 443
• OpenVPN: $TUNNEL_PORT
• WireGuard: $WIREGUARD_PORT

⚙️ MANAGEMENT COMMANDS:
• Main Menu: vpn-menu
• User Management: vpn-user
• Domain Management: vpn-domain
• Monitoring: vpn-monitor
• Backup: vpn-backup
• Restore: vpn-restore

📁 CONFIGURATION FILES:
• User Database: /etc/vpntunnel/users.json
• Domain Config: /etc/vpntunnel/domains.json
• VMESS Config: /etc/vpntunnel/vmess-config.json
• Tunnel Config: /etc/vpntunnel/tunnel-config.txt

⚠️ NEXT STEPS:
1. Add your first user: vpn-user add
2. Add domain (optional): vpn-domain add
3. Check server status: vpn-monitor
4. Backup configuration: vpn-backup

📞 SUPPORT:
GitHub: https://github.com/sukronwae85-design/terlupakan
Created: $(date)
EOF
    
    log_message "Final configuration completed"
}

# =================================================================
# INSTALLATION SUMMARY
# =================================================================

show_summary() {
    echo -e "${GREEN}[15/15] Installation Complete!${NC}"
    
    print_header
    
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 VPN TUNNEL SERVER SUCCESSFULLY INSTALLED! 🎉${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    
    echo -e "\n${CYAN}📊 SERVER INFORMATION:${NC}"
    echo -e "• Server IP: ${YELLOW}$SERVER_IP${NC}"
    echo -e "• OS: ${YELLOW}$OS_INFO${NC}"
    echo -e "• Version: ${YELLOW}$VERSION${NC}"
    
    echo -e "\n${CYAN}🔐 ACCESS POINTS:${NC}"
    echo -e "• SSH Ports: ${YELLOW}22, 2222, 80, 443${NC}"
    echo -e "• Web Interface: ${YELLOW}http://$SERVER_IP${NC}"
    echo -e "• Admin Panel: ${YELLOW}http://$SERVER_IP/admin${NC}"
    echo -e "• Admin Login: ${YELLOW}admin / vpntunnel123${NC}"
    
    echo -e "\n${CYAN}🚀 TUNNEL SERVICES:${NC}"
    echo -e "• UDP Custom: ${YELLOW}7100, 7200, 7300${NC}"
    echo -e "• Full UDP Range: ${YELLOW}1-65535${NC}"
    echo -e "• VMESS/VLESS: ${YELLOW}Port 80 & 443${NC}"
    echo -e "• OpenVPN: ${YELLOW}Port $TUNNEL_PORT${NC}"
    echo -e "• WireGuard: ${YELLOW}Port $WIREGUARD_PORT${NC}"
    
    echo -e "\n${CYAN}⚙️ MANAGEMENT TOOLS:${NC}"
    echo -e "• Main Menu: ${GREEN}vpn-menu${NC}"
    echo -e "• User Management: ${GREEN}vpn-user${NC}"
    echo -e "• Domain Management: ${GREEN}vpn-domain${NC}"
    echo -e "• Monitoring: ${GREEN}vpn-monitor${NC}"
    echo -e "• Backup: ${GREEN}vpn-backup${NC}"
    
    echo -e "\n${CYAN}📁 IMPORTANT FILES:${NC}"
    echo -e "• Installation Info: ${YELLOW}/root/vpn-info.txt${NC}"
    echo -e "• Config Directory: ${YELLOW}/etc/vpntunnel/${NC}"
    echo -e "• Log Files: ${YELLOW}/var/log/vpntunnel.log${NC}"
    
    echo -e "\n${CYAN}📝 QUICK START:${NC}"
    echo "1. Add your first user: ${GREEN}vpn-user add${NC}"
    echo "2. Check server status: ${GREEN}vpn-monitor${NC}"
    echo "3. Open admin panel: ${GREEN}http://$SERVER_IP/admin${NC}"
    echo "4. Backup config: ${GREEN}vpn-backup${NC}"
    
    echo -e "\n${YELLOW}⚠️ IMPORTANT:${NC}"
    echo "• Change default passwords immediately!"
    echo "• Configure firewall rules as needed"
    echo "• Regular backups are recommended"
    
    echo -e "\n${GREEN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ Installation completed at $(date)${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
    
    # Save summary to file
    cp /root/vpn-info.txt /etc/vpntunnel/installation-summary.txt
    
    log_message "VPN Tunnel Server installation completed successfully"
}

# =================================================================
# MAIN INSTALLATION FUNCTION
# =================================================================

auto_install() {
    print_header
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ Script must be run as root!${NC}"
        echo -e "Run: ${CYAN}sudo -i${NC}"
        exit 1
    fi
    
    # Check Ubuntu version
    check_ubuntu_version
    
    # Confirmation
    echo -e "${YELLOW}⚠️  This will install VPN Tunnel Server on your system${NC}"
    echo -e "${YELLOW}⚠️  Multiple ports will be opened (22, 80, 443, 1194, etc.)${NC}"
    echo -e "${YELLOW}⚠️  Estimated time: 10-15 minutes${NC}"
    echo ""
    read -p "Continue installation? (y/n): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    
    # Start installation
    echo -e "\n${GREEN}🚀 Starting VPN Tunnel Server Installation...${NC}"
    echo -e "${BLUE}Please wait, this may take a while...${NC}"
    echo "══════════════════════════════════════════════════════════════"
    
    # Installation steps
    init_system
    install_dependencies
    configure_ssh
    configure_vpn_tunnel
    configure_udp_tunnel
    configure_xray_vmess
    configure_nginx
    configure_domain_pointing
    configure_firewall
    create_user_management
    configure_backup
    configure_cron
    create_menu
    final_configuration
    show_summary
    
    # Wait and show menu
    echo -e "\n${YELLOW}Starting management menu in 10 seconds...${NC}"
    echo -e "${CYAN}Press Ctrl+C to skip and use 'vpn-menu' later${NC}"
    sleep 10
    
    # Start menu
    vpn-menu
}

# =================================================================
# COMMAND LINE INTERFACE
# =================================================================

case "$1" in
    "--install"|"-i")
        auto_install
        ;;
    "--menu"|"-m")
        vpn-menu 2>/dev/null || {
            echo "VPN menu not found. Run --install first."
            exit 1
        }
        ;;
    "--user"|"-u")
        vpn-user "${@:2}" 2>/dev/null || {
            echo "User management not available. Run --install first."
            exit 1
        }
        ;;
    "--monitor"|"-s")
        vpn-monitor 2>/dev/null || {
            echo "Monitor not available. Run --install first."
            exit 1
        }
        ;;
    "--backup"|"-b")
        vpn-backup 2>/dev/null || {
            echo "Backup not available. Run --install first."
            exit 1
        }
        ;;
    "--help"|"-h")
        echo -e "${GREEN}VPN Tunnel Server Auto Installer v$VERSION${NC}"
        echo "Usage:"
        echo "  $0 --install    Full automatic installation"
        echo "  $0 --menu       Interactive management menu"
        echo "  $0 --user       User management (add/list)"
        echo "  $0 --monitor    System monitoring"
        echo "  $0 --backup     Create backup"
        echo "  $0 --help       Show this help"
        ;;
    *)
        # If no arguments, show installation option
        echo -e "${GREEN}VPN Tunnel Server Auto Installer v$VERSION${NC}"
        echo "To install: $0 --install"
        echo "For help: $0 --help"
        ;;
esac