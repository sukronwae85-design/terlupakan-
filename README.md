 CARA AUTO INSTALL DI VPS ANDA:
1. Upload ke GitHub:

Buka https://github.com/sukronwae85-design/terlupakan
Upload file install.sh dengan script di atas.
2. PERINTAH AUTO INSTALL 1 BARIS:
bash

# Jalankan ini saja di VPS Ubuntu Anda:
sudo -i && bash <(curl -s https://raw.githubusercontent.com/sukronwae85-design/terlupakan/main/install.sh) --install

3. Atau jika pakai wget:
bash

sudo -i && bash <(wget -qO- https://raw.githubusercontent.com/sukronwae85-design/terlupakan/main/install.sh) --install

📦 FITUR YANG TERINSTALL:
✅ VPN TUNNEL SERVER:

    SSH Server (22, 2222, 80, 443)

    UDP Custom Tunnel (7100, 7200, 7300, 1-65535)

    VMESS/VLESS/Trojan (Port 80 & 443)

    OpenVPN (Port 1194)

    WireGuard (Port 51820)

✅ DOMAIN POINTING:

    Auto SSL dengan Let's Encrypt

    Nginx Reverse Proxy

    Multi-domain support

✅ MANAGEMENT:

    Interactive menu: vpn-menu

    User management: vpn-user

    Monitoring: vpn-monitor

    Backup: vpn-backup

    Domain: vpn-domain

✅ WEB INTERFACE:

    Dashboard: http://SERVER_IP

    Admin Panel: http://SERVER_IP/admin

    Status monitoring real-time

**🎯 UNTUK VPS UBUNTU 18.04/20.
This response is AI-generated, for reference only.
