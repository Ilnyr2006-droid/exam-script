#!/bin/bash
# ИСПРАВЛЕННАЯ ВЕРСИЯ 3.0 (Full DNS, ISP Routes, No Switch, Uniform Passwords)
# Поддерживаемые роли: hq-srv, br-srv, hq-rtr, br-rtr, isp, hq-cli

# --- Чиним пути ---
export PATH=$PATH:/usr/sbin:/sbin:/usr/bin:/bin

# --- Авто-определение интерфейса ---
REAL_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)
if [ -z "$REAL_IFACE" ]; then REAL_IFACE="ens33"; fi
echo ">>> Обнаружен основной интерфейс: $REAL_IFACE"

# --- Чиним DNS для установки пакетов ---
echo "nameserver 8.8.8.8" > /etc/resolv.conf

ROLE=$1
DOMAIN="au-team.irpo"

if [ -z "$ROLE" ]; then
    echo "Использование: ./setup.sh [роль]"
    exit 1
fi

echo "=== НАСТРОЙКА РОЛИ: $ROLE ==="

# --- Имя и Время ---
hostnamectl set-hostname "${ROLE}.${DOMAIN}"
timedatectl set-timezone Europe/Moscow

# --- Функция установки ---
install_pkg() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" $@
}

# --- Пользователи (Пароль P@ssw0rd везде) ---
setup_users() {
    echo ">>> Настройка пользователей..."
    if [[ "$ROLE" == *"srv"* ]]; then
        adduser --gecos "" remote_user --disabled-password || true
        adduser --uid 2026 --gecos "" sshuser --disabled-password || true
        # ЕДИНЫЙ ПАРОЛЬ: P@ssw0rd (с нулем)
        echo "sshuser:P@ssw0rd" | chpasswd
        usermod -aG sudo sshuser
        echo 'sshuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sshuser
    fi
    if [[ "$ROLE" == *"rtr"* ]]; then
        adduser --gecos "" net_admin --disabled-password || true
        echo "net_admin:P@ssw0rd" | chpasswd
        usermod -aG sudo net_admin
        echo 'net_admin ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/net_admin
    fi
    if [[ "$ROLE" == "hq-cli" ]]; then
         echo "root:P@ssw0rd" | chpasswd
    fi
}

# --- SSH (Порт 2026) ---
setup_ssh() {
    echo ">>> Настройка SSH..."
    apt-get update
    install_pkg openssh-server
    echo "Authorized access only" > /etc/issue.net
    
    sed -i 's/#Port 22/Port 2026/' /etc/ssh/sshd_config
    sed -i 's/Port 22/Port 2026/' /etc/ssh/sshd_config
    sed -i 's/#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/' /etc/ssh/sshd_config
    
    if [[ "$ROLE" == *"srv"* ]]; then
        echo "AllowUsers sshuser" >> /etc/ssh/sshd_config
    elif [[ "$ROLE" == *"rtr"* ]]; then
        echo "AllowUsers net_admin" >> /etc/ssh/sshd_config
    fi
    systemctl restart ssh
}

# --- ЛОГИКА ПО РОЛЯМ ---
case $ROLE in
    "hq-srv")
        setup_users
        setup_ssh
        # Настраиваем интерфейс (Предполагаем прямое подключение без тегов со стороны сервера)
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet static
    address 192.168.10.2/27
    gateway 192.168.10.1
EOF
        systemctl restart networking
        
        echo ">>> Установка Bind9 и всех зон..."
        install_pkg bind9
        
        # Options
        cat <<EOF > /etc/bind/named.conf.options
options {
    directory "/var/cache/bind";
    forwarders { 8.8.8.8; };
    recursion yes;
    allow-query { any; };
    listen-on { any; };
    allow-recursion { any; };
};
EOF
        # Local Zones Definition
        cat <<EOF > /etc/bind/named.conf.local
zone "au-team.irpo" { type master; file "/etc/bind/zones/db.au-team.irpo"; };
zone "10.168.192.in-addr.arpa" { type master; file "/etc/bind/zones/db.10.168.192"; };
zone "20.168.192.in-addr.arpa" { type master; file "/etc/bind/zones/db.20.168.192"; };
zone "1.16.172.in-addr.arpa" { type master; file "/etc/bind/zones/db.1.16.172"; };
zone "2.16.172.in-addr.arpa" { type master; file "/etc/bind/zones/db.2.16.172"; };
zone "100.168.192.in-addr.arpa" { type master; file "/etc/bind/zones/db.100.168.192"; };
EOF
        mkdir -p /etc/bind/zones

        # 1. Прямая зона
        cat <<EOF > /etc/bind/zones/db.au-team.irpo
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
hq-srv IN A 192.168.10.2
hq-rtr IN A 172.16.1.2
br-rtr IN A 172.16.2.2
br-srv IN A 192.168.100.2
hq-cli IN A 192.168.20.10
docker IN A 172.16.1.1
web    IN A 172.16.2.1
EOF

        # 2. Обратная зона HQ (192.168.10.x)
        cat <<EOF > /etc/bind/zones/db.10.168.192
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
2 IN PTR hq-srv.au-team.irpo.
EOF

        # 3. Обратная зона CLI (192.168.20.x)
        cat <<EOF > /etc/bind/zones/db.20.168.192
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
10 IN PTR hq-cli.au-team.irpo.
EOF

        # 4. Обратная зона WAN HQ (172.16.1.x)
        cat <<EOF > /etc/bind/zones/db.1.16.172
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
1 IN PTR docker.au-team.irpo.
2 IN PTR hq-rtr.au-team.irpo.
EOF

        # 5. Обратная зона WAN BR (172.16.2.x)
        cat <<EOF > /etc/bind/zones/db.2.16.172
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
1 IN PTR web.au-team.irpo.
2 IN PTR br-rtr.au-team.irpo.
EOF

        # 6. Обратная зона BR (192.168.100.x)
        cat <<EOF > /etc/bind/zones/db.100.168.192
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
2 IN PTR br-srv.au-team.irpo.
EOF
        systemctl restart bind9
        ;;

    "br-srv")
        setup_users
        setup_ssh
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet static
    address 192.168.100.2/27
    gateway 192.168.100.1
EOF
        systemctl restart networking
        ;;

    "hq-rtr")
        setup_users
        setup_ssh
        echo "ip_gre" >> /etc/modules
        modprobe ip_gre
        
        # Настройка VLAN (Router-on-a-stick)
        # ВНИМАНИЕ: Если нет свитча, убедитесь, что ens37 в виртуалке подключен к правильному сегменту
        cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback

auto $REAL_IFACE
iface $REAL_IFACE inet static
    address 172.16.1.2/28
    gateway 172.16.1.1

auto ens37
iface ens37 inet manual

# VLAN 100 для Сервера
auto ens37.100
iface ens37.100 inet static
    address 192.168.10.1/27
    vlan_raw_device ens37

# VLAN 200 для Клиентов
auto ens37.200
iface ens37.200 inet static
    address 192.168.20.1/28
    vlan_raw_device ens37

# VLAN 999 (Management)
auto ens37.999
iface ens37.999 inet static
    address 192.168.20.1/29
    vlan_raw_device ens37

auto gre30
iface gre30 inet tunnel
    address 10.0.0.1
    netmask 255.255.255.252
    mode gre
    local 172.16.1.2
    endpoint 172.16.2.2
    ttl 255
    mtu 1476
    post-up ip route replace 192.168.100.0/28 via 10.0.0.2
EOF
        systemctl restart networking

        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        install_pkg iptables-persistent
        
        # NAT для VLAN сетей
        iptables -t nat -A POSTROUTING -o ens37.100 -j MASQUERADE
        iptables -t nat -A POSTROUTING -o ens37.200 -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4

        install_pkg isc-dhcp-server
        sed -i 's/INTERFACESv4=""/INTERFACESv4="ens37.200"/' /etc/default/isc-dhcp-server
        cat <<EOF > /etc/dhcp/dhcpd.conf
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet 192.168.20.0 netmask 255.255.255.240 {
    range 192.168.20.2 192.168.20.14;
    option routers 192.168.20.1;
    option domain-name "au-team.irpo";
    option domain-name-servers 192.168.10.2;
}
EOF
        systemctl restart isc-dhcp-server

        install_pkg frr
        sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons
        systemctl restart frr
        cat <<EOF > /etc/frr/frr.conf
frr version 8.1
frr defaults traditional
hostname hq-rtr
interface gre30
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 1c+rYtGm
!
router ospf
 network 192.168.100.0/27 area 0
 network 10.0.0.0/30 area 0
!
line vty
EOF
        systemctl restart frr
        ;;

    "br-rtr")
        setup_users
        setup_ssh
        echo "ip_gre" >> /etc/modules
        modprobe ip_gre

        cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback
auto $REAL_IFACE
iface $REAL_IFACE inet static
    address 172.16.2.2/28
    gateway 172.16.2.1
auto ens37
iface ens37 inet static
    address 192.168.100.1/27
auto gre30
iface gre30 inet tunnel
    address 10.0.0.2
    netmask 255.255.255.252
    mode gre
    local 172.16.2.2
    endpoint 172.16.1.2
    ttl 255
    mtu 1476
    post-up ip route replace 192.168.10.0/28 via 10.0.0.1
    post-up ip route replace 192.168.20.0/28 via 10.0.0.1
EOF
        systemctl restart networking

        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        install_pkg iptables-persistent
        iptables -t nat -A POSTROUTING -o $REAL_IFACE -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4

        install_pkg frr
        sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons
        systemctl restart frr
        cat <<EOF > /etc/frr/frr.conf
frr version 8.1
frr defaults traditional
hostname br-rtr
interface gre30
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 1c+rYtGm
!
router ospf
 network 192.168.0.0/28 area 0
 network 10.0.0.0/30 area 0
!
line vty
EOF
        systemctl restart frr
        ;;

    "isp")
        # Добавляем маршруты прямо в конфиг интерфейса, чтобы они применялись при старте
        cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback

auto $REAL_IFACE
iface $REAL_IFACE inet dhcp

auto ens37
iface ens37 inet static
    address 172.16.1.1/28
    # Маршрут к офису HQ
    up ip route add 192.168.10.0/27 via 172.16.1.2

auto ens38
iface ens38 inet static
    address 172.16.2.1/28
    # Маршрут к офису Branch
    up ip route add 192.168.100.0/27 via 172.16.2.2
EOF
        systemctl restart networking

        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        install_pkg iptables-persistent
        iptables -t nat -A POSTROUTING -o $REAL_IFACE -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4
        
        install_pkg chrony
        echo "server 0.debian.pool.ntp.org iburst" > /etc/chrony/chrony.conf
        echo "local stratum 5" >> /etc/chrony/chrony.conf
        echo "allow 172.16.0.0/12" >> /etc/chrony/chrony.conf
        echo "allow 192.168.0.0/16" >> /etc/chrony/chrony.conf
        systemctl restart chrony
        ;;

    "hq-cli")
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet dhcp
EOF
        cat <<EOF > /etc/resolv.conf
search au.team.irpo
domain au.team.irpo
nameserver 192.168.10.2
EOF
        systemctl restart networking
        ;;
esac

echo "--- НАСТРОЙКА ЗАВЕРШЕНА. ПРОВЕРЬТЕ IP (ip a) ---"