#!/bin/bash
# ИСПРАВЛЕННАЯ ВЕРСИЯ 3.0 (Full DNS, ISP Routes, No Switch, Uniform Passwords)
# Поддерживаемые роли: hq-srv, br-srv, hq-rtr, br-rtr, isp, hq-cli

# --- Чиним пути ---
export PATH=$PATH:/usr/sbin:/sbin:/usr/bin:/bin

# --- Авто-определение интерфейса ---
REAL_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)
if [ -z "$REAL_IFACE" ]; then REAL_IFACE="ens33"; fi
echo ">>> Обнаружен основной интерфейс: $REAL_IFACE"

ROLE=$1
DOMAIN="au-team.irpo"
VALID_ROLES="hq-srv br-srv hq-rtr br-rtr isp hq-cli"

if [ -z "$ROLE" ]; then
    echo "Использование: ./setup.sh [роль]"
    exit 1
fi
if ! echo "$VALID_ROLES" | grep -qw "$ROLE"; then
    echo "Ошибка: неизвестная роль '$ROLE'"
    echo "Доступные роли: $VALID_ROLES"
    exit 1
fi

echo "=== НАСТРОЙКА РОЛИ: $ROLE ==="

# --- Ввод IP-адресов (Enter = оставить значение по умолчанию) ---
prompt_var() {
    local var_name="$1"
    local default_val="$2"
    local prompt_text="$3"
    local input=""
    read -r -p "$prompt_text [$default_val]: " input
    if [ -z "$input" ]; then
        eval "$var_name=\"$default_val\""
    else
        eval "$var_name=\"$input\""
    fi
}

# --- Ввод интерфейсов (если имена отличаются) ---
prompt_var HQ_RTR_LAN_IFACE "ens37" "HQ-RTR LAN интерфейс (для VLAN 100/200/999)"
prompt_var BR_RTR_LAN_IFACE "ens37" "BR-RTR LAN интерфейс (в сторону BR-SRV)"
prompt_var ISP_HQ_IFACE "ens37" "ISP интерфейс в сторону HQ-RTR"
prompt_var ISP_BR_IFACE "ens38" "ISP интерфейс в сторону BR-RTR"

# IP адреса (с CIDR там, где нужно)
prompt_var HQ_SRV_IP_CIDR "192.168.10.2/27" "HQ-SRV IP/CIDR"
prompt_var BR_SRV_IP_CIDR "192.168.100.2/27" "BR-SRV IP/CIDR"
prompt_var HQ_RTR_WAN_IP_CIDR "172.16.1.2/28" "HQ-RTR WAN IP/CIDR"
prompt_var BR_RTR_WAN_IP_CIDR "172.16.2.2/28" "BR-RTR WAN IP/CIDR"
prompt_var HQ_RTR_VLAN100_IP_CIDR "192.168.10.1/27" "HQ-RTR VLAN100 IP/CIDR"
prompt_var HQ_RTR_VLAN200_IP_CIDR "192.168.20.1/28" "HQ-RTR VLAN200 IP/CIDR"
prompt_var HQ_RTR_VLAN999_IP_CIDR "192.168.250.1/29" "HQ-RTR VLAN999 IP/CIDR"
prompt_var BR_RTR_LAN_IP_CIDR "192.168.100.1/27" "BR-RTR LAN IP/CIDR"
prompt_var HQ_CLI_IP_CIDR "192.168.20.2/28" "HQ-CLI IP/CIDR"
prompt_var ISP_HQ_IP_CIDR "172.16.1.1/28" "ISP IP toward HQ (ens37) IP/CIDR"
prompt_var ISP_BR_IP_CIDR "172.16.2.1/28" "ISP IP toward BR (ens38) IP/CIDR"

# Сети (для маршрутов, DHCP, OSPF)
prompt_var HQ_SRV_NET "192.168.10.0/27" "HQ-SRV network/CIDR"
prompt_var HQ_CLI_NET "192.168.20.0/28" "HQ-CLI network/CIDR"
prompt_var BR_SRV_NET "192.168.100.0/27" "BR-SRV network/CIDR"
prompt_var GRE_NET "10.0.0.0/30" "GRE network/CIDR"
prompt_var GRE_HQ_IP "10.0.0.1" "GRE IP on HQ-RTR (no CIDR)"
prompt_var GRE_BR_IP "10.0.0.2" "GRE IP on BR-RTR (no CIDR)"
prompt_var GRE_NETMASK "255.255.255.252" "GRE netmask"
prompt_var DHCP_RANGE_START "192.168.20.2" "DHCP range start (HQ-CLI)"
prompt_var DHCP_RANGE_END "192.168.20.14" "DHCP range end (HQ-CLI)"

# Подсказка: шлюзы берем как IP ISP или .1 внутри подсети
HQ_SRV_GW="${HQ_RTR_VLAN100_IP_CIDR%%/*}"
BR_SRV_GW="${BR_RTR_LAN_IP_CIDR%%/*}"
HQ_RTR_WAN_GW="${ISP_HQ_IP_CIDR%%/*}"
BR_RTR_WAN_GW="${ISP_BR_IP_CIDR%%/*}"
HQ_CLI_GW="${HQ_RTR_VLAN200_IP_CIDR%%/*}"

# Короткие IP без CIDR
HQ_SRV_IP="${HQ_SRV_IP_CIDR%%/*}"
BR_SRV_IP="${BR_SRV_IP_CIDR%%/*}"
HQ_RTR_WAN_IP="${HQ_RTR_WAN_IP_CIDR%%/*}"
BR_RTR_WAN_IP="${BR_RTR_WAN_IP_CIDR%%/*}"
HQ_RTR_VLAN100_IP="${HQ_RTR_VLAN100_IP_CIDR%%/*}"
HQ_RTR_VLAN200_IP="${HQ_RTR_VLAN200_IP_CIDR%%/*}"
HQ_RTR_VLAN999_IP="${HQ_RTR_VLAN999_IP_CIDR%%/*}"
BR_RTR_LAN_IP="${BR_RTR_LAN_IP_CIDR%%/*}"
HQ_CLI_IP="${HQ_CLI_IP_CIDR%%/*}"
ISP_HQ_IP="${ISP_HQ_IP_CIDR%%/*}"
ISP_BR_IP="${ISP_BR_IP_CIDR%%/*}"

last_octet() { echo "${1##*.}"; }
cidr_to_netmask() {
    local cidr="$1"
    local i mask=""
    for i in 1 2 3 4; do
        local octet
        if [ "$cidr" -ge 8 ]; then
            octet=255
            cidr=$((cidr - 8))
        else
            octet=$((256 - 2 ** (8 - cidr)))
            cidr=0
        fi
        mask+="$octet"
        [ "$i" -lt 4 ] && mask+="."
    done
    echo "$mask"
}

HQ_CLI_NET_ADDR="${HQ_CLI_NET%%/*}"
HQ_CLI_NET_CIDR="${HQ_CLI_NET##*/}"
HQ_CLI_NETMASK="$(cidr_to_netmask "$HQ_CLI_NET_CIDR")"
BR_SRV_NET_ADDR="${BR_SRV_NET%%/*}"

reverse_zone_24_from_ip() {
    local ip="$1"
    IFS=. read -r o1 o2 o3 o4 <<<"$ip"
    echo "${o3}.${o2}.${o1}.in-addr.arpa"
}

# Подстраховка, если сети пустые
if [ -z "$HQ_SRV_NET_ADDR" ]; then HQ_SRV_NET_ADDR="${HQ_SRV_IP%.*}.0"; fi
if [ -z "$HQ_CLI_NET_ADDR" ]; then HQ_CLI_NET_ADDR="${HQ_CLI_IP%.*}.0"; fi
if [ -z "$BR_SRV_NET_ADDR" ]; then BR_SRV_NET_ADDR="${BR_SRV_IP%.*}.0"; fi

HQ_SRV_REV_ZONE="$(reverse_zone_24_from_ip "$HQ_SRV_NET_ADDR")"
HQ_CLI_REV_ZONE="$(reverse_zone_24_from_ip "$HQ_CLI_NET_ADDR")"
BR_SRV_REV_ZONE="$(reverse_zone_24_from_ip "$BR_SRV_NET_ADDR")"
HQ_WAN_REV_ZONE="$(reverse_zone_24_from_ip "$HQ_RTR_WAN_IP")"
BR_WAN_REV_ZONE="$(reverse_zone_24_from_ip "$BR_RTR_WAN_IP")"

validate_rev_zone() {
    case "$1" in
        ""|*..*|*"...in-addr.arpa"*) return 1 ;;
    esac
    return 0
}
for z in "$HQ_SRV_REV_ZONE" "$HQ_CLI_REV_ZONE" "$BR_SRV_REV_ZONE" "$HQ_WAN_REV_ZONE" "$BR_WAN_REV_ZONE"; do
    if ! validate_rev_zone "$z"; then
        echo "Ошибка: не удалось вычислить reverse-зону. Проверьте введенные IP/сети."
        exit 1
    fi
done

# --- DNS по заданию ---
if [ "$ROLE" != "isp" ]; then
    if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf 2>/dev/null; then
cat <<EOF > /etc/resolv.conf
search au.team.irpo
domain au.team.irpo
nameserver 8.8.8.8
EOF
    fi
fi

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
    # Убираем возможный lock от packagekit
    systemctl stop packagekit || true
    systemctl stop packagekitd || true
    apt-get update
    install_pkg openssh-server
    echo "Authorized access only" > /etc/issue.net
    
    sed -i 's/#Port 22/Port 2026/' /etc/ssh/sshd_config
    sed -i 's/Port 22/Port 2026/' /etc/ssh/sshd_config
    sed -i 's/#Banner none/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 2/' /etc/ssh/sshd_config
    # Разрешаем парольную аутентификацию
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
    
    if [[ "$ROLE" == *"srv"* ]]; then
        echo "AllowUsers sshuser" >> /etc/ssh/sshd_config
    elif [[ "$ROLE" == *"rtr"* ]]; then
        echo "AllowUsers net_admin" >> /etc/ssh/sshd_config
    fi
    systemctl restart ssh || systemctl restart sshd
}

# --- ЛОГИКА ПО РОЛЯМ ---
case $ROLE in
    "hq-srv")
        setup_users
        setup_ssh
        # VLAN-интерфейс для HQ-SRV (ens33.100)
        echo "8021q" >> /etc/modules
        modprobe 8021q
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet manual

auto ${REAL_IFACE}.100
iface ${REAL_IFACE}.100 inet static
    address $HQ_SRV_IP_CIDR
    gateway $HQ_SRV_GW
    vlan_raw_device $REAL_IFACE
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
// Прямая зона
zone "au-team.irpo" {
    type master;
    file "/etc/bind/zones/db.au-team.irpo";
};

// Обратная зона для серверов (192.168.10.x)
zone "10.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.10.168.192.in-addr.arpa";
};

// Обратная зона для клиентов (192.168.20.x)
zone "20.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.20.168.192.in-addr.arpa";
};

// Обратная зона для WAN HQ (172.16.1.x)
zone "1.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.1.16.172.in-addr.arpa";
};

// Обратная зона для WAN BR (172.16.2.x)
zone "2.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.2.16.172.in-addr.arpa";
};

// Обратная зона для филиала (192.168.100.x)
zone "100.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.100.168.192.in-addr.arpa";
};
EOF
        # На HQ-SRV не используем samba-dlz (это только для BR-SRV)
        sed -i '/samba-dlz/d' /etc/bind/named.conf.local
        mkdir -p /etc/bind/zones

        # 1. Прямая зона
        cat <<EOF > /etc/bind/zones/db.au-team.irpo
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
hq-srv IN A $HQ_SRV_IP
hq-rtr IN A $HQ_RTR_WAN_IP
br-rtr IN A $BR_RTR_WAN_IP
br-srv IN A $BR_SRV_IP
hq-cli IN A $HQ_CLI_IP
docker IN A $ISP_HQ_IP
web    IN A $ISP_BR_IP
EOF

        # 2. Обратная зона HQ (192.168.10.x)
        cat <<EOF > /etc/bind/zones/db.10.168.192.in-addr.arpa
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
$(last_octet "$HQ_SRV_IP") IN PTR hq-srv.au-team.irpo.
EOF

        # 3. Обратная зона CLI (192.168.20.x)
        cat <<EOF > /etc/bind/zones/db.20.168.192.in-addr.arpa
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
$(last_octet "$HQ_CLI_IP") IN PTR hq-cli.au-team.irpo.
EOF

        # 4. Обратная зона WAN HQ (172.16.1.x)
        cat <<EOF > /etc/bind/zones/db.1.16.172.in-addr.arpa
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
$(last_octet "$ISP_HQ_IP") IN PTR docker.au-team.irpo.
$(last_octet "$HQ_RTR_WAN_IP") IN PTR hq-rtr.au-team.irpo.
EOF

        # 5. Обратная зона WAN BR (172.16.2.x)
        cat <<EOF > /etc/bind/zones/db.2.16.172.in-addr.arpa
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
$(last_octet "$ISP_BR_IP") IN PTR web.au-team.irpo.
$(last_octet "$BR_RTR_WAN_IP") IN PTR br-rtr.au-team.irpo.
EOF

        # 6. Обратная зона BR (192.168.100.x)
        cat <<EOF > /etc/bind/zones/db.100.168.192.in-addr.arpa
\$TTL 604800
@ IN SOA hq-srv.au-team.irpo. root.au-team.irpo. ( 2026020201 604800 86400 2419200 604800 )
@ IN NS hq-srv.au-team.irpo.
$(last_octet "$BR_SRV_IP") IN PTR br-srv.au-team.irpo.
EOF
        # Проверка и запуск DNS
        named-checkconf -z >/dev/null 2>&1 || true
        systemctl restart named >/dev/null 2>&1 || systemctl restart bind9
        # Быстрая проверка, что DNS отвечает локально
        nslookup hq-srv.${DOMAIN} 127.0.0.1 >/dev/null 2>&1 || true
        ;;

    "br-srv")
        setup_users
        setup_ssh
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet static
    address $BR_SRV_IP_CIDR
    gateway $BR_SRV_GW
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
    address $HQ_RTR_WAN_IP_CIDR
    gateway $HQ_RTR_WAN_GW

auto $HQ_RTR_LAN_IFACE
iface $HQ_RTR_LAN_IFACE inet manual

# VLAN 100 для Сервера
auto ${HQ_RTR_LAN_IFACE}.100
iface ${HQ_RTR_LAN_IFACE}.100 inet static
    address $HQ_RTR_VLAN100_IP_CIDR
    vlan_raw_device $HQ_RTR_LAN_IFACE

# VLAN 200 для Клиентов
auto ${HQ_RTR_LAN_IFACE}.200
iface ${HQ_RTR_LAN_IFACE}.200 inet static
    address $HQ_RTR_VLAN200_IP_CIDR
    vlan_raw_device $HQ_RTR_LAN_IFACE

# VLAN 999 (Management)
auto ${HQ_RTR_LAN_IFACE}.999
iface ${HQ_RTR_LAN_IFACE}.999 inet static
    address $HQ_RTR_VLAN999_IP_CIDR
    vlan_raw_device $HQ_RTR_LAN_IFACE

auto gre30
iface gre30 inet tunnel
    address $GRE_HQ_IP
    netmask $GRE_NETMASK
    mode gre
    local $HQ_RTR_WAN_IP
    endpoint $BR_RTR_WAN_IP
    ttl 255
    mtu 1476
    post-up ip route replace $BR_SRV_NET via $GRE_BR_IP
EOF
        systemctl restart networking

        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p
        
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
        install_pkg iptables-persistent
        
        # NAT наружу через WAN-интерфейс
        iptables -t nat -A POSTROUTING -o $REAL_IFACE -j MASQUERADE
        iptables-save > /etc/iptables/rules.v4

        install_pkg isc-dhcp-server
        sed -i "s/INTERFACESv4=\"\"/INTERFACESv4=\"${HQ_RTR_LAN_IFACE}.200\"/" /etc/default/isc-dhcp-server
        cat <<EOF > /etc/dhcp/dhcpd.conf
default-lease-time 600;
max-lease-time 7200;
authoritative;
subnet $HQ_CLI_NET_ADDR netmask $HQ_CLI_NETMASK {
    range $DHCP_RANGE_START $DHCP_RANGE_END;
    option routers $HQ_CLI_GW;
    option domain-name "au-team.irpo";
    option domain-name-servers $HQ_SRV_IP;
}
EOF
        systemctl restart isc-dhcp-server

        install_pkg frr
        sed -i 's/ospfd=no/ospfd=yes/' /etc/frr/daemons
        systemctl restart frr
        # Проверка vtysh (иногда в /usr/bin или /usr/lib/frr)
        if ! command -v vtysh >/dev/null 2>&1 && [ ! -x /usr/lib/frr/vtysh ]; then
            install_pkg frr-pythontools
        fi
        cat <<EOF > /etc/frr/frr.conf
frr version 8.1
frr defaults traditional
hostname hq-rtr
interface gre30
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 1c+rYtGm
!
router ospf
 network $HQ_SRV_NET area 0
 network $HQ_CLI_NET area 0
 network $GRE_NET area 0
!
line vty
EOF
        systemctl restart frr
        ;;

    "br-rtr")
        echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4
        setup_users
        setup_ssh
        echo "ip_gre" >> /etc/modules
        modprobe ip_gre

        cat <<EOF > /etc/network/interfaces
auto lo
iface lo inet loopback
auto $REAL_IFACE
iface $REAL_IFACE inet static
    address $BR_RTR_WAN_IP_CIDR
    gateway $BR_RTR_WAN_GW
auto $BR_RTR_LAN_IFACE
iface $BR_RTR_LAN_IFACE inet static
    address $BR_RTR_LAN_IP_CIDR
auto gre30
iface gre30 inet tunnel
    address $GRE_BR_IP
    netmask $GRE_NETMASK
    mode gre
    local $BR_RTR_WAN_IP
    endpoint $HQ_RTR_WAN_IP
    ttl 255
    mtu 1476
    post-up ip route replace $HQ_SRV_NET via $GRE_HQ_IP
    post-up ip route replace $HQ_CLI_NET via $GRE_HQ_IP
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
        # Проверка vtysh (иногда в /usr/bin или /usr/lib/frr)
        if ! command -v vtysh >/dev/null 2>&1 && [ ! -x /usr/lib/frr/vtysh ]; then
            install_pkg frr-pythontools
        fi
        cat <<EOF > /etc/frr/frr.conf
frr version 8.1
frr defaults traditional
hostname br-rtr
interface gre30
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 1c+rYtGm
!
router ospf
 network $BR_SRV_NET area 0
 network $GRE_NET area 0
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

auto $ISP_HQ_IFACE
iface $ISP_HQ_IFACE inet static
    address $ISP_HQ_IP_CIDR
    # Маршрут к офису HQ
    up ip route add $HQ_SRV_NET via $HQ_RTR_WAN_IP

auto $ISP_BR_IFACE
iface $ISP_BR_IFACE inet static
    address $ISP_BR_IP_CIDR
    # Маршрут к офису Branch
    up ip route add $BR_SRV_NET via $BR_RTR_WAN_IP
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
        # VLAN-интерфейс для HQ-CLI (ens33.200)
        echo "8021q" >> /etc/modules
        modprobe 8021q
        cat <<EOF > /etc/network/interfaces
auto $REAL_IFACE
iface $REAL_IFACE inet manual

auto ${REAL_IFACE}.200
iface ${REAL_IFACE}.200 inet dhcp
    vlan_raw_device $REAL_IFACE
EOF
        systemctl restart networking
        ;;
esac

echo "--- НАСТРОЙКА ЗАВЕРШЕНА. ПРОВЕРЬТЕ IP (ip a) ---"
