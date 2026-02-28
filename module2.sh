#!/bin/bash
# МОДУЛЬ 2 (CLEAN VERSION)

ROLE=$1
PASS_ADM="P@ssw0rd"
ISO_FILE="/home/user/Загрузки/Additional.iso"
ISO_MOUNT="/media/cdrom0"
DOMAIN="au-team.irpo"

# --- Пути для iptables и других системных утилит ---
export PATH=$PATH:/usr/sbin:/sbin:/usr/bin:/bin

# --- Интерфейсы по ролям ---
REAL_IFACE=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)
if [ -z "$REAL_IFACE" ]; then REAL_IFACE="ens33"; fi

get_ip() {
    local iface="$1"
    ip -o -4 addr show dev "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1
}

# Значения будут определены по ролям
HQ_SRV_IP=""
BR_SRV_IP=""
HQ_CLI_IP=""
HQ_RTR_WAN_IP=""
BR_RTR_WAN_IP=""
ISP_HQ_IP=""
ISP_BR_IP=""
HQ_RTR_VLAN100_IP=""
HQ_RTR_VLAN200_IP=""
BR_RTR_LAN_IP=""

if [ -z "$ROLE" ]; then
    echo "Использование: ./module2.sh [роль]"
    exit 1
fi

install_pkg() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y $@
}

prepare_iso_mount() {
    # Prefer VMware CD/DVD mount if present.
    if [ -d "/media/cdrom0" ]; then
        ISO_MOUNT="/media/cdrom0"
        return 0
    fi
    mkdir -p "$ISO_MOUNT"
    if [ -f "$ISO_FILE" ]; then
        mountpoint -q "$ISO_MOUNT" || mount -o loop "$ISO_FILE" "$ISO_MOUNT" || true
        return 0
    fi
    return 1
}

setup_chrony_client() {
    install_pkg chrony curl
    cat <<CONFIG > /etc/chrony/chrony.conf
server 172.16.1.1 iburst
CONFIG
    systemctl restart chrony
    systemctl enable chrony
}

echo "=== ЗАПУСК: $ROLE ==="

case $ROLE in
    "isp")
        ISP_HQ_IP="$(get_ip ens37)"
        ISP_BR_IP="$(get_ip ens38)"

        echo ">>> ISP: Chrony..."
        install_pkg chrony nginx apache2-utils curl
        cat <<CONFIG > /etc/chrony/chrony.conf
server 0.debian.pool.ntp.org iburst
local stratum 5
allow 172.16.0.0/12
allow 192.168.0.0/16
log measurements statistics tracking
CONFIG
        systemctl restart chrony
        
        echo ">>> ISP: Nginx..."
        htpasswd -bc /etc/nginx/.htpasswd WEB $PASS_ADM
        cat <<CONFIG > /etc/nginx/sites-available/reverse_proxy.conf
upstream hq_srv_app { server 192.168.10.2:80; }
upstream testapp_app { server 192.168.100.2:8080; }
server {
    listen 80;
    server_name web.au-team.irpo;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
    location / {
        proxy_pass http://hq_srv_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
server {
    listen 80;
    server_name docker.au-team.irpo;
    location / {
        proxy_pass http://testapp_app;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
CONFIG
        ln -sf /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
        systemctl reload nginx
        ;;

    "br-srv")
        BR_SRV_IP="$(get_ip "$REAL_IFACE")"
        HQ_SRV_IP="$(get_ip "${REAL_IFACE}.100")"
        HQ_CLI_IP="$(get_ip "${REAL_IFACE}.200")"
        HQ_RTR_WAN_IP="$(get_ip "$REAL_IFACE")"
        BR_RTR_WAN_IP="$(get_ip "$REAL_IFACE")"

        echo ">>> BR-SRV: Chrony..."
        setup_chrony_client

        echo ">>> BR-SRV: Samba..."
        install_pkg samba winbind libnss-winbind krb5-user smbclient ldb-tools python3-cryptography expect sshpass
        cat <<CONFIG > /etc/krb5.conf
[libdefaults]
    default_realm = AU-TEAM.IRPO
    dns_lookup_kdc = true
    dns_lookup_realm = false
[realms]
    AU-TEAM.IRPO = {
        kdc = br-srv.au-team.irpo
        admin_server = br-srv.au-team.irpo
    }
[domain_realm]
    .au-team.irpo = AU-TEAM.IRPO
    au-team.irpo = AU-TEAM.IRPO
CONFIG
        rm -f /etc/samba/smb.conf
        systemctl stop samba winbind smbd nmbd
        samba-tool domain provision --realm=AU-TEAM.IRPO --domain=AU-TEAM --server-role=dc --dns-backend=BIND9_DLZ --adminpass=$PASS_ADM --option="dns forwarder=8.8.8.8"
        rm -f /var/lib/samba/private/krb5.conf
        ln -s /etc/krb5.conf /var/lib/samba/private/krb5.conf
        systemctl unmask samba-ad-dc
        systemctl enable samba-ad-dc
        systemctl restart samba-ad-dc

        echo ">>> BR-SRV: Users..."
        samba-tool user add user1 $PASS_ADM
        samba-tool group addmembers "Domain Admins" user1
        for i in {1..5}; do samba-tool user add hquser$i $PASS_ADM; done
        samba-tool group add hq
        for i in {1..5}; do samba-tool group addmembers hq hquser$i; done

        echo ">>> BR-SRV: Ansible..."
        install_pkg ansible
        mkdir -p /etc/ansible
        cat <<CONFIG > /etc/ansible/ansible.cfg
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
CONFIG
        cat <<CONFIG > /etc/ansible/hosts
[hq]
HQ-SRV ansible_host=hq-srv.${DOMAIN} ansible_user=sshuser ansible_port=2026 ansible_ssh_pass=$PASS_ADM
HQ-CLI ansible_host=hq-cli.${DOMAIN} ansible_user=sshuser ansible_port=2026 ansible_ssh_pass=$PASS_ADM
HQ-RTR ansible_host=hq-rtr.${DOMAIN} ansible_user=net_admin ansible_port=2026 ansible_ssh_pass=$PASS_ADM
[br]
BR-SRV ansible_connection=local ansible_user=root
BR-RTR ansible_host=br-rtr.${DOMAIN} ansible_user=net_admin ansible_port=2026 ansible_ssh_pass=$PASS_ADM
[all:vars]
ansible_become=yes
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
CONFIG
        echo -e "\n\n\n" | ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa

        echo ">>> BR-SRV: Docker..."
        install_pkg docker.io docker-compose
        if prepare_iso_mount; then
            if [ -d "$ISO_MOUNT/docker" ]; then
                docker load -i $ISO_MOUNT/docker/mariadb_latest.tar
                docker load -i $ISO_MOUNT/docker/site_latest.tar
                mkdir -p /opt/testapp
                cat <<CONFIG > /opt/testapp/docker-compose.yml
version: '3.8'
services:
  testapp:
    image: site:latest
    container_name: testapp
    ports:
      - "8080:8000"
    depends_on:
      - db
    environment:
      - DB_HOST=db
      - DB_NAME=testdb
      - DB_TYPE=maria
      - DB_USER=test
      - DB_PASS=$PASS_ADM
      - SERVER_PORT=8080
    restart: unless-stopped
  db:
    image: mariadb:10.11
    container_name: db
    environment:
      - MYSQL_ROOT_PASSWORD=root$PASS_ADM
      - MYSQL_DATABASE=testdb
      - MYSQL_USER=test
      - MYSQL_PASSWORD=$PASS_ADM
    volumes:
      - db_data:/var/lib/mysql
    restart: unless-stopped
volumes:
  db_data:
CONFIG
                cd /opt/testapp && docker-compose up -d
                # Перезапускаем приложение после поднятия БД
                sleep 5
                docker restart db >/dev/null 2>&1 || true
                sleep 5
                docker restart testapp >/dev/null 2>&1 || true
                # Проверка доступности приложения
                if curl -sSf http://localhost:8080 >/dev/null 2>&1; then
                    echo ">>> TESTAPP: OK (http://localhost:8080)"
                else
                    echo ">>> TESTAPP: НЕ ДОСТУПЕН на http://localhost:8080 (проверьте docker logs testapp)"
                fi
            fi
        fi
        ;;

    "hq-srv")
        HQ_SRV_IP="$(get_ip "${REAL_IFACE}.100")"
        BR_SRV_IP="$(get_ip "${REAL_IFACE}.100")"

        echo ">>> HQ-SRV: Chrony..."
        setup_chrony_client

        echo ">>> HQ-SRV: DNS..."
        install_pkg bind9
        cat <<CONFIG >> /etc/bind/zones/db.au-team.irpo
_ldap._tcp.au-team.irpo.        IN      SRV     0 100 389       br-srv.au-team.irpo.
_kerberos._tcp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kerberos._udp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kpasswd._tcp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_kpasswd._udp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_ldap._tcp.dc._msdcs.au-team.irpo       IN      SRV     0 100 389       br-srv.au-team.irpo.
CONFIG
        # На HQ-SRV не используем samba-dlz и не пишем allow-update в options
        sed -i '/samba-dlz/d' /etc/bind/named.conf.local
        sed -i '/allow-update/d' /etc/bind/named.conf.options
        grep -n "samba-dlz" /etc/bind/named.conf.local || true
        grep -n "allow-update" /etc/bind/named.conf.options || true
        systemctl restart named || systemctl restart bind9
        ss -lntup | grep :53 || true

        echo ">>> HQ-SRV: RAID..."
        install_pkg mdadm
        yes | mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sdb /dev/sdc || true
        mdadm --detail --scan >> /etc/mdadm/mdadm.conf
        update-initramfs -u
        echo -e "n\np\n1\n\n\nw" | fdisk /dev/md0 || true
        mkfs.ext4 /dev/md0p1 || true
        mkdir -p /raid
        mount /dev/md0p1 /raid
        echo "/dev/md0p1   /raid   ext4   defaults   0   0" >> /etc/fstab

        echo ">>> HQ-SRV: NFS..."
        install_pkg nfs-kernel-server
        mkdir -p /raid/nfs
        chmod 777 /raid/nfs
        echo "/raid/nfs 192.168.20.0/28(rw,sync,no_subtree_check)" >> /etc/exports
        exportfs -ra
        systemctl enable --now nfs-kernel-server

        echo ">>> HQ-SRV: Web..."
        install_pkg apache2 mariadb-server php php-mysql libapache2-mod-php
        mysql -e "CREATE DATABASE IF NOT EXISTS webdb;"
        mysql -e "CREATE USER IF NOT EXISTS 'web'@'localhost' IDENTIFIED BY '$PASS_ADM';"
        mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'web'@'localhost';"
        # Пользователь для приложения (user)
        mysql -e "CREATE USER IF NOT EXISTS 'user'@'localhost' IDENTIFIED BY '$PASS_ADM';"
        mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'user'@'localhost';"
        mysql -e "FLUSH PRIVILEGES;"
        
        if prepare_iso_mount; then
            if [ -d "$ISO_MOUNT/web" ]; then
                mysql webdb < $ISO_MOUNT/web/dump.sql || true
                cp $ISO_MOUNT/web/index.php /var/www/html/
                mkdir -p /var/www/html/images
                cp $ISO_MOUNT/web/logo.png /var/www/html/images/
                # Исправляем учетные данные БД в index.php
                sed -i 's/password = "password";/password = "P@ssw0rd";/' /var/www/html/index.php
                sed -i 's/dbname = "db";/dbname = "webdb";/' /var/www/html/index.php
                chown -R www-data:www-data /var/www/html/
                chmod -R 755 /var/www/html/
                rm -f /var/www/html/index.html
                sed -i 's/DirectoryIndex index.html/DirectoryIndex index.php index.html/' /etc/apache2/mods-enabled/dir.conf
                systemctl restart apache2
            fi
        fi
        ;;

    "hq-cli")
        HQ_SRV_IP="$(get_ip "${REAL_IFACE}.100")"

        echo ">>> HQ-CLI: Chrony..."
        setup_chrony_client

        echo ">>> HQ-CLI: SSH..."
        install_pkg openssh-server
        sed -i 's/#Port 22/Port 2026/' /etc/ssh/sshd_config
        sed -i 's/Port 22/Port 2026/' /etc/ssh/sshd_config
        systemctl restart ssh

        echo ">>> HQ-CLI: Kerberos config..."
        cat <<'CONFIG' > /etc/krb5.conf
[libdefaults]
    default_realm = AU-TEAM.IRPO
    dns_lookup_kdc = true
    dns_lookup_realm = false

[realms]
    AU-TEAM.IRPO = {
        kdc = br-srv.au-team.irpo
        admin_server = br-srv.au-team.irpo
    }

[domain_realm]
    .au-team.irpo = AU-TEAM.IRPO
    au-team.irpo = AU-TEAM.IRPO
CONFIG

        echo ">>> HQ-CLI: Join Domain..."
        install_pkg realmd sssd sssd-tools libnss-sss libpam-sss adcli oddjob oddjob-mkhomedir packagekit samba-common-bin krb5-user nfs-common
        echo $PASS_ADM | realm join -v --user=Administrator AU-TEAM.IRPO
        echo "%domain\\ admins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

        echo ">>> HQ-CLI: NFS Mount..."
        mkdir -p /mnt/nfs
        echo "${HQ_SRV_IP:-192.168.10.2}:/raid/nfs   /mnt/nfs   nfs   defaults   0   0" >> /etc/fstab
        mount -a
        
        echo ">>> HQ-CLI: Ansible User..."
        useradd -m -s /bin/bash sshuser || true
        echo "sshuser:$PASS_ADM" | chpasswd
        usermod -aG sudo sshuser
        echo "sshuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sshuser
        ;;

    "hq-rtr"|"br-rtr")
        if [ "$ROLE" == "hq-rtr" ]; then
            HQ_SRV_IP="$(get_ip "${REAL_IFACE}.100")"
            HQ_RTR_WAN_IP="$(get_ip "$REAL_IFACE")"
            DEST="${HQ_SRV_IP:-192.168.10.2}"
        else
            BR_SRV_IP="$(getent ahosts br-srv.${DOMAIN} 2>/dev/null | awk 'NR==1{print $1}')"
            if [ -z "$BR_SRV_IP" ]; then BR_SRV_IP="192.168.100.2"; fi
            BR_RTR_WAN_IP="$(get_ip "$REAL_IFACE")"
            DEST="${BR_SRV_IP:-192.168.100.2}"
        fi

        echo ">>> ROUTER: NAT & Chrony..."
        install_pkg iptables iptables-persistent
        
        /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 8080 -j DNAT --to-destination $DEST:8080
        /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination $DEST:80
        /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 2026 -j DNAT --to-destination $DEST:2026
        /usr/sbin/iptables -A FORWARD -p tcp -d $DEST --dport 8080 -j ACCEPT
        /usr/sbin/iptables -A FORWARD -p tcp -d $DEST --dport 80 -j ACCEPT
        /usr/sbin/iptables -A FORWARD -p tcp -d $DEST --dport 2026 -j ACCEPT
        /usr/sbin/iptables-save > /etc/iptables/rules.v4

        setup_chrony_client
        ;;
esac
 echo "--- ГОТОВО ---"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
rm -f -- "$SCRIPT_PATH" || true
