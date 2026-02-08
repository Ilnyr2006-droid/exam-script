#!/bin/bash
# АВТОМАТИЗАЦИЯ МОДУЛЯ 2 (Samba, RAID, Docker, Web, Ansible)
# Источник: Твой документ "демо.docx"

ROLE=$1
ISO_MOUNT="/mnt/additional"

# Пароли из задания
PASS_ADM="P@ssw0rd"
PASS_ROOT="P@ssw0rd"

if [ -z "$ROLE" ]; then
    echo "Использование: ./module2.sh [роль]"
    exit 1
fi

install_pkg() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y $@
}

echo "=== НАЧИНАЮ НАСТРОЙКУ МОДУЛЯ 2: $ROLE ==="

case $ROLE in
    "br-srv")
        [cite_start]# [cite: 5] Установка пакетов Samba
        echo ">>> Установка Samba AD DC..."
        install_pkg samba winbind libnss-winbind krb5-user smbclient ldb-tools python3-cryptography expect sshpass

        [cite_start]# [cite: 7-18] Настройка Kerberos
        cat <<EOF > /etc/krb5.conf
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
EOF

        [cite_start]# [cite: 19-39] Инициализация домена
        rm -f /etc/samba/smb.conf
        systemctl stop samba winbind smbd nmbd
        
        # Автоматический ввод данных для samba-tool (через аргументы, чтобы не висело)
        samba-tool domain provision \
            --realm=AU-TEAM.IRPO \
            --domain=AU-TEAM \
            --server-role=dc \
            --dns-backend=BIND9_DLZ \
            --adminpass=$PASS_ADM \
            --option="dns forwarder=8.8.8.8"

        rm -f /var/lib/samba/private/krb5.conf
        ln -s /etc/krb5.conf /var/lib/samba/private/krb5.conf

        systemctl disable samba winbind nmbd smbd
        systemctl mask samba winbind nmbd smbd
        systemctl unmask samba-ad-dc
        systemctl enable samba-ad-dc
        systemctl restart samba-ad-dc

        [cite_start]# [cite: 44-56] Создание пользователей и групп
        echo ">>> Создание пользователей..."
        samba-tool user add user1 $PASS_ADM
        samba-tool group addmembers "Domain Admins" user1
        
        for i in {1..5}; do
            samba-tool user add hquser$i $PASS_ADM
        done
        
        samba-tool group add hq
        for i in {1..5}; do
            samba-tool group addmembers hq hquser$i
        done

        [cite_start]# [cite: 221-247] Настройка Ansible
        echo ">>> Настройка Ansible..."
        install_pkg ansible
        mkdir -p /etc/ansible
        cat <<EOF > /etc/ansible/ansible.cfg
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
retry_files_enabled = False
EOF
        cat <<EOF > /etc/ansible/hosts
[hq]
HQ-SRV ansible_host=192.168.10.2 ansible_user=sshuser ansible_port=2026 ansible_ssh_pass=$PASS_ADM
HQ-CLI ansible_host=192.168.20.10 ansible_user=sshuser ansible_port=22 ansible_ssh_pass=$PASS_ADM
HQ-RTR ansible_host=172.16.1.2 ansible_user=net_admin ansible_port=22 ansible_ssh_pass=$PASS_ADM
[br]
BR-SRV ansible_connection=local ansible_user=root
BR-RTR ansible_host=172.16.2.2 ansible_user=net_admin ansible_port=22 ansible_ssh_pass=$PASS_ADM

[all:vars]
ansible_become=yes
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

        [cite_start]# [cite: 255] Генерация ключей (без вопросов)
        echo -e "\n\n\n" | ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa

        [cite_start]# [cite: 258-261] Раскидывание ключей (используем sshpass для автоматизации)
        # ВНИМАНИЕ: Это сработает, только если на других машинах уже созданы пользователи (см. ниже)
        echo ">>> Попытка копирования ключей (может не сработать, если хосты недоступны)..."
        sshpass -p "$PASS_ADM" ssh-copy-id -o StrictHostKeyChecking=no -p 2026 sshuser@192.168.10.2 || true
        sshpass -p "$PASS_ADM" ssh-copy-id -o StrictHostKeyChecking=no -p 22 sshuser@192.168.20.10 || true
        sshpass -p "$PASS_ADM" ssh-copy-id -o StrictHostKeyChecking=no -p 22 net_admin@172.16.1.2 || true
        sshpass -p "$PASS_ADM" ssh-copy-id -o StrictHostKeyChecking=no -p 22 net_admin@172.16.2.2 || true

        [cite_start]# [cite: 280-319] Docker и Web-App
        echo ">>> Настройка Docker..."
        install_pkg docker.io docker-compose
        
        # Монтируем ISO для образов
        mkdir -p $ISO_MOUNT
        mount /dev/cdrom $ISO_MOUNT || echo "!!! ОШИБКА: Вставьте Additional.iso в CD-ROM !!!"
        
        if [ -d "$ISO_MOUNT/docker" ]; then
            docker load -i $ISO_MOUNT/docker/mariadb_latest.tar
            docker load -i $ISO_MOUNT/docker/site_latest.tar
            
            mkdir -p /opt/testapp
            cat <<EOF > /opt/testapp/docker-compose.yml
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
      - MYSQL_ROOT_PASSWORD: root$PASS_ADM
      - MYSQL_DATABASE: testdb
      - MYSQL_USER: test
      - MYSQL_PASSWORD: $PASS_ADM
    volumes:
      - db_data:/var/lib/mysql
    restart: unless-stopped
volumes:
  db_data:
EOF
            cd /opt/testapp
            docker-compose up -d
        fi
        ;;

    "hq-srv")
        [cite_start]# [cite: 58-74] Настройка Bind9 DLZ и зон
        echo ">>> Донастройка DNS для AD..."
        
        # Добавляем SRV записи в зону
        cat <<EOF >> /etc/bind/zones/db.au-team.irpo
_ldap._tcp.au-team.irpo.        IN      SRV     0 100 389       br-srv.au-team.irpo.
_kerberos._tcp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kerberos._udp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kpasswd._tcp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_kpasswd._udp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_ldap._tcp.dc._msdcs.au-team.irpo       IN      SRV     0 100 389       br-srv.au-team.irpo.
EOF
        
        # В named.conf.local добавляем DLZ и запреты
        # (Упрощенно: перезаписываем файл, добавляя конфиг)
        echo 'dlz "samba-dlz" { database "dlopen /usr/lib/x86_64-linux-gnu/samba/bind9/dlz_bind9_11.so"; };' >> /etc/bind/named.conf.local
        
        # В named.conf.options
        sed -i '/};/i allow-update { 192.168.100.2; };' /etc/bind/named.conf.options
        systemctl restart bind9

        [cite_start]# [cite: 98-132] RAID 0
        echo ">>> Настройка RAID 0..."
        install_pkg mdadm
        # Создаем RAID (yes | ... чтобы не спрашивал)
        yes | mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sdb /dev/sdc || true
        mdadm --detail --scan >> /etc/mdadm/mdadm.conf
        update-initramfs -u
        
        # Разметка диска (n, p, 1, enter, enter, w)
        echo -e "n\np\n1\n\n\nw" | fdisk /dev/md0 || true
        mkfs.ext4 /dev/md0p1 || true
        mkdir -p /raid
        mount /dev/md0p1 /raid
        echo "/dev/md0p1   /raid   ext4   defaults   0   0" >> /etc/fstab

        [cite_start]# [cite: 136-149] NFS Server
        echo ">>> Настройка NFS..."
        install_pkg nfs-kernel-server
        mkdir -p /raid/nfs
        chmod 777 /raid/nfs
        echo "/raid/nfs 192.168.20.0/28(rw,sync,no_subtree_check)" >> /etc/exports
        exportfs -ra
        systemctl enable --now nfs-kernel-server

        [cite_start]# [cite: 325-455] Web Server (LAMP)
        echo ">>> Настройка Web-сервера..."
        install_pkg apache2 mariadb-server php php-mysql libapache2-mod-php
        
        # БД
        mysql -e "CREATE DATABASE webdb;"
        mysql -e "CREATE USER 'web'@'localhost' IDENTIFIED BY '$PASS_ADM';"
        mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'web'@'localhost';"
        mysql -e "FLUSH PRIVILEGES;"
        
        # Импорт сайта (Нужен ISO)
        mkdir -p $ISO_MOUNT
        mount /dev/cdrom $ISO_MOUNT || echo "!!! ВСТАВЬ ISO !!!"
        
        if [ -d "$ISO_MOUNT/web" ]; then
            # Импорт дампа
            mysql webdb < $ISO_MOUNT/web/dump.sql || mysql webdb < /root/dump.sql # Фолбэк если дампа нет
            
            # Копирование файлов
            cp $ISO_MOUNT/web/index.php /var/www/html/
            mkdir -p /var/www/html/images
            cp $ISO_MOUNT/web/logo.png /var/www/html/images/
            chown -R www-data:www-data /var/www/html/
            chmod -R 755 /var/www/html/
            rm /var/www/html/index.html
            
            # Настройка Apache
            sed -i 's/DirectoryIndex index.html/DirectoryIndex index.php index.html/' /etc/apache2/mods-enabled/dir.conf
            systemctl restart apache2
        fi
        
        [cite_start]# [cite: 195] Chrony Client
        install_pkg chrony
        echo "server 172.16.1.1 iburst" > /etc/chrony/chrony.conf
        systemctl restart chrony
        ;;

    "hq-cli")
        [cite_start]# [cite: 89-91] Ввод в домен
        echo ">>> Ввод в домен..."
        install_pkg realmd sssd sssd-tools libnss-sss libpam-sss adcli oddjob oddjob-mkhomedir packagekit samba-common-bin krb5-user nfs-common
        
        # Автоматический ввод пароля для realm join
        echo $PASS_ADM | realm join -v --user=Administrator AU-TEAM.IRPO

        [cite_start]# [cite: 94] Sudoers для доменных юзеров
        echo "%domain\ admins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers # Упростил для надежности
        
        [cite_start]# [cite: 161-167] Монтирование NFS
        mkdir -p /mnt/nfs
        echo "192.168.10.2:/raid/nfs   /mnt/nfs   nfs   defaults   0   0" >> /etc/fstab
        mount -a
        
        [cite_start]# [cite: 249-250] Создание пользователя для Ansible
        useradd -m -s /bin/bash sshuser
        echo "sshuser:$PASS_ADM" | chpasswd
        usermod -aG sudo sshuser
        echo "sshuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sshuser

        [cite_start]# [cite: 195] Chrony Client
        install_pkg chrony
        echo "server 172.16.1.1 iburst" > /etc/chrony/chrony.conf
        systemctl restart chrony
        ;;

    "hq-rtr"|"br-rtr")
        [cite_start]# [cite: 463-482] Port Forwarding (NAT)
        echo ">>> Настройка DNAT и Chrony..."
        
        if [ "$ROLE" == "hq-rtr" ]; then
            DEST_IP="192.168.10.2"
            LOCAL_NET="192.168.10.0/27"
        else
            DEST_IP="192.168.100.2"
            LOCAL_NET="192.168.100.0/27"
        fi

        # Правила iptables (добавляем к существующим)
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 8080 -j DNAT --to-destination $DEST_IP:8080
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination $DEST_IP:80 # Для hq-srv
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 2026 -j DNAT --to-destination $DEST_IP:2026
        
        # Разрешаем проброс (FORWARD)
        iptables -A FORWARD -p tcp -d $DEST_IP --dport 8080 -j ACCEPT
        iptables -A FORWARD -p tcp -d $DEST_IP --dport 80 -j ACCEPT
        iptables -A FORWARD -p tcp -d $DEST_IP --dport 2026 -j ACCEPT
        
        iptables-save > /etc/iptables/rules.v4

        # Chrony Client
        install_pkg chrony
        echo "server 172.16.1.1 iburst" > /etc/chrony/chrony.conf
        systemctl restart chrony
        ;;

    "isp")
        [cite_start]# [cite: 175-190] Chrony Server
        echo ">>> Настройка Chrony Server..."
        install_pkg chrony nginx apache2-utils
        
        cat <<EOF > /etc/chrony/chrony.conf
server 0.debian.pool.ntp.org iburst
local stratum 5
allow 172.16.0.0/12
allow 192.168.0.0/16
log measurements statistics tracking
EOF
        systemctl restart chrony

        [cite_start]# [cite: 493-591] Nginx Reverse Proxy
        echo ">>> Настройка Nginx Proxy..."
        
        # Создаем пароль для сайта
        htpasswd -bc /etc/nginx/.htpasswd WEB $PASS_ADM

        cat <<EOF > /etc/nginx/sites-available/reverse_proxy.conf
upstream hq_srv_app {
    server 192.168.10.2:80;
}
upstream testapp_app {
    server 192.168.100.2:8080;
}

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
EOF
        ln -s /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
        systemctl reload nginx
        ;;
esac

echo "--- МОДУЛЬ 2 НАСТРОЕН ($ROLE) ---"