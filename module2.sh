cat << 'EOF' > module2.sh
#!/bin/bash
# МОДУЛЬ 2: С ISO ИЗ ЗАГРУЗОК (/home/user/Загрузки)

ROLE=$1
PASS_ADM="P@ssw0rd"
# [cite: 281, 345] Точка монтирования
ISO_MOUNT="/mnt/additional"
#  Путь к файлу
ISO_FILE="/home/user/Загрузки/Additional.iso"

if [ -z "$ROLE" ]; then
    echo "Использование: ./module2.sh [роль]"
    exit 1
fi

install_pkg() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y $@
}

echo "=== НАСТРОЙКА МОДУЛЯ 2: $ROLE ==="

case $ROLE in
    "isp")
        # [cite: 174-190] Chrony
        echo ">>> Настройка времени (Chrony)..."
        install_pkg chrony nginx apache2-utils
        
        cat <<CONFIG > /etc/chrony/chrony.conf
server 0.debian.pool.ntp.org iburst
local stratum 5
allow 172.16.0.0/12
allow 192.168.0.0/16
log measurements statistics tracking
CONFIG
        systemctl restart chrony
        systemctl enable chrony

        # [cite: 487-591] Nginx Proxy
        echo ">>> Настройка веб-прокси (Nginx)..."
        htpasswd -bc /etc/nginx/.htpasswd WEB $PASS_ADM

        cat <<CONFIG > /etc/nginx/sites-available/reverse_proxy.conf
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
CONFIG
        ln -sf /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
        systemctl reload nginx
        ;;

    "br-srv")
        # [cite: 3-43] Samba AD DC
        echo ">>> Установка Samba AD..."
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

        echo ">>> Создание пользователей..."
        samba-tool user add user1 $PASS_ADM
        samba-tool group addmembers "Domain Admins" user1
        for i in {1..5}; do samba-tool user add hquser$i $PASS_ADM; done
        samba-tool group add hq
        for i in {1..5}; do samba-tool group addmembers hq hquser$i; done

        # [cite: 221-247] Ansible
        echo ">>> Настройка Ansible..."
        install_pkg ansible
        mkdir -p /etc/ansible
        cat <<CONFIG > /etc/ansible/ansible.cfg
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
retry_files_enabled = False
CONFIG
        cat <<CONFIG > /etc/ansible/hosts
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
CONFIG
        echo -e "\n\n\n" | ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa

        # [cite: 280-319] Docker (С монтированием файла)
        echo ">>> Настройка Docker..."
        install_pkg docker.io docker-compose
        mkdir -p $ISO_MOUNT
        
        # Монтируем файл ISO
        if [ -f "$ISO_FILE" ]; then
            mount -o loop "$ISO_FILE" $ISO_MOUNT
            echo "ISO смонтирован."
            
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
      - MYSQL_ROOT_PASSWORD: root$PASS_ADM
      - MYSQL_DATABASE: testdb
      - MYSQL_USER: test
      - MYSQL_PASSWORD: $PASS_ADM
    volumes:
      - db_data:/var/lib/mysql
    restart: unless-stopped
volumes:
  db_data:
CONFIG
                cd /opt/testapp && docker-compose up -d
            fi
        else
            echo "!!! ОШИБКА: Файл $ISO_FILE не найден !!!"
        fi
        ;;

    "hq-srv")
        # [cite: 58-74] DNS for AD
        echo ">>> Настройка DNS..."
        install_pkg bind9
        cat <<CONFIG >> /etc/bind/zones/db.au-team.irpo
_ldap._tcp.au-team.irpo.        IN      SRV     0 100 389       br-srv.au-team.irpo.
_kerberos._tcp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kerberos._udp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kpasswd._tcp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_kpasswd._udp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_ldap._tcp.dc._msdcs.au-team.irpo       IN      SRV     0 100 389       br-srv.au-team.irpo.
CONFIG
        echo 'dlz "samba-dlz" { database "dlopen /usr/lib/x86_64-linux-gnu/samba/bind9/dlz_bind9_11.so"; };' >> /etc/bind/named.conf.local
        sed -i '/};/i allow-update { 192.168.100.2; };' /etc/bind/named.conf.options
        systemctl restart bind9

        # [cite: 98-132] RAID
        echo ">>> Настройка RAID..."
        install_pkg mdadm
        yes | mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sdb /dev/sdc || true
        mdadm --detail --scan >> /etc/mdadm/mdadm.conf
        update-initramfs -u
        echo -e "n\np\n1\n\n\nw" | fdisk /dev/md0 || true
        mkfs.ext4 /dev/md0p1 || true
        mkdir -p /raid
        mount /dev/md0p1 /raid
        echo "/dev/md0p1   /raid   ext4   defaults   0   0" >> /etc/fstab

        # [cite: 136-149] NFS
        echo ">>> Настройка NFS..."
        install_pkg nfs-kernel-server
        mkdir -p /raid/nfs
        chmod 777 /raid/nfs
        echo "/raid/nfs 192.168.20.0/28(rw,sync,no_subtree_check)" >> /etc/exports
        exportfs -ra
        systemctl enable --now nfs-kernel-server

        # [cite: 325-455] Web Server (с монтированием файла)
        echo ">>> Настройка Web..."
        install_pkg apache2 mariadb-server php php-mysql libapache2-mod-php
        mysql -e "CREATE DATABASE IF NOT EXISTS webdb;"
        mysql -e "CREATE USER IF NOT EXISTS 'web'@'localhost' IDENTIFIED BY '$PASS_ADM';"
        mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'web'@'localhost';"
        mysql -e "FLUSH PRIVILEGES;"
        
        mkdir -p $ISO_MOUNT
        # Монтируем файл ISO
        if [ -f "$ISO_FILE" ]; then
            mount -o loop "$ISO_FILE" $ISO_MOUNT
            echo "ISO смонтирован."

            if [ -d "$ISO_MOUNT/web" ]; then
                mysql webdb < $ISO_MOUNT/web/dump.sql || true
                cp $ISO_MOUNT/web/index.php /var/www/html/
                mkdir -p /var/www/html/images
                cp $ISO_MOUNT/web/logo.png /var/www/html/images/
                chown -R www-data:www-data /var/www/html/
                chmod -R 755 /var/www/html/
                rm -f /var/www/html/index.html
                sed -i 's/DirectoryIndex index.html/DirectoryIndex index.php index.html/' /etc/apache2/mods-enabled/dir.conf
                systemctl restart apache2
            fi
        else
            echo "!!! ОШИБКА: Файл $ISO_FILE не найден !!!"
        fi
        ;;

    "hq-cli")
        # [cite: 89-91] Join Domain
        echo ">>> Ввод в домен..."
        install_pkg realmd sssd sssd-tools libnss-sss libpam-sss adcli oddjob oddjob-mkhomedir packagekit samba-common-bin krb5-user nfs-common
        echo $PASS_ADM | realm join -v --user=Administrator AU-TEAM.IRPO
        echo "%domain\ admins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

        # [cite: 161-167] NFS Mount
        mkdir -p /mnt/nfs
        echo "192.168.10.2:/raid/nfs   /mnt/nfs   nfs   defaults   0   0" >> /etc/fstab
        mount -a
        
        # [cite: 249-250] Ansible User
        useradd -m -s /bin/bash sshuser || true
        echo "sshuser:$PASS_ADM" | chpasswd
        usermod -aG sudo sshuser
        echo "sshuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sshuser
        ;;

    "hq-rtr"|"br-rtr")
        # [cite: 463-485] Routers
        echo ">>> Настройка проброса портов..."
        if [ "$ROLE" == "hq-rtr" ]; then DEST="192.168.10.2"; else DEST="192.168.100.2"; fi
        
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 8080 -j DNAT --to-destination $DEST:8080
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination $DEST:80
        iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 2026 -j DNAT --to-destination $DEST:2026
        iptables -A FORWARD -p tcp -d $DEST --dport 8080 -j ACCEPT
        iptables -A FORWARD -p tcp -d $DEST --dport 80 -j ACCEPT
        iptables -A FORWARD -p tcp -d $DEST --dport 2026 -j ACCEPT
        iptables-save > /etc/iptables/rules.v4

        install_pkg chrony
        echo "server 172.16.1.1 iburst" > /etc/chrony/chrony.conf
        systemctl restart chrony
        ;;
esac
echo "--- ГОТОВО: $ROLE ---"
EOF

chmod +x module2.sh
./module2.sh isp