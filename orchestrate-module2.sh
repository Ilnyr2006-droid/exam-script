#!/bin/bash
# Orchestrator: run module2 tasks from ISP via SSH (root)

set -euo pipefail

SSH_PORT=2026
ROOT_PASS="root"
PASS_ADM="P@ssw0rd"
ISO_FILE="/home/user/Загрузки/Additional.iso"
ISO_MOUNT="/mnt/additional"
DOMAIN="au-team.irpo"

# Default IPs (per your layout)
HQ_SRV_IP="192.168.10.2"
BR_SRV_IP="192.168.100.2"
HQ_RTR_IP="172.16.1.2"
BR_RTR_IP="172.16.2.2"
HQ_CLI_IP="192.168.20.2"

echo ">>> Pre-flight: sshpass + route to HQ-CLI"
apt-get install -y sshpass
/sbin/ip route add 192.168.20.0/28 via 172.16.1.2 || true

ssh_run() {
  local host="$1"
  local role="$2"
  echo ">>> [$role] Подключение к $host:$SSH_PORT"
  sshpass -p "$ROOT_PASS" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    root@"$host" "ROLE='$role' PASS_ADM='$PASS_ADM' ISO_FILE='$ISO_FILE' ISO_MOUNT='$ISO_MOUNT' DOMAIN='$DOMAIN' HQ_SRV_IP='$HQ_SRV_IP' BR_SRV_IP='$BR_SRV_IP' HQ_RTR_IP='$HQ_RTR_IP' BR_RTR_IP='$BR_RTR_IP' HQ_CLI_IP='$HQ_CLI_IP' bash -s" <<'REMOTE'
set -e
install_pkg() { DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }

setup_chrony_client() {
  install_pkg chrony
  cat <<CONF > /etc/chrony/chrony.conf
server 172.16.1.1 iburst
CONF
  systemctl restart chrony
  systemctl enable chrony
}

case "$ROLE" in
  "br-srv")
    setup_chrony_client
    install_pkg samba winbind libnss-winbind krb5-user smbclient ldb-tools python3-cryptography expect sshpass
    cat <<CONF > /etc/krb5.conf
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
CONF
    rm -f /etc/samba/smb.conf
    systemctl stop samba winbind smbd nmbd || true
    samba-tool domain provision --realm=AU-TEAM.IRPO --domain=AU-TEAM --server-role=dc --dns-backend=BIND9_DLZ --adminpass=$PASS_ADM --option="dns forwarder=8.8.8.8"
    rm -f /var/lib/samba/private/krb5.conf
    ln -s /etc/krb5.conf /var/lib/samba/private/krb5.conf
    systemctl unmask samba-ad-dc
    systemctl enable samba-ad-dc
    systemctl restart samba-ad-dc

    samba-tool user add user1 $PASS_ADM
    samba-tool group addmembers "Domain Admins" user1
    for i in 1 2 3 4 5; do samba-tool user add hquser$i $PASS_ADM; done
    samba-tool group add hq
    for i in 1 2 3 4 5; do samba-tool group addmembers hq hquser$i; done

    install_pkg ansible
    mkdir -p /etc/ansible
    cat <<CONF > /etc/ansible/ansible.cfg
[defaults]
inventory = /etc/ansible/hosts
host_key_checking = False
CONF
    cat <<CONF > /etc/ansible/hosts
[hq]
HQ-SRV ansible_host=${HQ_SRV_IP} ansible_user=root ansible_port=2026 ansible_ssh_pass=${ROOT_PASS}
HQ-CLI ansible_host=${HQ_CLI_IP} ansible_user=root ansible_port=2026 ansible_ssh_pass=${ROOT_PASS}
HQ-RTR ansible_host=${HQ_RTR_IP} ansible_user=root ansible_port=2026 ansible_ssh_pass=${ROOT_PASS}
[br]
BR-SRV ansible_connection=local ansible_user=root
BR-RTR ansible_host=${BR_RTR_IP} ansible_user=root ansible_port=2026 ansible_ssh_pass=${ROOT_PASS}
[all:vars]
ansible_become=yes
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no'
CONF
    echo -e "\n\n\n" | ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/id_rsa

    install_pkg docker.io docker-compose
    mkdir -p $ISO_MOUNT
    if [ -f "$ISO_FILE" ]; then
      mount -o loop "$ISO_FILE" $ISO_MOUNT || true
      if [ -d "$ISO_MOUNT/docker" ]; then
        docker load -i $ISO_MOUNT/docker/mariadb_latest.tar
        docker load -i $ISO_MOUNT/docker/site_latest.tar
        mkdir -p /opt/testapp
        cat <<CONF > /opt/testapp/docker-compose.yml
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
CONF
        cd /opt/testapp && docker-compose up -d
        sleep 5
        docker restart db >/dev/null 2>&1 || true
        sleep 5
        docker restart testapp >/dev/null 2>&1 || true
      fi
    fi
    perl -0777 -pi -e 's/ansible_ssh_pass=\\S*/ansible_ssh_pass=root/g' /etc/ansible/hosts
    ;;

  "hq-srv")
    setup_chrony_client
    install_pkg bind9
    cat <<CONF >> /etc/bind/zones/db.au-team.irpo
_ldap._tcp.au-team.irpo.        IN      SRV     0 100 389       br-srv.au-team.irpo.
_kerberos._tcp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kerberos._udp.au-team.irpo.    IN      SRV     0 100 88        br-srv.au-team.irpo.
_kpasswd._tcp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_kpasswd._udp.au-team.irpo      IN      SRV     0 100 464       br-srv.au-team.irpo.
_ldap._tcp.dc._msdcs.au-team.irpo       IN      SRV     0 100 389       br-srv.au-team.irpo.
CONF
    sed -i '/samba-dlz/d' /etc/bind/named.conf.local
    sed -i '/allow-update/d' /etc/bind/named.conf.options
    systemctl restart named || systemctl restart bind9

    install_pkg mdadm
    yes | mdadm --create /dev/md0 --level=0 --raid-devices=2 /dev/sdb /dev/sdc || true
    mdadm --detail --scan >> /etc/mdadm/mdadm.conf
    update-initramfs -u
    echo -e "n\np\n1\n\n\nw" | fdisk /dev/md0 || true
    mkfs.ext4 /dev/md0p1 || true
    mkdir -p /raid
    mount /dev/md0p1 /raid
    echo "/dev/md0p1   /raid   ext4   defaults   0   0" >> /etc/fstab

    install_pkg nfs-kernel-server
    mkdir -p /raid/nfs
    chmod 777 /raid/nfs
    echo "/raid/nfs 192.168.20.0/28(rw,sync,no_subtree_check)" >> /etc/exports
    exportfs -ra
    systemctl enable --now nfs-kernel-server

    install_pkg apache2 mariadb-server php php-mysql libapache2-mod-php
    mysql -e "CREATE DATABASE IF NOT EXISTS webdb;"
    mysql -e "CREATE USER IF NOT EXISTS 'web'@'localhost' IDENTIFIED BY '$PASS_ADM';"
    mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'web'@'localhost';"
    mysql -e "CREATE USER IF NOT EXISTS 'user'@'localhost' IDENTIFIED BY '$PASS_ADM';"
    mysql -e "GRANT ALL PRIVILEGES ON webdb.* TO 'user'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"

    mkdir -p $ISO_MOUNT
    if [ -f "$ISO_FILE" ]; then
      mount -o loop "$ISO_FILE" $ISO_MOUNT || true
      if [ -d "$ISO_MOUNT/web" ]; then
        mysql webdb < $ISO_MOUNT/web/dump.sql || true
        cp $ISO_MOUNT/web/index.php /var/www/html/
        mkdir -p /var/www/html/images
        cp $ISO_MOUNT/web/logo.png /var/www/html/images/
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
    setup_chrony_client
    install_pkg openssh-server
    sed -i 's/#Port 22/Port 2026/' /etc/ssh/sshd_config
    sed -i 's/Port 22/Port 2026/' /etc/ssh/sshd_config
    systemctl restart ssh || systemctl restart sshd

    cat <<CONF > /etc/krb5.conf
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
CONF

    # Domain join prerequisites (avoid interactive prompts)
    echo "krb5-config krb5-config/default_realm string AU-TEAM.IRPO" | debconf-set-selections
    echo "krb5-config krb5-config/kerberos_servers string br-srv.au-team.irpo" | debconf-set-selections
    echo "krb5-config krb5-config/admin_server string br-srv.au-team.irpo" | debconf-set-selections
    install_pkg realmd sssd oddjob oddjob-mkhomedir adcli samba-common packagekit sssd-tools krb5-user
    install_pkg realmd sssd sssd-tools libnss-sss libpam-sss adcli oddjob oddjob-mkhomedir packagekit samba-common-bin krb5-user

    echo "$PASS_ADM" | realm join -v --user=Administrator AU-TEAM.IRPO || true
    kinit Administrator || true
    klist || true

    # Добавляем sudo по GID доменной группы (если доступно)
    gid=$(getent group "hquser1@au-team.irpo" | cut -d: -f3 || true)
    if [ -n "$gid" ]; then
      grep -q "%#${gid} ALL=(ALL) NOPASSWD: /bin/cat, /bin/grep, /usr/bin/id" /etc/sudoers || \
        echo "%#${gid} ALL=(ALL) NOPASSWD: /bin/cat, /bin/grep, /usr/bin/id" >> /etc/sudoers
    fi

    # NFS client
    install_pkg nfs-common
    showmount -e ${HQ_SRV_IP} || true
    mkdir -p /mnt/nfs
    mount -t nfs ${HQ_SRV_IP}:/raid/nfs /mnt/nfs || true
    df -h | grep nfs || true
    grep -q "${HQ_SRV_IP}:/raid/nfs" /etc/fstab || \
      echo "${HQ_SRV_IP}:/raid/nfs   /mnt/nfs   nfs   defaults   0   0" >> /etc/fstab
    umount /mnt/nfs || true
    systemctl daemon-reload || true
    mount -a || true
    df -h | grep nfs || true

    useradd -m -s /bin/bash sshuser || true
    echo "sshuser:$PASS_ADM" | chpasswd
    usermod -aG sudo sshuser
    echo "sshuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sshuser
    ;;

  "hq-rtr"|"br-rtr")
    setup_chrony_client
    install_pkg iptables iptables-persistent
    if [ "$ROLE" = "hq-rtr" ]; then
      DEST="$HQ_SRV_IP"
    else
      DEST="$BR_SRV_IP"
    fi
    # гарантируем пароль net_admin
    echo "net_admin:$PASS_ADM" | chpasswd || true
    /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 8080 -j DNAT --to-destination ${DEST}:8080
    /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 80 -j DNAT --to-destination ${DEST}:80
    /usr/sbin/iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 2026 -j DNAT --to-destination ${DEST}:2026
    /usr/sbin/iptables -A FORWARD -p tcp -d ${DEST} --dport 8080 -j ACCEPT
    /usr/sbin/iptables -A FORWARD -p tcp -d ${DEST} --dport 80 -j ACCEPT
    /usr/sbin/iptables -A FORWARD -p tcp -d ${DEST} --dport 2026 -j ACCEPT
    /usr/sbin/iptables-save > /etc/iptables/rules.v4
    ;;
esac
REMOTE
}

echo "=== Orchestrating module2 from ISP ==="

check_ssh() {
  local host="$1"
  sshpass -p "$ROOT_PASS" ssh -p "$SSH_PORT" \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    root@"$host" "echo ok" >/dev/null 2>&1
}

for pair in \
  "$HQ_RTR_IP hq-rtr" \
  "$BR_RTR_IP br-rtr" \
  "$HQ_SRV_IP hq-srv" \
  "$BR_SRV_IP br-srv" \
  "$HQ_CLI_IP hq-cli"
do
  host="${pair%% *}"
  role="${pair##* }"
  echo ">>> Проверка SSH: $role ($host)"
  if check_ssh "$host"; then
    echo ">>> SSH OK: $role"
  else
    echo "!!! SSH FAIL: $role ($host)"
    exit 1
  fi
done

echo ">>> STEP 1: ISP (NTP + Proxy)"
# запуск локально на ISP
ROLE="isp" bash -s <<'LOCAL'
set -e
install_pkg() { DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }

install_pkg chrony nginx apache2-utils sshpass
cat <<CONF > /etc/chrony/chrony.conf
server 0.debian.pool.ntp.org iburst
local stratum 5
allow 172.16.0.0/12
allow 192.168.0.0/16
log measurements statistics tracking
CONF
systemctl restart chrony

htpasswd -bc /etc/nginx/.htpasswd WEB P@ssw0rd
cat <<'CONF' > /etc/nginx/sites-available/reverse_proxy.conf
upstream hq_srv_app { server 192.168.10.2:80; }
upstream testapp_app { server 192.168.100.2:8080; }
server {
    listen 80;
    server_name web.au-team.irpo;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
    location / {
        proxy_pass http://hq_srv_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
server {
    listen 80;
    server_name docker.au-team.irpo;
    location / {
        proxy_pass http://testapp_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
CONF
ln -sf /etc/nginx/sites-available/reverse_proxy.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl reload nginx
LOCAL

echo ">>> STEP 2: HQ-RTR & BR-RTR (NAT + Chrony)"
ssh_run "$HQ_RTR_IP" "hq-rtr"
ssh_run "$BR_RTR_IP" "br-rtr"

echo ">>> STEP 3: HQ-SRV (RAID + Web + NFS) — ISO required"
ssh_run "$HQ_SRV_IP" "hq-srv"

echo ">>> STEP 4: BR-SRV (Samba AD + Ansible + Docker) — ISO required"
# временно ставим 8.8.8.8, если нужно скачать пакеты
sshpass -p "$ROOT_PASS" ssh -p "$SSH_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  root@"$BR_SRV_IP" "echo 'nameserver 8.8.8.8' > /etc/resolv.conf" || true
ssh_run "$BR_SRV_IP" "br-srv"

echo ">>> STEP 5: HQ-CLI (Domain join + NFS)"
ssh_run "$HQ_CLI_IP" "hq-cli"

echo ">>> Ansible ping (from BR-SRV)"
sshpass -p "$ROOT_PASS" ssh -p "$SSH_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  root@"$BR_SRV_IP" "ansible all -m ping" || true
echo "=== Done ==="
