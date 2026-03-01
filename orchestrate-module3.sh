#!/bin/bash
# Orchestrator for module 3: run all role configs from ISP via SSH

set -euo pipefail

SSH_PORT=2026
ROOT_PASS="root"
PASS_ADM="P@ssw0rd"

HQ_SRV_IP="192.168.10.2"
BR_SRV_IP="192.168.100.2"
HQ_RTR_IP="172.16.1.2"
BR_RTR_IP="172.16.2.2"
HQ_CLI_IP="192.168.20.2"

echo ">>> Pre-flight: install sshpass + route to HQ-CLI"
apt-get update
apt-get install -y sshpass
/sbin/ip route add 192.168.20.0/28 via 172.16.1.2 || true

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

resolve_hq_cli_ip() {
  for candidate in "$HQ_CLI_IP" 192.168.20.3 192.168.20.4; do
    echo ">>> Проверка SSH: hq-cli ($candidate)"
    if check_ssh "$candidate"; then
      HQ_CLI_IP="$candidate"
      echo ">>> SSH OK: hq-cli (using $HQ_CLI_IP)"
      return 0
    fi
  done
  echo "!!! SSH FAIL: hq-cli (tried 192.168.20.2/3/4)"
  return 1
}

ssh_run() {
  local host="$1"
  local role="$2"
  echo ">>> [$role] connecting to $host:$SSH_PORT"
  sshpass -p "$ROOT_PASS" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o IdentitiesOnly=yes \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    root@"$host" "ROLE='$role' PASS_ADM='$PASS_ADM' HQ_SRV_IP='$HQ_SRV_IP' BR_SRV_IP='$BR_SRV_IP' HQ_RTR_IP='$HQ_RTR_IP' BR_RTR_IP='$BR_RTR_IP' HQ_CLI_IP='$HQ_CLI_IP' ROOT_PASS='$ROOT_PASS' SSH_PORT='$SSH_PORT' bash -s" <<'REMOTE'
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin:/usr/bin:/bin"

install_pkg() {
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

setup_hq_cli_pam() {
  grep -q "pam_mkhomedir.so" /etc/pam.d/common-session || \
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/common-session
}

setup_ipsec_hq_rtr() {
  install_pkg strongswan strongswan-starter strongswan-swanctl
  cat > /etc/ipsec.conf <<'EOF'
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha2_256-modp2048!
    esp=aes256-sha2_256!
    leftauth=psk
    rightauth=psk
    auto=start
    dpdaction=restart
    closeaction=restart

conn gre-encrypt
    left=172.16.1.2
    leftid=@hq-rtr.au-team.irpo
    right=172.16.2.2
    rightid=@br-rtr.au-team.irpo
    type=transport
    authby=psk
    leftprotoport=47/%any
    rightprotoport=47/%any
EOF
  cat > /etc/ipsec.secrets <<'EOF'
@hq-rtr.au-team.irpo @br-rtr.au-team.irpo : PSK "P@ssw0rd"
EOF
  systemctl enable --now strongswan-starter
  systemctl restart strongswan-starter
  /usr/sbin/ipsec restart || true
}

setup_ipsec_br_rtr() {
  install_pkg strongswan strongswan-starter strongswan-swanctl
  cat > /etc/ipsec.conf <<'EOF'
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids=no

conn %default
    keyexchange=ikev2
    ike=aes256-sha2_256-modp2048!
    esp=aes256-sha2_256!
    leftauth=psk
    rightauth=psk
    auto=start
    dpdaction=restart
    closeaction=restart

conn gre-encrypt
    left=172.16.2.2
    leftid=@br-rtr.au-team.irpo
    right=172.16.1.2
    rightid=@hq-rtr.au-team.irpo
    type=transport
    authby=psk
    leftprotoport=47/%any
    rightprotoport=47/%any
EOF
  cat > /etc/ipsec.secrets <<'EOF'
@br-rtr.au-team.irpo @hq-rtr.au-team.irpo : PSK "P@ssw0rd"
EOF
  systemctl enable --now strongswan-starter
  systemctl restart strongswan-starter
  /usr/sbin/ipsec restart || true
}

write_firewall_script() {
  local dest="$1"
  local wan_if="${2:-ens33}"
  install_pkg iptables iptables-persistent
  # Avoid nftables/iptables conflict that may drop SSH with "No route to host".
  nft flush ruleset 2>/dev/null || true
  systemctl disable --now nftables 2>/dev/null || true
  cat > /etc/start_iptables.sh <<EOF
#!/bin/bash
set -e
WAN_IF="$wan_if"
DEST="$dest"
/sbin/iptables -F
/sbin/iptables -t nat -F
/sbin/iptables -t mangle -F
/sbin/iptables -t raw -F
/sbin/iptables -P INPUT DROP
/sbin/iptables -P FORWARD DROP
/sbin/iptables -P OUTPUT DROP
/sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
/sbin/iptables -A INPUT -p icmp -j ACCEPT
/sbin/iptables -A FORWARD -p icmp -j ACCEPT
/sbin/iptables -A OUTPUT -p icmp -j ACCEPT
/sbin/iptables -A INPUT -p ospf -j ACCEPT
/sbin/iptables -A FORWARD -p ospf -j ACCEPT
/sbin/iptables -A OUTPUT -p ospf -j ACCEPT
/sbin/iptables -A INPUT -p gre -j ACCEPT
/sbin/iptables -A FORWARD -p gre -j ACCEPT
/sbin/iptables -A OUTPUT -p gre -j ACCEPT
/sbin/iptables -A INPUT -p 50 -j ACCEPT
/sbin/iptables -A OUTPUT -p 50 -j ACCEPT
/sbin/iptables -A FORWARD -p 50 -j ACCEPT
/sbin/iptables -A INPUT -p 51 -j ACCEPT
/sbin/iptables -A OUTPUT -p 51 -j ACCEPT
/sbin/iptables -A FORWARD -p 51 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 500 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 500 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 500 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 4500 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 4500 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 4500 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 53 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp --dport 53 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 53 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 53 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -m multiport --dports 80,443,8080 -j ACCEPT
/sbin/iptables -A INPUT -p udp --sport 68 --dport 67 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --sport 67 --dport 68 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --sport 68 --dport 67 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --sport 67 --dport 68 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 2049 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 2049 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp --dport 2049 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 123 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 123 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 514 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 514 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 514 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 514 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 514 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp --dport 514 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m multiport --dports 22,2026 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -m multiport --dports 22,2026 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -m multiport --dports 22,2026 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m multiport --dports 10050,10051 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -m multiport --dports 10050,10051 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -m multiport --dports 10050,10051 -j ACCEPT
/sbin/iptables -A INPUT -p tcp --dport 631 -j ACCEPT
/sbin/iptables -A INPUT -p udp --dport 631 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp --dport 631 -j ACCEPT
/sbin/iptables -A OUTPUT -p udp --dport 631 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp --dport 631 -j ACCEPT
/sbin/iptables -A FORWARD -p udp --dport 631 -j ACCEPT
/sbin/iptables -A INPUT -p tcp -m multiport --dports 88,389,636,3268,3269,139,445,137,138 -j ACCEPT
/sbin/iptables -A OUTPUT -p tcp -m multiport --dports 88,389,636,3268,3269,139,445,137,138 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -m multiport --dports 88,389,636,3268,3269,139,445,137,138 -j ACCEPT
/sbin/iptables -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 8080 -j DNAT --to-destination \${DEST}:8080
/sbin/iptables -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 80 -j DNAT --to-destination \${DEST}:80
/sbin/iptables -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 2026 -j DNAT --to-destination \${DEST}:2026
/sbin/iptables -A FORWARD -p tcp -d "\$DEST" --dport 8080 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -d "\$DEST" --dport 80 -j ACCEPT
/sbin/iptables -A FORWARD -p tcp -d "\$DEST" --dport 2026 -j ACCEPT
EOF
  chmod +x /etc/start_iptables.sh
  /etc/start_iptables.sh
  /usr/sbin/iptables-save > /etc/iptables/rules.v4
}

setup_rsyslog_server_br_srv() {
  install_pkg rsyslog
  mkdir -p /opt
  cat > /etc/rsyslog.d/10-remote-server.conf <<'EOF'
module(load="imudp")
input(type="imudp" port="514")
module(load="imtcp")
input(type="imtcp" port="514")
$template RemoteLogs,"/opt/%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log"
if $fromhost-ip != '127.0.0.1' and $fromhost-ip != '192.168.100.2' then {
    if $syslogseverity <= 4 then {
        ?RemoteLogs
        stop
    }
}
EOF
  systemctl restart rsyslog
  systemctl enable rsyslog
}

setup_rsyslog_client() {
  install_pkg rsyslog
  cat > /etc/rsyslog.d/90-remote-forward.conf <<'EOF'
*.* @192.168.100.2:514
EOF
  systemctl restart rsyslog
  systemctl enable rsyslog
}

setup_ansible_inventory_task_br_srv() {
  install_pkg ansible sshpass
  mkdir -p /etc/ansible/PC-INFO /etc/ansible/playbook
  cat > /etc/ansible/hosts <<EOF
[hq]
hq-srv ansible_host=${HQ_SRV_IP} ansible_user=root ansible_port=${SSH_PORT} ansible_ssh_pass=${ROOT_PASS}
hq-cli ansible_host=${HQ_CLI_IP} ansible_user=root ansible_port=${SSH_PORT} ansible_ssh_pass=${ROOT_PASS}
[all:vars]
ansible_become=yes
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o IdentitiesOnly=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no'
EOF
  cat > /etc/ansible/playbook/get_hostname_address.yml <<'EOF'
- name: получение данных с хоста
  hosts: hq
  gather_facts: yes
  tasks:
    - name: создание отчета на BR-SRV
      copy:
        dest: /etc/ansible/PC-INFO/{{ ansible_hostname }}.yml
        content: |
          computer_name: {{ ansible_hostname }}
          ip_address: {{ ansible_default_ipv4.address | default('N/A') }}
      delegate_to: localhost
      run_once: false
EOF
}

setup_import_users_br_srv() {
  mkdir -p /mnt/additional
  mount -o loop "/home/user/Загрузки/Additional.iso" /mnt/additional 2>/dev/null || true
  mount -o loop "/home/br-srv/Загрузки/Additional.iso" /mnt/additional 2>/dev/null || true
  local csv_src="/media/cdrom0/Users.csv"
  [ -f /mnt/additional/Users.csv ] && csv_src="/mnt/additional/Users.csv"
  cat > /opt/import_users.sh <<'EOF'
#!/bin/bash
set -euo pipefail
CSV_FILE="${1:-/media/cdrom0/Users.csv}"
if [ ! -f "$CSV_FILE" ]; then
  echo "Ошибка: Файл $CSV_FILE не найден!"
  exit 1
fi
tail -n +2 "$CSV_FILE" | while IFS=';' read -r first_name last_name role phone ou street zip city country password
do
  username=$(echo "${first_name:0:1}$last_name" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | iconv -f utf-8 -t ascii//TRANSLIT 2>/dev/null || true)
  username=$(echo "$username" | tr -d '[:punct:]')
  password=$(echo "${password:-}" | tr -d ' ')
  first_name=$(echo "${first_name:-}" | tr -d ' ')
  last_name=$(echo "${last_name:-}" | tr -d ' ')
  city=$(echo "${city:-}" | tr -d ' ')
  [ -z "$username" ] && continue
  [ -z "$password" ] && continue
  if samba-tool user show "$username" >/dev/null 2>&1; then
    echo "[SKIP] Пользователь $username уже существует."
    continue
  fi
  samba-tool user create "$username" "$password" \
    --given-name="$first_name" \
    --surname="$last_name" \
    --description="$role" \
    --company="$city" || true
done
echo "Импорт завершен."
EOF
  chmod +x /opt/import_users.sh
  /opt/import_users.sh "$csv_src" || true
}

setup_fail2ban_hq_srv() {
  install_pkg fail2ban
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 60
findtime = 600
maxretry = 3
backend = auto
banaction = iptables-multiport
action = %(action_)s
[sshd]
enabled = true
port = 2026
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 60
findtime = 600
[sshd-ddos]
enabled = false
EOF
  systemctl restart fail2ban
  systemctl enable fail2ban
}

case "$ROLE" in
  br-srv)
    setup_import_users_br_srv
    setup_rsyslog_server_br_srv
    setup_ansible_inventory_task_br_srv
    ;;
  hq-cli)
    setup_hq_cli_pam
    ;;
  hq-rtr)
    setup_ipsec_hq_rtr
    write_firewall_script "$HQ_SRV_IP" "ens33"
    setup_rsyslog_client
    ;;
  br-rtr)
    setup_ipsec_br_rtr
    write_firewall_script "$BR_SRV_IP" "ens33"
    setup_rsyslog_client
    ;;
  hq-srv)
    setup_rsyslog_client
    setup_fail2ban_hq_srv
    ;;
esac
REMOTE
}

echo "=== Orchestrating module3 from ISP ==="

for pair in \
  "$HQ_RTR_IP hq-rtr" \
  "$BR_RTR_IP br-rtr" \
  "$HQ_SRV_IP hq-srv" \
  "$BR_SRV_IP br-srv"
do
  host="${pair%% *}"
  role="${pair##* }"
  echo ">>> SSH check: $role ($host)"
  check_ssh "$host" || { echo "!!! SSH FAIL: $role"; exit 1; }
done

resolve_hq_cli_ip || exit 1

echo ">>> STEP 1: BR-SRV (task1/task6-server/task8)"
ssh_run "$BR_SRV_IP" "br-srv"

echo ">>> STEP 2: HQ-CLI (pam_mkhomedir)"
ssh_run "$HQ_CLI_IP" "hq-cli"

echo ">>> STEP 3: HQ-RTR (task3/task4/task6-client)"
ssh_run "$HQ_RTR_IP" "hq-rtr"

echo ">>> STEP 4: BR-RTR (task3/task4/task6-client)"
ssh_run "$BR_RTR_IP" "br-rtr"

echo ">>> STEP 5: HQ-SRV (task6-client/task9)"
ssh_run "$HQ_SRV_IP" "hq-srv"

echo "=== module3 orchestration done ==="
