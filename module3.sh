#!/bin/bash
# Module 3 local runner (run on each target VM)

set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin:/usr/bin:/bin"

ROLE="${1:-}"
PASS_ADM="P@ssw0rd"
ROOT_PASS="root"
HQ_SRV_IP="192.168.10.2"
BR_SRV_IP="192.168.100.2"
HQ_CLI_IP="192.168.20.2"
SSH_PORT="2026"

if [ -z "$ROLE" ]; then
  echo "Usage: $0 {br-srv|hq-cli|hq-rtr|br-rtr|hq-srv}"
  exit 1
fi

install_pkg() {
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
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
[ -f "$CSV_FILE" ] || { echo "Ошибка: Файл $CSV_FILE не найден!"; exit 1; }
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
  samba-tool user show "$username" >/dev/null 2>&1 && { echo "[SKIP] $username"; continue; }
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

setup_hq_cli_pam() {
  grep -q "pam_mkhomedir.so" /etc/pam.d/common-session || \
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/common-session
}

setup_ipsec() {
  local left_ip="$1"
  local left_id="$2"
  local right_ip="$3"
  local right_id="$4"

  install_pkg strongswan strongswan-starter strongswan-swanctl

  cat > /etc/ipsec.conf <<EOF
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
    left=$left_ip
    leftid=@$left_id
    right=$right_ip
    rightid=@$right_id
    type=transport
    authby=psk
    leftprotoport=47/%any
    rightprotoport=47/%any
EOF

  cat > /etc/ipsec.secrets <<EOF
@$left_id @$right_id : PSK "$PASS_ADM"
EOF

  systemctl enable strongswan-starter >/dev/null 2>&1 || true
  rm -f /var/run/charon.pid /var/run/starter.charon.pid || true
  systemctl restart strongswan-starter || true
}

setup_firewall_router() {
  local dest="$1"
  local wan_if="${2:-ens33}"
  install_pkg iptables iptables-persistent
  nft flush ruleset 2>/dev/null || true
  systemctl disable --now nftables 2>/dev/null || true

  cat > /etc/start_iptables.sh <<EOF
#!/bin/bash
set -e
WAN_IF="$wan_if"
DEST="$dest"
IPT="\$(command -v iptables 2>/dev/null || echo /usr/sbin/iptables)"
"\$IPT" -F
"\$IPT" -t nat -F
"\$IPT" -t mangle -F
"\$IPT" -t raw -F
"\$IPT" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
"\$IPT" -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
"\$IPT" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
"\$IPT" -A INPUT -p icmp -j ACCEPT
"\$IPT" -A FORWARD -p icmp -j ACCEPT
"\$IPT" -A OUTPUT -p icmp -j ACCEPT
"\$IPT" -A INPUT -p ospf -j ACCEPT
"\$IPT" -A FORWARD -p ospf -j ACCEPT
"\$IPT" -A OUTPUT -p ospf -j ACCEPT
"\$IPT" -A INPUT -p gre -j ACCEPT
"\$IPT" -A FORWARD -p gre -j ACCEPT
"\$IPT" -A OUTPUT -p gre -j ACCEPT
"\$IPT" -A INPUT -p 50 -j ACCEPT
"\$IPT" -A OUTPUT -p 50 -j ACCEPT
"\$IPT" -A FORWARD -p 50 -j ACCEPT
"\$IPT" -A INPUT -p 51 -j ACCEPT
"\$IPT" -A OUTPUT -p 51 -j ACCEPT
"\$IPT" -A FORWARD -p 51 -j ACCEPT
"\$IPT" -A INPUT -p udp --dport 500 -j ACCEPT
"\$IPT" -A OUTPUT -p udp --dport 500 -j ACCEPT
"\$IPT" -A FORWARD -p udp --dport 500 -j ACCEPT
"\$IPT" -A INPUT -p udp --dport 4500 -j ACCEPT
"\$IPT" -A OUTPUT -p udp --dport 4500 -j ACCEPT
"\$IPT" -A FORWARD -p udp --dport 4500 -j ACCEPT
"\$IPT" -A OUTPUT -p udp --dport 53 -j ACCEPT
"\$IPT" -A OUTPUT -p tcp --dport 53 -j ACCEPT
"\$IPT" -A INPUT -p udp --sport 53 -j ACCEPT
"\$IPT" -A INPUT -p tcp --sport 53 -j ACCEPT
"\$IPT" -A FORWARD -p udp --dport 53 -j ACCEPT
"\$IPT" -A FORWARD -p tcp --dport 53 -j ACCEPT
"\$IPT" -A INPUT -p tcp -m multiport --dports 22,2026,80,443,8080 -j ACCEPT
"\$IPT" -A OUTPUT -p tcp -m multiport --dports 22,2026,80,443,8080 -j ACCEPT
"\$IPT" -A FORWARD -p tcp -m multiport --dports 22,2026,80,443,8080 -j ACCEPT
"\$IPT" -P INPUT DROP
"\$IPT" -P FORWARD DROP
"\$IPT" -P OUTPUT DROP
"\$IPT" -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 8080 -j DNAT --to-destination \${DEST}:8080
"\$IPT" -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 80 -j DNAT --to-destination \${DEST}:80
"\$IPT" -t nat -A PREROUTING -i "\$WAN_IF" -p tcp --dport 2026 -j DNAT --to-destination \${DEST}:2026
"\$IPT" -A FORWARD -p tcp -d "\$DEST" --dport 8080 -j ACCEPT
"\$IPT" -A FORWARD -p tcp -d "\$DEST" --dport 80 -j ACCEPT
"\$IPT" -A FORWARD -p tcp -d "\$DEST" --dport 2026 -j ACCEPT
EOF
  chmod +x /etc/start_iptables.sh
  /etc/start_iptables.sh
  mkdir -p /etc/iptables
  $(command -v iptables-save 2>/dev/null || echo /usr/sbin/iptables-save) > /etc/iptables/rules.v4
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

setup_ansible_task8_br_srv() {
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
    setup_ansible_task8_br_srv
    ;;
  hq-cli)
    setup_hq_cli_pam
    ;;
  hq-rtr)
    setup_ipsec "172.16.1.2" "hq-rtr.au-team.irpo" "172.16.2.2" "br-rtr.au-team.irpo"
    setup_firewall_router "$HQ_SRV_IP" "ens33"
    setup_rsyslog_client
    ;;
  br-rtr)
    setup_ipsec "172.16.2.2" "br-rtr.au-team.irpo" "172.16.1.2" "hq-rtr.au-team.irpo"
    setup_firewall_router "$BR_SRV_IP" "ens33"
    setup_rsyslog_client
    ;;
  hq-srv)
    setup_rsyslog_client
    setup_fail2ban_hq_srv
    ;;
  *)
    echo "Unknown role: $ROLE"
    exit 1
    ;;
esac

echo "=== module3 done for role: $ROLE ==="
