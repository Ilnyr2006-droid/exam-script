#!/bin/bash
# Unified exam checker for modules 1-3.
# Recommended run host: ISP (with routes to all lab subnets).

set -u

SSH_PORT=2026
ROOT_PASS="root"

HQ_SRV_IP="192.168.10.2"
BR_SRV_IP="192.168.100.2"
HQ_RTR_IP="172.16.1.2"
BR_RTR_IP="172.16.2.2"
HQ_CLI_IP="192.168.20.2"

SSH_OPTS=(
  -p "$SSH_PORT"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o IdentitiesOnly=yes
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o ConnectTimeout=5
)

RESULTS=()
PASS_CNT=0
FAIL_CNT=0

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_remote() {
  local host="$1"
  local cmd="$2"
  sshpass -p "$ROOT_PASS" ssh "${SSH_OPTS[@]}" root@"$host" "$cmd" >/dev/null 2>&1
}

check_hq_cli_ip() {
  local cand
  for cand in "$HQ_CLI_IP" 192.168.20.3 192.168.20.4; do
    if run_remote "$cand" "echo ok"; then
      HQ_CLI_IP="$cand"
      return 0
    fi
  done
  return 1
}

add_result() {
  local module="$1"
  local task="$2"
  local ok="$3"
  local note="$4"
  if [ "$ok" -eq 0 ]; then
    RESULTS+=("$module|$task|DONE|$note")
    PASS_CNT=$((PASS_CNT + 1))
  else
    RESULTS+=("$module|$task|NOT DONE|$note")
    FAIL_CNT=$((FAIL_CNT + 1))
  fi
}

check_local() {
  local cmd="$1"
  bash -lc "$cmd" >/dev/null 2>&1
}

main() {
  if ! need_cmd sshpass; then
    echo "ERROR: sshpass is required. Install: apt-get install -y sshpass"
    exit 1
  fi

  check_hq_cli_ip || true

  # --- Module 1 ---
  run_remote "$HQ_RTR_IP" "echo ok"
  add_result "M1" "SSH access to HQ-RTR" "$?" "$HQ_RTR_IP:$SSH_PORT"

  run_remote "$BR_RTR_IP" "echo ok"
  add_result "M1" "SSH access to BR-RTR" "$?" "$BR_RTR_IP:$SSH_PORT"

  run_remote "$HQ_SRV_IP" "echo ok"
  add_result "M1" "SSH access to HQ-SRV" "$?" "$HQ_SRV_IP:$SSH_PORT"

  run_remote "$BR_SRV_IP" "echo ok"
  add_result "M1" "SSH access to BR-SRV" "$?" "$BR_SRV_IP:$SSH_PORT"

  run_remote "$HQ_CLI_IP" "echo ok"
  add_result "M1" "SSH access to HQ-CLI" "$?" "$HQ_CLI_IP:$SSH_PORT"

  run_remote "$HQ_SRV_IP" "systemctl is-active named >/dev/null 2>&1 || systemctl is-active bind9 >/dev/null 2>&1"
  add_result "M1" "DNS service active on HQ-SRV" "$?" "named/bind9"

  run_remote "$HQ_RTR_IP" "nslookup br-srv.au-team.irpo 192.168.10.2 | grep -q '192.168.100.2'"
  add_result "M1" "Forward DNS zone works" "$?" "br-srv.au-team.irpo"

  run_remote "$HQ_RTR_IP" "ip link show gre30 2>/dev/null | grep -q 'UP'"
  add_result "M1" "GRE up on HQ-RTR" "$?" "gre30"

  run_remote "$BR_RTR_IP" "ip link show gre30 2>/dev/null | grep -q 'UP'"
  add_result "M1" "GRE up on BR-RTR" "$?" "gre30"

  run_remote "$HQ_RTR_IP" "ping -c1 -W1 10.0.0.2 >/dev/null 2>&1"
  add_result "M1" "GRE connectivity HQ->BR" "$?" "10.0.0.2"

  check_local "sysctl -n net.ipv4.ip_forward | grep -q '^1$'"
  add_result "M1" "ISP ip_forward enabled" "$?" "net.ipv4.ip_forward=1"

  check_local "iptables -t nat -S POSTROUTING | grep -q MASQUERADE"
  add_result "M1" "ISP NAT MASQUERADE present" "$?" "POSTROUTING"

  # --- Module 2 ---
  check_local "systemctl is-active nginx >/dev/null 2>&1"
  add_result "M2" "Nginx reverse proxy active on ISP" "$?" "nginx"

  check_local "grep -q 'server_name web.au-team.irpo' /etc/nginx/sites-available/reverse_proxy.conf && grep -q 'server_name docker.au-team.irpo' /etc/nginx/sites-available/reverse_proxy.conf"
  add_result "M2" "Reverse proxy config contains web/docker vhosts" "$?" "reverse_proxy.conf"

  for host in "$HQ_RTR_IP" "$BR_RTR_IP" "$HQ_SRV_IP" "$BR_SRV_IP" "$HQ_CLI_IP"; do
    run_remote "$host" "systemctl is-active chrony >/dev/null 2>&1"
    add_result "M2" "Chrony active on $host" "$?" "chrony.service"
  done

  run_remote "$HQ_SRV_IP" "[ -b /dev/md0 ] && mount | grep -q ' /raid '"
  add_result "M2" "HQ-SRV RAID mounted on /raid" "$?" "/dev/md0"

  run_remote "$HQ_SRV_IP" "exportfs -v | grep -q '/raid/nfs'"
  add_result "M2" "HQ-SRV NFS export /raid/nfs" "$?" "exportfs"

  run_remote "$HQ_SRV_IP" "ss -lnt | grep -q ':80 '"
  add_result "M2" "HQ-SRV web service listens on 80" "$?" "apache/nginx"

  run_remote "$BR_SRV_IP" "systemctl is-active samba-ad-dc >/dev/null 2>&1"
  add_result "M2" "BR-SRV Samba AD DC active" "$?" "samba-ad-dc"

  run_remote "$BR_SRV_IP" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^testapp$'"
  add_result "M2" "BR-SRV testapp container running" "$?" "docker testapp"

  run_remote "$BR_SRV_IP" "ss -lnt | grep -q ':8080 '"
  add_result "M2" "BR-SRV app listens on 8080" "$?" "testapp"

  run_remote "$HQ_CLI_IP" "realm list 2>/dev/null | grep -qi 'au-team.irpo'"
  add_result "M2" "HQ-CLI joined AD realm" "$?" "realm list"

  run_remote "$HQ_CLI_IP" "mount | grep -q ' /mnt/nfs '"
  add_result "M2" "HQ-CLI NFS mounted at /mnt/nfs" "$?" "mount"

  run_remote "$BR_SRV_IP" "ansible all -m ping -o >/tmp/ansible_ping.out 2>&1 && ! grep -q 'UNREACHABLE' /tmp/ansible_ping.out"
  add_result "M2" "Ansible ping from BR-SRV to all nodes" "$?" "ansible all -m ping"

  # --- Module 3 ---
  run_remote "$BR_SRV_IP" "test -x /opt/import_users.sh"
  add_result "M3" "User import script exists on BR-SRV" "$?" "/opt/import_users.sh"

  run_remote "$BR_SRV_IP" "samba-tool user list 2>/dev/null | grep -Eiq 'hquser1|atran|lbuck|qpurk'"
  add_result "M3" "Imported/domain users present in AD" "$?" "samba-tool user list"

  run_remote "$HQ_RTR_IP" "ipsec statusall 2>/dev/null | grep -q 'gre-encrypt'"
  add_result "M3" "IPsec tunnel profile active on HQ-RTR" "$?" "gre-encrypt"

  run_remote "$BR_RTR_IP" "ipsec statusall 2>/dev/null | grep -q 'gre-encrypt'"
  add_result "M3" "IPsec tunnel profile active on BR-RTR" "$?" "gre-encrypt"

  run_remote "$HQ_RTR_IP" "test -x /etc/start_iptables.sh && iptables -S | grep -q '^-P INPUT DROP'"
  add_result "M3" "Firewall script + DROP policy on HQ-RTR" "$?" "/etc/start_iptables.sh"

  run_remote "$BR_RTR_IP" "test -x /etc/start_iptables.sh && iptables -S | grep -q '^-P INPUT DROP'"
  add_result "M3" "Firewall script + DROP policy on BR-RTR" "$?" "/etc/start_iptables.sh"

  run_remote "$BR_SRV_IP" "systemctl is-active rsyslog >/dev/null 2>&1 && ss -lun | grep -q ':514 '"
  add_result "M3" "Rsyslog server listens on BR-SRV:514" "$?" "imudp/imtcp"

  run_remote "$HQ_RTR_IP" "grep -q '@192.168.100.2:514' /etc/rsyslog.d/90-remote-forward.conf"
  add_result "M3" "Rsyslog forwarding configured on HQ-RTR" "$?" "90-remote-forward.conf"

  run_remote "$BR_RTR_IP" "grep -q '@192.168.100.2:514' /etc/rsyslog.d/90-remote-forward.conf"
  add_result "M3" "Rsyslog forwarding configured on BR-RTR" "$?" "90-remote-forward.conf"

  run_remote "$HQ_SRV_IP" "grep -q '@192.168.100.2:514' /etc/rsyslog.d/90-remote-forward.conf"
  add_result "M3" "Rsyslog forwarding configured on HQ-SRV" "$?" "90-remote-forward.conf"

  run_remote "$BR_SRV_IP" "test -f /etc/ansible/playbook/get_hostname_address.yml && test -f /etc/ansible/PC-INFO/hq-srv.yml && test -f /etc/ansible/PC-INFO/hq-cli.yml"
  add_result "M3" "Ansible inventory reports generated (task 8)" "$?" "/etc/ansible/PC-INFO/*.yml"

  run_remote "$HQ_SRV_IP" "systemctl is-active fail2ban >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1"
  add_result "M3" "Fail2ban active with sshd jail on HQ-SRV" "$?" "fail2ban"

  echo
  echo "================ EXAM CHECK SUMMARY ================"
  printf "%-6s | %-52s | %-8s | %s\n" "MOD" "TASK" "STATUS" "DETAIL"
  printf -- "-------------------------------------------------------------\n"
  local row
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r m t s d <<<"$row"
    printf "%-6s | %-52s | %-8s | %s\n" "$m" "$t" "$s" "$d"
  done
  printf -- "-------------------------------------------------------------\n"
  echo "TOTAL: $((PASS_CNT + FAIL_CNT))  DONE: $PASS_CNT  NOT DONE: $FAIL_CNT"
  echo "===================================================="
}

main "$@"

