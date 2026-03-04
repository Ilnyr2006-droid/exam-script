#!/bin/bash
# Unified exam checker for modules 1-3 with readable PASS/FAIL output.
# Recommended run host: ISP.

set -u

SSH_PORT=2026
ROOT_PASS="root"

DEF_HQ_SRV_IP="192.168.10.2"
DEF_BR_SRV_IP="192.168.100.2"
DEF_HQ_RTR_IP="172.16.1.2"
DEF_BR_RTR_IP="172.16.2.2"
DEF_HQ_CLI_IP="192.168.20.2"

if [ -n "${CLIENT_KEY:-}" ]; then
  if ! command -v sha256sum >/dev/null 2>&1; then
    echo "ERROR: sha256sum is required for CLIENT_KEY mode"
    exit 1
  fi

  SEED_HEX="$(echo -n "$CLIENT_KEY" | sha256sum | awk '{print $1}' | cut -c1-8)"
  SEED=$((16#$SEED_HEX))

  BASE_A=$(( (SEED % 200) + 20 ))
  BASE_B=$(( ((SEED / 257) % 200) + 20 ))
  WAN_C=$(( ((SEED / 65537) % 200) + 20 ))

  next_octet() {
    local base="$1" off="$2"
    echo $(( ((base - 20 + off) % 200) + 20 ))
  }

  O1="$(next_octet "$BASE_B" 0)"
  O2="$(next_octet "$BASE_B" 1)"
  O4="$(next_octet "$BASE_B" 3)"

  DEF_HQ_SRV_IP="10.${BASE_A}.${O1}.2"
  DEF_HQ_CLI_IP="10.${BASE_A}.${O2}.2"
  DEF_BR_SRV_IP="10.${BASE_A}.${O4}.2"

  DEF_HQ_RTR_IP="172.16.${WAN_C}.2"
  WAN_D="$(next_octet "$WAN_C" 37)"
  DEF_BR_RTR_IP="172.16.${WAN_D}.2"

  echo ">>> CLIENT_KEY mode enabled: $CLIENT_KEY"
fi

HQ_SRV_IP="$DEF_HQ_SRV_IP"
BR_SRV_IP="$DEF_BR_SRV_IP"
HQ_RTR_IP="$DEF_HQ_RTR_IP"
BR_RTR_IP="$DEF_BR_RTR_IP"
HQ_CLI_IP="$DEF_HQ_CLI_IP"

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
CURRENT_MODULE=""

need_cmd() { command -v "$1" >/dev/null 2>&1; }

run_remote() {
  local host="$1"
  local cmd="$2"
  sshpass -p "$ROOT_PASS" ssh "${SSH_OPTS[@]}" root@"$host" "$cmd" >/dev/null 2>&1
}

check_local() {
  local cmd="$1"
  bash -lc "$cmd" >/dev/null 2>&1
}

check_hq_cli_ip() {
  local cand
  local hq_cli_base="${HQ_CLI_IP%.*}"
  for cand in "$HQ_CLI_IP" "${hq_cli_base}.3" "${hq_cli_base}.4"; do
    if run_remote "$cand" "echo ok"; then
      HQ_CLI_IP="$cand"
      return 0
    fi
  done
  return 1
}

module_start() {
  CURRENT_MODULE="$1"
  echo
  echo "--- Запуск проверок Модуля $CURRENT_MODULE ---"
}

record_check() {
  local id="$1"
  local desc="$2"
  local detail="$3"
  local rc="$4"

  if [ "$rc" -eq 0 ]; then
    echo "[PASS] [M${CURRENT_MODULE}.${id}] ${desc}."
    RESULTS+=("M${CURRENT_MODULE}|${id}|PASS|${desc}|${detail}")
    PASS_CNT=$((PASS_CNT + 1))
  else
    echo "[FAIL] [M${CURRENT_MODULE}.${id}] ${desc}."
    RESULTS+=("M${CURRENT_MODULE}|${id}|FAIL|${desc}|${detail}")
    FAIL_CNT=$((FAIL_CNT + 1))
  fi
}

print_summary() {
  local host_name
  host_name="$(hostname -f 2>/dev/null || hostname)"

  echo
  echo "============================================================"
  echo "СВОДКА РЕЗУЛЬТАТОВ НА ХОСТЕ ${host_name}"
  echo "============================================================"

  local row m i s d note
  for row in "${RESULTS[@]}"; do
    IFS='|' read -r m i s d note <<<"$row"
    if [ "$s" = "PASS" ]; then
      echo "[PASS] [${m}.${i}] ${d} (${note})"
    else
      echo "[FAIL] [${m}.${i}] ${d} (${note})"
    fi
  done

  echo "------------------------------------------------------------"
  echo "ИТОГО: $((PASS_CNT + FAIL_CNT))  PASS: $PASS_CNT  FAIL: $FAIL_CNT"
  echo "============================================================"
}

main() {
  if ! need_cmd sshpass; then
    echo "ERROR: sshpass is required. Install: apt-get install -y sshpass"
    exit 1
  fi

  check_hq_cli_ip || true

  # ---------------- Module 1 ----------------
  module_start "1"

  run_remote "$HQ_RTR_IP" "echo ok"; record_check "1" "SSH доступ к HQ-RTR" "$HQ_RTR_IP:$SSH_PORT" "$?"
  run_remote "$BR_RTR_IP" "echo ok"; record_check "1" "SSH доступ к BR-RTR" "$BR_RTR_IP:$SSH_PORT" "$?"
  run_remote "$HQ_SRV_IP" "echo ok"; record_check "1" "SSH доступ к HQ-SRV" "$HQ_SRV_IP:$SSH_PORT" "$?"
  run_remote "$BR_SRV_IP" "echo ok"; record_check "1" "SSH доступ к BR-SRV" "$BR_SRV_IP:$SSH_PORT" "$?"
  run_remote "$HQ_CLI_IP" "echo ok"; record_check "1" "SSH доступ к HQ-CLI" "$HQ_CLI_IP:$SSH_PORT" "$?"

  run_remote "$HQ_SRV_IP" "systemctl is-active named >/dev/null 2>&1 || systemctl is-active bind9 >/dev/null 2>&1"
  record_check "2" "DNS служба на HQ-SRV активна" "named/bind9" "$?"

  run_remote "$HQ_RTR_IP" "nslookup br-srv.au-team.irpo ${HQ_SRV_IP} | grep -q '${BR_SRV_IP}'"
  record_check "2" "Прямая DNS-зона работает" "br-srv.au-team.irpo" "$?"

  run_remote "$HQ_RTR_IP" "ip link show gre30 2>/dev/null | grep -q 'UP'"
  record_check "4" "GRE интерфейс на HQ-RTR поднят" "gre30" "$?"

  run_remote "$BR_RTR_IP" "ip link show gre30 2>/dev/null | grep -q 'UP'"
  record_check "4" "GRE интерфейс на BR-RTR поднят" "gre30" "$?"

  run_remote "$HQ_RTR_IP" "ping -c1 -W1 10.0.0.2 >/dev/null 2>&1"
  record_check "4" "GRE связность HQ->BR есть" "10.0.0.2" "$?"

  check_local "sysctl -n net.ipv4.ip_forward | grep -q '^1$'"
  record_check "6" "IP-forwarding на ISP включен" "net.ipv4.ip_forward=1" "$?"

  check_local "iptables -t nat -S POSTROUTING | grep -q MASQUERADE"
  record_check "6" "NAT MASQUERADE на ISP настроен" "POSTROUTING" "$?"

  # ---------------- Module 2 ----------------
  module_start "2"

  check_local "systemctl is-active nginx >/dev/null 2>&1"
  record_check "1" "Nginx reverse proxy на ISP активен" "nginx" "$?"

  check_local "grep -q 'server_name web.au-team.irpo' /etc/nginx/sites-available/reverse_proxy.conf && grep -q 'server_name docker.au-team.irpo' /etc/nginx/sites-available/reverse_proxy.conf"
  record_check "1" "Конфиг reverse proxy содержит web/docker" "reverse_proxy.conf" "$?"

  local host
  for host in "$HQ_RTR_IP" "$BR_RTR_IP" "$HQ_SRV_IP" "$BR_SRV_IP" "$HQ_CLI_IP"; do
    run_remote "$host" "systemctl is-active chrony >/dev/null 2>&1"
    record_check "2" "Chrony активен на $host" "chrony.service" "$?"
  done

  run_remote "$HQ_SRV_IP" "[ -b /dev/md0 ] && mount | grep -q ' /raid '"
  record_check "3" "RAID на HQ-SRV смонтирован в /raid" "/dev/md0" "$?"

  run_remote "$HQ_SRV_IP" "exportfs -v | grep -q '/raid/nfs'"
  record_check "3" "NFS экспорт /raid/nfs на HQ-SRV" "exportfs" "$?"

  run_remote "$HQ_SRV_IP" "ss -lnt | grep -q ':80 '"
  record_check "5" "Веб-сервис HQ-SRV слушает 80/tcp" "web" "$?"

  run_remote "$BR_SRV_IP" "systemctl is-active samba-ad-dc >/dev/null 2>&1"
  record_check "6" "Samba AD DC на BR-SRV активен" "samba-ad-dc" "$?"

  run_remote "$BR_SRV_IP" "docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^testapp$'"
  record_check "6" "Контейнер testapp запущен" "docker" "$?"

  run_remote "$BR_SRV_IP" "ss -lnt | grep -q ':8080 '"
  record_check "6" "Приложение на BR-SRV слушает 8080/tcp" "testapp" "$?"

  run_remote "$HQ_CLI_IP" "realm list 2>/dev/null | grep -qi 'au-team.irpo'"
  record_check "7" "HQ-CLI присоединен к домену" "realm list" "$?"

  run_remote "$HQ_CLI_IP" "mountpoint -q /mnt/nfs"
  record_check "7" "NFS на HQ-CLI смонтирован в /mnt/nfs" "mountpoint" "$?"

  run_remote "$BR_SRV_IP" "ansible all -m ping -o >/tmp/ansible_ping.out 2>&1 && ! grep -q 'UNREACHABLE' /tmp/ansible_ping.out"
  record_check "8" "Ansible ping с BR-SRV успешен для всех узлов" "ansible all -m ping" "$?"

  # ---------------- Module 3 ----------------
  module_start "3"

  run_remote "$BR_SRV_IP" "test -x /opt/import_users.sh"
  record_check "1" "Скрипт импорта пользователей присутствует" "/opt/import_users.sh" "$?"

  run_remote "$BR_SRV_IP" "samba-tool user list 2>/dev/null | grep -Eiq 'hquser1|atran|lbuck|qpurk'"
  record_check "1" "Импорт пользователей в домен выполнен" "samba-tool user list" "$?"

  run_remote "$HQ_CLI_IP" "grep -q 'pam_mkhomedir.so' /etc/pam.d/common-session"
  record_check "2" "pam_mkhomedir настроен на HQ-CLI" "common-session" "$?"

  run_remote "$HQ_RTR_IP" "ipsec statusall 2>/dev/null | grep -q 'gre-encrypt'"
  record_check "3" "IPsec профиль gre-encrypt активен на HQ-RTR" "ipsec" "$?"

  run_remote "$BR_RTR_IP" "ipsec statusall 2>/dev/null | grep -q 'gre-encrypt'"
  record_check "3" "IPsec профиль gre-encrypt активен на BR-RTR" "ipsec" "$?"

  run_remote "$HQ_RTR_IP" "test -x /etc/start_iptables.sh && iptables -S | grep -q '^-P INPUT DROP'"
  record_check "4" "Firewall-скрипт и DROP policy на HQ-RTR" "/etc/start_iptables.sh" "$?"

  run_remote "$BR_RTR_IP" "test -x /etc/start_iptables.sh && iptables -S | grep -q '^-P INPUT DROP'"
  record_check "4" "Firewall-скрипт и DROP policy на BR-RTR" "/etc/start_iptables.sh" "$?"

  run_remote "$HQ_SRV_IP" "systemctl is-active cups >/dev/null 2>&1 && lpstat -v 2>/dev/null | grep -q 'CUPS-PDF'"
  record_check "5" "CUPS сервер и CUPS-PDF настроены на HQ-SRV" "cups" "$?"

  run_remote "$HQ_CLI_IP" "lpstat -v 2>/dev/null | grep -q 'Virtual_PDF_Printer'"
  record_check "5" "Virtual_PDF_Printer добавлен на HQ-CLI" "lpstat" "$?"

  run_remote "$BR_SRV_IP" "systemctl is-active rsyslog >/dev/null 2>&1 && ss -lun | grep -q ':514 '"
  record_check "6" "Rsyslog сервер на BR-SRV слушает 514/udp" "imudp/imtcp" "$?"

  run_remote "$HQ_RTR_IP" "grep -q '@${BR_SRV_IP}:514' /etc/rsyslog.d/90-remote-forward.conf"
  record_check "6" "Rsyslog forwarding настроен на HQ-RTR" "90-remote-forward.conf" "$?"

  run_remote "$BR_RTR_IP" "grep -q '@${BR_SRV_IP}:514' /etc/rsyslog.d/90-remote-forward.conf"
  record_check "6" "Rsyslog forwarding настроен на BR-RTR" "90-remote-forward.conf" "$?"

  run_remote "$HQ_SRV_IP" "grep -q '@${BR_SRV_IP}:514' /etc/rsyslog.d/90-remote-forward.conf"
  record_check "6" "Rsyslog forwarding настроен на HQ-SRV" "90-remote-forward.conf" "$?"

  run_remote "$BR_SRV_IP" "test -f /etc/ansible/playbook/get_hostname_address.yml && test -f /etc/ansible/PC-INFO/hq-srv.yml && test -f /etc/ansible/PC-INFO/hq-cli.yml"
  record_check "8" "Отчеты инвентаризации Ansible сгенерированы" "/etc/ansible/PC-INFO/*.yml" "$?"

  run_remote "$HQ_SRV_IP" "systemctl is-active fail2ban >/dev/null 2>&1 && fail2ban-client status sshd >/dev/null 2>&1"
  record_check "9" "Fail2ban активен и jail sshd работает" "fail2ban" "$?"

  run_remote "$HQ_CLI_IP" "id backupuser >/dev/null 2>&1 && [ -d /backup/etc ] && [ -d /backup/webdb ]"
  record_check "10" "Restic storage подготовлен на HQ-CLI" "backupuser,/backup" "$?"

  run_remote "$HQ_SRV_IP" "id irpoadmin >/dev/null 2>&1 && [ -x /home/irpoadmin/backup_etc.sh ] && [ -x /home/irpoadmin/backup_webdb.sh ]"
  record_check "10" "Restic скрипты backup созданы на HQ-SRV" "backup_etc.sh,backup_webdb.sh" "$?"

  run_remote "$HQ_SRV_IP" "sudo -u irpoadmin RESTIC_PASSWORD='P@ssw0rd' restic snapshots --repo 'sftp:backupuser@hq-cli.au-team.irpo:/backup/etc' >/dev/null 2>&1 && sudo -u irpoadmin RESTIC_PASSWORD='P@ssw0rd' restic snapshots --repo 'sftp:backupuser@hq-cli.au-team.irpo:/backup/webdb' >/dev/null 2>&1"
  record_check "10" "Restic репозитории доступны и snapshots читаются" "restic snapshots" "$?"

  print_summary
}

main "$@"

# Clean command history (best-effort).
history -c 2>/dev/null || true
history -w 2>/dev/null || true
unset HISTFILE || true
rm -f /root/.bash_history /home/user/.bash_history /root/.zsh_history /home/user/.zsh_history 2>/dev/null || true

SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
rm -f -- "$SCRIPT_PATH" || true
