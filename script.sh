#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C

R0=$'\033[0m'
B0=$'\033[1m'
D0=$'\033[2m'
RD=$'\033[31m'
GN=$'\033[32m'
YL=$'\033[33m'
BL=$'\033[34m'
MG=$'\033[35m'
CY=$'\033[36m'
WT=$'\033[37m'

SPIN_CHARS='|/-\'
SPIN_PID=""

die() { echo -e "${RD}${B0}✖${R0} $*" >&2; exit 1; }
ok() { echo -e "${GN}${B0}✔${R0} $*"; }
info() { echo -e "${CY}${B0}➜${R0} $*"; }
warn() { echo -e "${YL}${B0}⚠${R0} $*"; }

start_spinner() {
  local msg="$1"
  echo -ne "${BL}${B0}⟲${R0} ${msg} "
  (
    local i=0
    while :; do
      i=$(( (i + 1) % 4 ))
      printf "\b${MG}%s${R0}" "${SPIN_CHARS:$i:1}"
      sleep 0.1
    done
  ) &
  SPIN_PID="$!"
}

stop_spinner_ok() {
  if [[ -n "${SPIN_PID}" ]]; then
    kill "${SPIN_PID}" >/dev/null 2>&1 || true
    wait "${SPIN_PID}" >/dev/null 2>&1 || true
    SPIN_PID=""
    echo -e "\b${GN}${B0}✔${R0}"
  fi
}

stop_spinner_fail() {
  if [[ -n "${SPIN_PID}" ]]; then
    kill "${SPIN_PID}" >/dev/null 2>&1 || true
    wait "${SPIN_PID}" >/dev/null 2>&1 || true
    SPIN_PID=""
    echo -e "\b${RD}${B0}✖${R0}"
  fi
}

on_err() {
  stop_spinner_fail
  echo -e "${RD}${B0}Ошибка${R0}: команда завершилась неуспешно."
  echo -e "${D0}Строка:${R0} ${BASH_LINENO[0]}  ${D0}Команда:${R0} ${BASH_COMMAND}"
}
trap on_err ERR

require_root() { [[ "${EUID}" -eq 0 ]] || die "Запусти от root: sudo -i"; }
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  local pkgs=("$@")
  start_spinner "Установка пакетов: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >/dev/null
  stop_spinner_ok
}

read_nonempty() {
  local prompt="$1"
  local varname="$2"
  local secret="${3:-0}"
  local value=""
  while [[ -z "${value}" ]]; do
    if [[ "${secret}" == "1" ]]; then
      read -r -s -p "$(echo -e "${B0}${prompt}${R0} ")" value
      echo
    else
      read -r -p "$(echo -e "${B0}${prompt}${R0} ")" value
    fi
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
  done
  printf -v "${varname}" '%s' "${value}"
}

normalize_domain() {
  local d="$1"
  d="${d#http://}"
  d="${d#https://}"
  d="${d%%/*}"
  echo "$d"
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

validate_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    (( x >= 0 && x <= 255 )) || return 1
  done
}

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
}

ensure_git_python_yaml() {
  local need=()
  cmd_exists git || need+=(git)
  cmd_exists python3 || need+=(python3)
  python3 -c "import yaml" >/dev/null 2>&1 || need+=(python3-yaml)
  ((${#need[@]})) && apt_install "${need[@]}" || ok "git/python3/yaml уже есть"
}

ensure_docker() {
  if ! cmd_exists docker; then
    warn "Docker не найден. Ставлю docker.io + compose plugin."
    apt_install ca-certificates curl gnupg lsb-release
    apt_install docker.io docker-compose-plugin
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi

  if ! docker info >/dev/null 2>&1; then
    die "Docker не запускается. Проверь: systemctl status docker"
  fi

  if ! docker compose version >/dev/null 2>&1; then
    apt_install docker-compose-plugin
  fi

  ok "Docker работает"
}

detect_ssh_unit() {
  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then
    echo "ssh"; return 0
  fi
  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then
    echo "sshd"; return 0
  fi
  if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then
    echo "ssh"; return 0
  fi
  if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then
    echo "sshd"; return 0
  fi
  return 1
}

ensure_sshd_include_dropins() {
  local main_cfg="/etc/ssh/sshd_config"
  [[ -f "$main_cfg" ]] || die "Не найден $main_cfg"
  if grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$' "$main_cfg"; then
    return 0
  fi
  backup_file "$main_cfg"
  { echo "Include /etc/ssh/sshd_config.d/*.conf"; echo; cat "$main_cfg"; } > "${main_cfg}.tmp"
  mv "${main_cfg}.tmp" "$main_cfg"
}

comment_out_other_port_directives() {
  local keep_file="$1"
  local main_cfg="/etc/ssh/sshd_config"

  if grep -Eiq '^\s*Port\s+[0-9]+' "$main_cfg"; then
    backup_file "$main_cfg"
    sed -i -E 's/^\s*(Port\s+[0-9]+)\s*$/# \1/Ig' "$main_cfg"
  fi

  shopt -s nullglob
  local f
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [[ "$f" == "$keep_file" ]] && continue
    if grep -Eiq '^\s*Port\s+[0-9]+' "$f"; then
      backup_file "$f"
      sed -i -E 's/^\s*(Port\s+[0-9]+)\s*$/# \1/Ig' "$f"
    fi
  done
  shopt -u nullglob
}

restart_ssh_and_verify() {
  local unit="$1"
  local new_port="$2"

  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.socket'; then
    systemctl restart ssh.socket >/dev/null 2>&1 || true
  fi

  systemctl restart "${unit}" >/dev/null

  systemctl is-active --quiet "${unit}" || {
    echo -e "${RD}${B0}SSH unit не активен после рестарта.${R0}"
    journalctl -u "${unit}" -n 120 --no-pager || true
    die "SSH не поднялся после применения конфига"
  }

  cmd_exists ss || apt_install iproute2

  if ! ss -lntp 2>/dev/null | grep -qE "LISTEN.+:${new_port}\b"; then
    echo -e "${RD}${B0}sshd не слушает порт ${new_port}.${R0}"
    ss -lntp 2>/dev/null | grep -i ssh || ss -lntp 2>/dev/null || true
    echo -e "${WT}${B0}Эффективная конфигурация sshd (port):${R0}"
    sshd -T 2>/dev/null | awk '/^port /{print}' || true
    journalctl -u "${unit}" -n 120 --no-pager || true
    die "Порт не применился / sshd не слушает новый порт"
  fi
}

set_root_password() {
  echo -e "${CY}${B0}ROOT пароль:${R0}"
  passwd root
  ok "Пароль root изменён"
}

ssh_hardening_port() {
  local new_port="$1"
  validate_port "$new_port" || die "Неверный порт SSH: $new_port"

  start_spinner "Настройка SSH (порт ${new_port})"

  local dropin_dir="/etc/ssh/sshd_config.d"
  local dropin_file="${dropin_dir}/99-custom.conf"

  mkdir -p "${dropin_dir}"
  ensure_sshd_include_dropins
  backup_file "${dropin_file}"

  cat > "${dropin_file}" <<EOF
Port ${new_port}
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PrintMotd no
Banner none
EOF

  rm -f /etc/issue /etc/issue.net
  : > /etc/issue
  : > /etc/issue.net

  comment_out_other_port_directives "${dropin_file}"

  if ! sshd -t >/dev/null 2>&1; then
    stop_spinner_fail
    sshd -t || true
    die "sshd_config невалиден после изменений. Проверь ${dropin_file}"
  fi

  local unit
  unit="$(detect_ssh_unit)" || { stop_spinner_fail; die "Не нашёл systemd unit ssh/sshd. Проверь systemctl status ssh sshd"; }

  restart_ssh_and_verify "${unit}" "${new_port}"

  stop_spinner_ok
  ok "SSH применён. Новый порт: ${new_port}"
  echo -e "${YL}${B0}ВАЖНО:${R0} проверь вход в новой сессии: ${B0}ssh -p ${new_port} root@<IP>${R0}"
}

setup_fail2ban() {
  apt_install fail2ban
  start_spinner "Настройка Fail2Ban"
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
bantime = 30m
findtime = 10m
maxretry = 5
backend = systemd
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  stop_spinner_ok
  ok "Fail2Ban активирован"
}

setup_sysctl() {
  start_spinner "Применение sysctl"
  cat > /etc/sysctl.d/99-hardening.conf <<EOF
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
  sysctl --system >/dev/null 2>&1 || true
  stop_spinner_ok
  ok "sysctl применён"
}

disable_ufw() {
  start_spinner "Отключение UFW"
  systemctl stop ufw >/dev/null 2>&1 || true
  systemctl disable ufw >/dev/null 2>&1 || true
  stop_spinner_ok
  ok "UFW выключен"
}

disable_netfilter_persistent() {
  start_spinner "Отключение netfilter-persistent"
  systemctl stop netfilter-persistent >/dev/null 2>&1 || true
  systemctl disable netfilter-persistent >/dev/null 2>&1 || true
  stop_spinner_ok
  ok "netfilter-persistent выключен"
}

setup_nftables_firewall() {
  local ssh_port="$1"
  local control_ip="$2"
  local monitoring_ip="$3"

  validate_port "$ssh_port" || die "Неверный SSH порт для nftables"
  validate_ipv4 "$control_ip" || die "Неверный IPv4 control_plane_sources: $control_ip"
  validate_ipv4 "$monitoring_ip" || die "Неверный IPv4 monitoring_sources: $monitoring_ip"

  apt_install nftables
  start_spinner "Настройка nftables (/etc/nftables.conf)"

  backup_file /etc/nftables.conf

  cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

define SSH_PORT = ${ssh_port}
define CONTROL_PORT = 4431
define MONITORING_PORT = 9100
define WEB_PORTS = { 80, 443 }

table inet firewall {

    set ddos_blacklist {
        type ipv4_addr
        flags timeout
        timeout 5m
        size 8192
        comment "Dynamic blacklist for DDoS sources"
    }

    set user_blacklist {
        type ipv4_addr
        flags timeout
        size 8192
        comment "Dynamic blacklist for subscription policy violators"
    }

    set control_plane_sources {
        type ipv4_addr
        elements = { ${control_ip} }
    }

    set monitoring_sources {
        type ipv4_addr
        elements = { ${monitoring_ip} }
    }

    set tls_flood_sources {
        type ipv4_addr
        flags timeout
        timeout 15m
        size 4096
    }

    chain prerouting {
        type filter hook prerouting priority raw; policy accept;

        ip saddr @user_blacklist drop comment "Drop traffic from policy violators"

        ip6 version 6 drop comment "Block IPv6 completely"
        iif != lo ip saddr 127.0.0.0/8 drop comment "Block spoofed loopback from external"
        ip frag-off & 0x1fff != 0 drop comment "Drop fragmented packets"

        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop comment "Drop NULL packets"
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg drop comment "Drop XMAS packets"
        tcp flags & (syn|rst) == syn|rst drop comment "Drop SYN+RST packets"
        tcp flags & (syn|fin) == syn|fin drop comment "Drop SYN+FIN packets"

        fib daddr type broadcast drop comment "Drop broadcast early"
        fib daddr type multicast drop comment "Drop multicast early"
        fib daddr type anycast   drop comment "Drop anycast early"

        ip saddr @ddos_blacklist drop comment "Drop blacklisted source early"

        tcp dport \$SSH_PORT tcp flags & (syn|ack) == syn limit rate 5/second burst 3 packets accept comment "SSH SYN flood limit"
        tcp dport \$SSH_PORT tcp flags & (syn|ack) == syn add @ddos_blacklist { ip saddr timeout 5m } drop comment "Blacklist SSH flooders"

        ip protocol icmp icmp type echo-request limit rate 2/second burst 2 packets accept comment "Allow limited ping"
        ip protocol icmp icmp type echo-request add @ddos_blacklist { ip saddr timeout 5m } drop comment "Blacklist ping flooders"
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept comment "Allow established forward"
        drop comment "Drop forward"
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }

    chain filter_input {
        type filter hook input priority filter; policy drop;

        iif lo accept comment "Allow loopback"
        ct state invalid drop comment "Drop invalid packets"
        ct state established,related accept comment "Allow established"

        ip saddr @ddos_blacklist drop comment "Drop known DDoS sources"

        tcp dport \$WEB_PORTS ct count over 100 drop comment "Limit concurrent web connections"
        tcp dport \$SSH_PORT ct count over 15 drop comment "Limit SSH connections"
        ct count over 100 drop comment "Limit total connections per IP"

        tcp dport \$SSH_PORT ct state new meter ssh_meter { ip saddr limit rate 5/minute burst 3 packets } accept comment "SSH rate limit"
        tcp dport \$SSH_PORT ct state new add @ddos_blacklist { ip saddr timeout 5m } drop comment "SSH flood → blacklist"

        ip saddr @control_plane_sources tcp dport \$CONTROL_PORT ct state new accept comment "Control plane"
        ip saddr @monitoring_sources tcp dport \$MONITORING_PORT ct state new accept comment "Monitoring"

        ip saddr @tls_flood_sources drop comment "Drop TLS flooded IPs"
        tcp dport 443 ct state new meter tls_meter { ip saddr limit rate 400/second burst 300 packets } accept comment "TLS connections"
        tcp dport 443 ct state new add @tls_flood_sources { ip saddr timeout 5m } drop comment "TLS flood → temp block"

        tcp dport 80 ct state new meter cert_meter { ip saddr limit rate 5/minute burst 3 packets } accept comment "HTTP cert renewal"

        drop comment "Default drop"
    }
}
EOF

  if ! nft -c -f /etc/nftables.conf >/dev/null 2>&1; then
    stop_spinner_fail
    nft -c -f /etc/nftables.conf || true
    die "nftables.conf невалиден"
  fi

  if ! nft -f /etc/nftables.conf >/dev/null 2>&1; then
    stop_spinner_fail
    nft -f /etc/nftables.conf || true
    die "Не удалось применить правила nft"
  fi

  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl restart nftables >/dev/null

  systemctl is-active --quiet nftables || {
    stop_spinner_fail
    systemctl status nftables --no-pager || true
    die "nftables не активен после рестарта"
  }

  stop_spinner_ok
  ok "nftables настроен и применён"
}

clone_or_update_repo() {
  local dst="/opt/remnawave-observer"
  local url="https://github.com/0FL01/remnawave-observer.git"

  mkdir -p /opt
  if [[ -d "${dst}/.git" ]]; then
    start_spinner "Обновляю репозиторий в ${dst}"
    git -C "${dst}" fetch --all --prune >/dev/null
    git -C "${dst}" reset --hard origin/main >/dev/null 2>&1 || git -C "${dst}" reset --hard origin/master >/dev/null
    stop_spinner_ok
  else
    start_spinner "Клонирую репозиторий в ${dst}"
    rm -rf "${dst}"
    git clone --depth 1 "${url}" "${dst}" >/dev/null
    stop_spinner_ok
  fi
  ok "Репозиторий готов: ${dst}"
}

ensure_remnanode_paths() {
  [[ -d /opt/remnanode ]] || die "Не найден каталог /opt/remnanode (должен существовать с твоим remnanode docker-compose.yml)"
  [[ -f /opt/remnanode/docker-compose.yml ]] || die "Не найден /opt/remnanode/docker-compose.yml"

  mkdir -p /var/log/remnanode
  chown -R 1000:1000 /var/log/remnanode >/dev/null 2>&1 || true
  chmod 755 /var/log/remnanode >/dev/null 2>&1 || true
  ok "Логи remnanode: /var/log/remnanode"
}

upsert_env_kv_with_blank_before() {
  local file="$1"
  local key="$2"
  local val="$3"
  mkdir -p "$(dirname "$file")"
  touch "$file"

  python3 - <<PY
import os, re
path = "${file}"
key = "${key}"
val = "${val}"
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.read().splitlines()

out = []
found = False
for line in lines:
    if line.startswith(key + "="):
        continue
    out.append(line)

need_blank = False
if out and out[-1].strip() != "":
    need_blank = True

if need_blank:
    out.append("")

out.append(f"{key}={val}")

tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write("\n".join(out) + "\n")
os.replace(tmp, path)
PY
}

render_vector_toml_exact() {
  local domain="$1"
  local out="/opt/remnanode/vector.toml"
  local uri="https://${domain}:38213/"

  cat > "${out}" <<EOF
# Источник данных: указываем, откуда читать логи.
# Мы будем читать access.log из директории, которую пробросим из remnanode.
[sources.xray_access_logs]
  type = "file"
  # ВАЖНО: Путь внутри контейнера Vector. Мы пробросим /var/log/remnanode с хоста.
  include = ["/var/log/remnanode/access.log"]
  # Начинаем читать с конца файла, чтобы не обрабатывать старые записи при перезапуске
  read_from = "end"

# Трансформация: парсим каждую строку лога, чтобы извлечь нужные данные.
[transforms.parse_xray_log]
  type = "remap"
  inputs = ["xray_access_logs"]
  source = '''
    # (tcp:)? означает, что группа "tcp:" может присутствовать 0 или 1 раз.
    pattern = r'from (tcp:)?(?P<ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):\\d+.*? email: (?P<email>\\S+)'

    parsed, err = parse_regex(.message, pattern)

    if err != null {
      log("Не удалось распарсить строку лога: " + err, level: "warn")
      abort
    }

    . = {
      "user_email": parsed.email,
      "source_ip": parsed.ip,
      "timestamp": to_string(now())
    }
  '''

# Назначение: отправляем обработанные данные на наш центральный сервис-наблюдатель.
[sinks.central_observer_api]
  type = "http"
  inputs = ["parse_xray_log"]
  # ВАЖНО: Указываем HTTPS и ваш домен!
  uri = "${uri}"
  method = "post"
  encoding.codec = "json"
  compression = "gzip"

  [sinks.central_observer_api.batch]
    max_events = 100
    timeout_secs = 5

  [sinks.central_observer_api.request]
    retry_attempts = 5
    retry_backoff_secs = 2

  [sinks.central_observer_api.tls]
EOF

  ok "Создан /opt/remnanode/vector.toml → ${uri}"
}

patch_compose_add_services() {
  python3 - <<'PY'
import sys, os
import yaml

compose_path = "/opt/remnanode/docker-compose.yml"

with open(compose_path, "r", encoding="utf-8") as f:
    data = yaml.safe_load(f) or {}

if not isinstance(data, dict):
    raise SystemExit("docker-compose.yml не YAML-словарь")

services = data.get("services")
if services is None:
    services = {}
    data["services"] = services
if not isinstance(services, dict):
    raise SystemExit("services в docker-compose.yml не словарь")

if "remnanode" not in services:
    raise SystemExit("В docker-compose.yml не найден сервис 'remnanode'")

blocker = {
  "container_name": "blocker-xray",
  "hostname": "blocker-xray",
  "image": "quay.io/0fl01/blocker-xray-go:0.0.6",
  "restart": "unless-stopped",
  "network_mode": "host",
  "logging": {
    "driver": "json-file",
    "options": {"max-size":"8m","max-file":"5"}
  },
  "env_file": [".env"],
  "cap_add": ["NET_ADMIN","NET_RAW"],
  "depends_on": ["remnanode"],
  "deploy": {
    "resources": {
      "limits": {"memory":"64M","cpus":"0.25"},
      "reservations": {"memory":"32M","cpus":"0.10"}
    }
  }
}

vector = {
  "image": "timberio/vector:0.48.0-alpine",
  "container_name": "vector",
  "hostname": "vector",
  "restart": "unless-stopped",
  "network_mode": "host",
  "command": ["--config", "/etc/vector/vector.toml"],
  "depends_on": ["remnanode"],
  "volumes": [
    "./vector.toml:/etc/vector/vector.toml:ro",
    "/var/log/remnanode:/var/log/remnanode:ro"
  ],
  "logging": {
    "driver": "json-file",
    "options": {"max-size":"8m","max-file":"3"}
  },
  "deploy": {
    "resources": {
      "limits": {"memory":"128M","cpus":"0.25"},
      "reservations": {"memory":"64M","cpus":"0.10"}
    }
  }
}

changed = False
for name, svc in (("blocker-xray", blocker), ("vector", vector)):
    if name not in services:
        services[name] = svc
        changed = True

if not changed:
    print("NOCHANGE")
    sys.exit(0)

tmp = compose_path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    yaml.safe_dump(
        data, f,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True
    )
os.replace(tmp, compose_path)
print("CHANGED")
PY
}

compose_down_up() {
  start_spinner "docker compose down"
  (cd /opt/remnanode && docker compose down --remove-orphans) >/dev/null 2>&1 || true
  stop_spinner_ok

  start_spinner "docker compose up -d"
  (cd /opt/remnanode && docker compose up -d) >/dev/null
  stop_spinner_ok
}

show_status() {
  echo -e "${WT}${B0}Состояние контейнеров:${R0}"
  (cd /opt/remnanode && docker compose ps) || true
  echo
  echo -e "${WT}${B0}Логи blocker-xray (последние 120 строк):${R0}"
  docker logs --tail 120 blocker-xray 2>/dev/null || true
  echo
  echo -e "${WT}${B0}Логи vector (последние 120 строк):${R0}"
  docker logs --tail 120 vector 2>/dev/null || true
}

main() {
  require_root

  clear || true
  echo -e "${CY}${B0}=== VPS HARDENING + Observer Node Installer (nftables) ===${R0}"
  echo

  if ! cmd_exists apt-get; then
    die "Нужен Debian/Ubuntu (apt-get не найден)."
  fi

  ensure_git_python_yaml
  ensure_docker
  apt_install ca-certificates curl iproute2 openssh-server

  read_nonempty "Новый SSH порт (например 50012):" SSH_PORT 0
  validate_port "${SSH_PORT}" || die "Порт невалидный"

  read_nonempty "IPv4 адрес главного сервера (Control plane, для nftables):" CONTROL_IP 0
  validate_ipv4 "${CONTROL_IP}" || die "IPv4 невалидный"

  read_nonempty "IPv4 адрес monitoring (если нет отдельного — введи тот же):" MON_IP 0
  validate_ipv4 "${MON_IP}" || die "IPv4 невалидный"

  echo
  set_root_password
  echo

  ssh_hardening_port "${SSH_PORT}"
  setup_fail2ban
  setup_sysctl
  disable_ufw
  disable_netfilter_persistent

  setup_nftables_firewall "${SSH_PORT}" "${CONTROL_IP}" "${MON_IP}"

  echo
  echo -e "${MG}${B0}=== Установка Blocker + Vector ===${R0}"
  echo

  read_nonempty "Домен центрального Observer (пример: obs.noctacore.com):" OBS_DOMAIN 0
  OBS_DOMAIN="$(normalize_domain "${OBS_DOMAIN}")"

  read_nonempty "RabbitMQ URL (пример: amqps://user:pass@${OBS_DOMAIN}:38214/):" RABBITMQ_URL 0

  clone_or_update_repo
  ensure_remnanode_paths

  upsert_env_kv_with_blank_before "/opt/remnanode/.env" "RABBITMQ_URL" "${RABBITMQ_URL}"
  ok "Обновлён /opt/remnanode/.env (перед RABBITMQ_URL вставлена пустая строка, если файл был не пустой)"

  render_vector_toml_exact "${OBS_DOMAIN}"

  start_spinner "Правлю /opt/remnanode/docker-compose.yml (blocker-xray + vector)"
  out="$(patch_compose_add_services || true)"
  stop_spinner_ok
  if [[ "${out:-}" == "NOCHANGE" ]]; then
    ok "docker-compose.yml уже содержит blocker-xray/vector"
  else
    ok "docker-compose.yml обновлён"
  fi

  compose_down_up

  echo
  ok "Готово"
  echo
  show_status
  echo
  echo -e "${YL}${B0}Проверь:${R0} в новой сессии SSH: ${B0}ssh -p ${SSH_PORT} root@<IP>${R0}"
  echo -e "${YL}${B0}Проверка nftables:${R0} ${B0}nft list ruleset | sed -n '1,120p'${R0}"
}

main "$@"
