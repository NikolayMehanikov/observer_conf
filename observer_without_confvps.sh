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
ok()  { echo -e "${GN}${B0}✔${R0} $*"; }
info(){ echo -e "${CY}${B0}➜${R0} $*"; }
warn(){ echo -e "${YL}${B0}⚠${R0} $*"; }

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
  stop_spinner_fail || true
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

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
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

read_with_default() {
  local prompt="$1"
  local def="$2"
  local varname="$3"
  local value=""
  read -r -p "$(echo -e "${B0}${prompt}${R0} ${D0}(Enter = ${def})${R0} ")" value || true
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -z "$value" ]]; then
    value="$def"
  fi
  printf -v "${varname}" '%s' "${value}"
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

validate_ipv4_one() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    (( x >= 0 && x <= 255 )) || return 1
  done
}

normalize_ipv4_list_to_nft_elements() {
  local raw="$1"
  local cleaned
  cleaned="$(echo "$raw" | tr ',;' '  ' | tr -s ' ' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  [[ -n "$cleaned" ]] || die "IP список пустой"
  local out=()
  local ip
  while read -r ip; do
    [[ -n "$ip" ]] || continue
    validate_ipv4_one "$ip" || die "Невалидный IPv4: $ip"
    out+=("$ip")
  done < <(echo "$cleaned" | tr ' ' '\n' | sed '/^$/d')

  [[ "${#out[@]}" -gt 0 ]] || die "IP список пустой"

  local joined=""
  local i=0
  for ip in "${out[@]}"; do
    if (( i == 0 )); then joined="$ip"; else joined="$joined, $ip"; fi
    i=$((i+1))
  done
  echo "$joined"
}

ensure_git_python_yaml() {
  local need=()
  cmd_exists git || need+=(git)
  cmd_exists python3 || need+=(python3)
  python3 -c "import yaml" >/dev/null 2>&1 || need+=(python3-yaml)
  ((${#need[@]})) && apt_install "${need[@]}" || ok "git/python3/yaml уже есть"
}

# НУЖНО ДЛЯ ЗАПУСКА vector/blocker в docker:
ensure_docker() {
  if ! cmd_exists docker; then
    warn "Docker не найден. Ставлю docker.io + compose plugin."
    apt_install ca-certificates curl gnupg lsb-release
    apt_install docker.io docker-compose-plugin
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker info >/dev/null 2>&1 || die "Docker не запускается. Проверь: systemctl status docker"
  ok "Docker работает"
}

# ---------------------------------------------------------------------------
# ВСЁ НИЖЕ — НАСТРОЙКА VPS (SSH/ROOT/F2B/SYSCTL/UFW) — ЗАКОММЕНТИРОВАНО ПО ПРОСЬБЕ
# ---------------------------------------------------------------------------

# detect_ssh_unit() {
#   if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then echo "ssh"; return 0; fi
#   if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then echo "sshd"; return 0; fi
#   if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then echo "ssh"; return 0; fi
#   if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then echo "sshd"; return 0; fi
#   return 1
# }

# ensure_run_sshd_dir() {
#   mkdir -p /run/sshd
#   chmod 0755 /run/sshd
#   chown root:root /run/sshd
# }

# ensure_sshd_include_dropins() {
#   local main_cfg="/etc/ssh/sshd_config"
#   [[ -f "$main_cfg" ]] || die "Не найден $main_cfg"
#   if grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$' "$main_cfg"; then
#     return 0
#   fi
#   backup_file "$main_cfg"
#   { echo "Include /etc/ssh/sshd_config.d/*.conf"; echo; cat "$main_cfg"; } > "${main_cfg}.tmp"
#   mv "${main_cfg}.tmp" "$main_cfg"
# }

# comment_out_other_port_directives() {
#   local keep_file="$1"
#   local main_cfg="/etc/ssh/sshd_config"
#   if grep -Eiq '^\s*Port\s+[0-9]+' "$main_cfg"; then
#     backup_file "$main_cfg"
#     sed -i -E 's/^\s*(Port\s+[0-9]+)\s*$/# \1/Ig' "$main_cfg"
#   fi
#   shopt -s nullglob
#   local f
#   for f in /etc/ssh/sshd_config.d/*.conf; do
#     [[ "$f" == "$keep_file" ]] && continue
#     if grep -Eiq '^\s*Port\s+[0-9]+' "$f"; then
#       backup_file "$f"
#       sed -i -E 's/^\s*(Port\s+[0-9]+)\s*$/# \1/Ig' "$f"
#     fi
#   done
#   shopt -u nullglob
# }

# restart_ssh_and_verify() {
#   local unit="$1"
#   local new_port="$2"
#   systemctl daemon-reload >/dev/null 2>&1 || true
#   ensure_run_sshd_dir
#   if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.socket'; then
#     systemctl restart ssh.socket >/dev/null 2>&1 || true
#   fi
#   systemctl restart "${unit}" >/dev/null
#   systemctl is-active --quiet "${unit}" || {
#     echo -e "${RD}${B0}SSH unit не активен после рестарта.${R0}"
#     journalctl -u "${unit}" -n 160 --no-pager || true
#     die "SSH не поднялся после применения конфига"
#   }
#   if ! cmd_exists ss; then apt_install iproute2; fi
#   if ! ss -lntp 2>/dev/null | grep -qE "LISTEN.+:${new_port}\b"; then
#     echo -e "${RD}${B0}sshd не слушает порт ${new_port}.${R0}"
#     ss -lntp 2>/dev/null | grep -i ssh || ss -lntp 2>/dev/null || true
#     sshd -T 2>/dev/null | awk '/^port /{print}' || true
#     journalctl -u "${unit}" -n 200 --no-pager || true
#     die "Порт не применился / sshd не слушает новый порт"
#   fi
# }

# ssh_hardening_port() {
#   local new_port="$1"
#   validate_port "$new_port" || die "Неверный порт SSH: $new_port"
#   start_spinner "Настройка SSH (порт ${new_port})"
#   local dropin_dir="/etc/ssh/sshd_config.d"
#   local dropin_file="${dropin_dir}/99-custom.conf"
#   mkdir -p "${dropin_dir}"
#   ensure_sshd_include_dropins
#   backup_file "${dropin_file}"
#   cat > "${dropin_file}" <<EOF
# # Managed by installer script
# Port ${new_port}
# PermitRootLogin yes
# PasswordAuthentication yes
# KbdInteractiveAuthentication yes
# PubkeyAuthentication yes
# PrintMotd no
# Banner none
# EOF
#   rm -f /etc/issue /etc/issue.net || true
#   : > /etc/issue
#   : > /etc/issue.net
#   comment_out_other_port_directives "${dropin_file}"
#   ensure_run_sshd_dir
#   if ! sshd -t >/dev/null 2>&1; then
#     stop_spinner_fail
#     sshd -t || true
#     die "sshd_config невалиден после изменений. Проверь ${dropin_file}"
#   fi
#   local unit
#   unit="$(detect_ssh_unit)" || { stop_spinner_fail; die "Не нашёл systemd unit ssh/sshd."; }
#   restart_ssh_and_verify "${unit}" "${new_port}"
#   stop_spinner_ok
#   ok "SSH применён. Новый порт: ${new_port}"
#   echo -e "${YL}${B0}ВАЖНО:${R0} проверь вход в новой сессии: ${B0}ssh -p ${new_port} root@<IP>${R0}"
# }

# set_root_password() {
#   echo -e "${CY}${B0}ROOT пароль:${R0}"
#   passwd root
#   ok "Пароль root изменён"
# }

# setup_fail2ban() {
#   apt_install fail2ban
#   start_spinner "Настройка Fail2Ban"
#   mkdir -p /etc/fail2ban/jail.d
#   cat > /etc/fail2ban/jail.d/sshd.local <<EOF
# [sshd]
# enabled = true
# bantime = 30m
# findtime = 10m
# maxretry = 5
# backend = systemd
# EOF
#   systemctl enable fail2ban >/dev/null 2>&1 || true
#   systemctl restart fail2ban >/dev/null 2>&1 || true
#   stop_spinner_ok
#   ok "Fail2Ban активирован"
# }

# setup_sysctl() {
#   start_spinner "Применение sysctl"
#   cat > /etc/sysctl.d/99-hardening.conf <<EOF
# net.ipv4.icmp_echo_ignore_all = 1
# net.ipv4.tcp_syncookies = 1
# net.ipv4.conf.all.send_redirects = 0
# net.ipv4.conf.default.send_redirects = 0
# net.ipv4.conf.all.accept_redirects = 0
# net.ipv4.conf.default.accept_redirects = 0
# net.ipv4.conf.all.rp_filter = 1
# net.ipv4.conf.default.rp_filter = 1
# EOF
#   sysctl --system >/dev/null 2>&1 || true
#   stop_spinner_ok
#   ok "sysctl применён"
# }

# disable_ufw() {
#   start_spinner "Отключение UFW"
#   systemctl stop ufw >/dev/null 2>&1 || true
#   systemctl disable ufw >/dev/null 2>&1 || true
#   stop_spinner_ok
#   ok "UFW выключен"
# }

# ---------------------------------------------------------------------------
# NFTABLES + OBSERVER INSTALL
# ---------------------------------------------------------------------------

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

apply_nftables_from_repo_example() {
  local ssh_port="$1"
  local control_port="$2"
  local monitoring_port="$3"
  local node_api_port="$4"
  local control_ips_csv="$5"
  local monitoring_ips_csv="$6"

  local src="/opt/remnawave-observer/nftables_example.conf"
  [[ -f "$src" ]] || die "Не найден ${src}"

  local control_elems monitoring_elems
  control_elems="$(normalize_ipv4_list_to_nft_elements "$control_ips_csv")"
  monitoring_elems="$(normalize_ipv4_list_to_nft_elements "$monitoring_ips_csv")"

  start_spinner "Готовлю /etc/nftables.conf из repo nftables_example.conf"
  backup_file /etc/nftables.conf

  python3 - "$src" "$ssh_port" "$control_port" "$monitoring_port" "$node_api_port" "$control_elems" "$monitoring_elems" > /etc/nftables.conf <<'PY'
import sys, re

src = sys.argv[1]
SSH_PORT = sys.argv[2]
CONTROL_PORT = sys.argv[3]
MONITORING_PORT = sys.argv[4]
NODE_API_PORT = sys.argv[5]
CONTROL_ELEMS = sys.argv[6]
MONITOR_ELEMS = sys.argv[7]

with open(src, "r", encoding="utf-8") as f:
    lines = f.readlines()

def replace_define(line: str, name: str, value: str) -> str:
    pattern = re.compile(rf'^(\s*define\s+{re.escape(name)}\s*=\s*)\d+(\s*)$', re.IGNORECASE)
    m = pattern.match(line.rstrip("\n"))
    if not m:
        return line
    return f"{m.group(1)}{value}{m.group(2)}\n"

def is_forward_drop(line: str) -> bool:
    return re.match(r'^\s*drop\s+comment\s+"Drop forward"\s*;?\s*$', line.strip()) is not None

out = []
in_control_set = False
in_monitor_set = False

in_chain_forward = False
forward_depth = 0
forward_has_docker0_iif = False
forward_has_docker0_oif = False
forward_has_br_iif = False
forward_has_br_oif = False

in_chain_input = False
input_depth = 0
has_node_api_rule = False

has_define_node_api = any(re.match(r'^\s*define\s+NODE_API_PORT\s*=\s*\d+', ln.strip(), re.IGNORECASE) for ln in lines)
inserted_define_node_api = False

for line in lines:
    line2 = line
    line2 = replace_define(line2, "SSH_PORT", SSH_PORT)
    line2 = replace_define(line2, "CONTROL_PORT", CONTROL_PORT)
    line2 = replace_define(line2, "MONITORING_PORT", MONITORING_PORT)
    if has_define_node_api:
        line2 = replace_define(line2, "NODE_API_PORT", NODE_API_PORT)

    if not has_define_node_api and not inserted_define_node_api:
        if re.match(r'^\s*define\s+MONITORING_PORT\s*=\s*\d+', line2.strip(), re.IGNORECASE):
            out.append(line2)
            out.append(f"define NODE_API_PORT = {NODE_API_PORT}\n")
            inserted_define_node_api = True
            continue

    if re.match(r'^\s*set\s+control_plane_sources\s*\{', line2):
        in_control_set = True
        in_monitor_set = False
        out.append(line2)
        continue
    if re.match(r'^\s*set\s+monitoring_sources\s*\{', line2):
        in_monitor_set = True
        in_control_set = False
        out.append(line2)
        continue

    m_elems = re.match(r'^(\s*elements\s*=\s*\{\s*)(.*?)(\s*\}\s*;?\s*)$', line2.rstrip("\n"))
    if m_elems and in_control_set:
        out.append(f"{m_elems.group(1)}{CONTROL_ELEMS}{m_elems.group(3)}\n")
        continue
    if m_elems and in_monitor_set:
        out.append(f"{m_elems.group(1)}{MONITOR_ELEMS}{m_elems.group(3)}\n")
        continue

    if in_control_set and line2.strip().startswith("}"):
        in_control_set = False
    if in_monitor_set and line2.strip().startswith("}"):
        in_monitor_set = False

    if re.match(r'^\s*chain\s+forward\s*\{', line2):
        in_chain_forward = True
        forward_depth = 1
        out.append(line2)
        continue

    if in_chain_forward:
        forward_depth += line2.count("{")
        forward_depth -= line2.count("}")

        if 'iifname "docker0"' in line2:
            forward_has_docker0_iif = True
        if 'oifname "docker0"' in line2:
            forward_has_docker0_oif = True
        if 'iifname "br-"' in line2 or 'iifname "br-*" ' in line2 or 'iifname "br-*"'.strip() in line2:
            forward_has_br_iif = True
        if 'oifname "br-"' in line2 or 'oifname "br-*" ' in line2 or 'oifname "br-*"'.strip() in line2:
            forward_has_br_oif = True

        if is_forward_drop(line2):
            continue

        if line2.strip() == "}" and forward_depth == 0:
            if not forward_has_docker0_iif:
                out.append('        iifname "docker0" accept comment "Allow docker0 forward in"\n')
            if not forward_has_docker0_oif:
                out.append('        oifname "docker0" accept comment "Allow docker0 forward out"\n')
            if not forward_has_br_iif:
                out.append('        iifname "br-*" accept comment "Allow docker bridge forward in"\n')
            if not forward_has_br_oif:
                out.append('        oifname "br-*" accept comment "Allow docker bridge forward out"\n')
            out.append(line2)
            in_chain_forward = False
            continue

        out.append(line2)
        continue

    if re.match(r'^\s*chain\s+filter_input\s*\{', line2):
        in_chain_input = True
        input_depth = 1
        out.append(line2)
        continue

    if in_chain_input:
        input_depth += line2.count("{")
        input_depth -= line2.count("}")

        if re.search(r'\bRemnawave\b.*\bnode\b.*\bAPI\b', line2, re.IGNORECASE) or re.search(r'\bNODE_API_PORT\b', line2):
            has_node_api_rule = True

        if (not has_node_api_rule) and re.search(r'@control_plane_sources', line2) and re.search(r'\bdport\b', line2):
            out.append(line2)
            if has_define_node_api or inserted_define_node_api:
                out.append('        ip saddr @control_plane_sources tcp dport $NODE_API_PORT ct state new accept comment "Remnawave node API"\n')
            else:
                out.append(f'        ip saddr @control_plane_sources tcp dport {NODE_API_PORT} ct state new accept comment "Remnawave node API"\n')
            has_node_api_rule = True
            continue

        if line2.strip() == "}" and input_depth == 0:
            out.append(line2)
            in_chain_input = False
            continue

        out.append(line2)
        continue

    out.append(line2)

if (not has_define_node_api) and (not inserted_define_node_api):
    new_out = []
    inserted = False
    for ln in out:
        new_out.append(ln)
        if (not inserted) and re.match(r'^\s*define\s+SSH_PORT\s*=\s*\d+', ln.strip(), re.IGNORECASE):
            new_out.append(f"define NODE_API_PORT = {NODE_API_PORT}\n")
            inserted = True
    out = new_out

sys.stdout.write("".join(out))
PY

  stop_spinner_ok

  start_spinner "Проверка синтаксиса nftables"
  nft -c -f /etc/nftables.conf >/dev/null
  stop_spinner_ok

  start_spinner "Применение nftables + enable"
  nft -f /etc/nftables.conf >/dev/null
  systemctl enable nftables >/dev/null 2>&1 || true
  systemctl restart nftables >/dev/null 2>&1 || true
  stop_spinner_ok

  ok "nftables применён (repo-first). Разрешён NODE_API_PORT (${node_api_port}) только от control_plane_sources."
}

ensure_remnanode_paths() {
  [[ -d /opt/remnanode ]] || die "Не найден каталог /opt/remnanode"
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

  if grep -qE "^${key}=" "$file"; then
    sed -i -E "s|^${key}=.*|${key}=${val}|" "$file"
    return 0
  fi

  local last_line=""
  if [[ -s "$file" ]]; then
    last_line="$(tail -n 1 "$file" || true)"
  fi
  if [[ -n "$last_line" ]]; then printf "\n" >> "$file"; fi
  printf "%s=%s\n" "$key" "$val" >> "$file"
}

render_vector_toml_exact() {
  local domain="$1"
  local out="/opt/remnanode/vector.toml"
  local uri="https://${domain}:38213/"

  cat > "${out}" <<EOF
[sources.xray_access_logs]
  type = "file"
  include = ["/var/log/remnanode/access.log"]
  read_from = "end"

[transforms.parse_xray_log]
  type = "remap"
  inputs = ["xray_access_logs"]
  source = '''
    pattern = r'from (tcp:)?(?P<ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):\\d+.*? email: (?P<email>\\S+)'
    parsed, err = parse_regex(.message, pattern)
    if err != null { log("Parse failed: " + err, level: "warn"); abort }
    . = { "user_email": parsed.email, "source_ip": parsed.ip, "timestamp": to_string(now()) }
  '''

[sinks.central_observer_api]
  type = "http"
  inputs = ["parse_xray_log"]
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
  "logging": {"driver":"json-file","options":{"max-size":"8m","max-file":"5"}},
  "env_file": [".env"],
  "cap_add": ["NET_ADMIN","NET_RAW"],
  "depends_on": ["remnanode"],
  "deploy": {"resources":{"limits":{"memory":"64M","cpus":"0.25"},"reservations":{"memory":"32M","cpus":"0.10"}}}
}

vector = {
  "image": "timberio/vector:0.48.0-alpine",
  "container_name": "vector",
  "hostname": "vector",
  "restart": "unless-stopped",
  "network_mode": "host",
  "command": ["--config", "/etc/vector/vector.toml"],
  "depends_on": ["remnanode"],
  "volumes": ["./vector.toml:/etc/vector/vector.toml:ro","/var/log/remnanode:/var/log/remnanode:ro"],
  "logging": {"driver":"json-file","options":{"max-size":"8m","max-file":"3"}},
  "deploy": {"resources":{"limits":{"memory":"128M","cpus":"0.25"},"reservations":{"memory":"64M","cpus":"0.10"}}}
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
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
os.replace(tmp, compose_path)
print("CHANGED")
PY
}

compose_apply_safely() {
  local changed="$1"
  if [[ "${changed}" == "CHANGED" ]]; then
    start_spinner "docker compose down (только потому что compose изменён)"
    (cd /opt/remnanode && docker compose down --remove-orphans) >/dev/null 2>&1 || true
    stop_spinner_ok
    start_spinner "docker compose up -d"
    (cd /opt/remnanode && docker compose up -d) >/dev/null
    stop_spinner_ok
  else
    start_spinner "docker compose up -d (без down)"
    (cd /opt/remnanode && docker compose up -d) >/dev/null
    stop_spinner_ok
  fi
}

show_logs_and_status() {
  echo -e "${WT}${B0}docker compose ps:${R0}"
  (cd /opt/remnanode && docker compose ps) || true
  echo
  echo -e "${WT}${B0}Логи blocker-xray (tail 200):${R0}"
  docker logs --tail 200 blocker-xray 2>/dev/null || true
  echo
  echo -e "${WT}${B0}Логи vector (tail 200):${R0}"
  docker logs --tail 200 vector 2>/dev/null || true
}

main() {
  require_root
  clear || true
  echo -e "${CY}${B0}=== Observer Node Installer + nftables (VPS-hardening disabled) ===${R0}"
  echo

  # Оставляем только пакеты, нужные для observer/nft/docker-стека
  apt_install ca-certificates curl iproute2 coreutils nftables netcat-openbsd
  ensure_git_python_yaml
  ensure_docker

  # SSH_PORT теперь нужен только как значение define в nftables_example.conf (если там используется).
  # Никаких изменений sshd/порта скрипт НЕ ДЕЛАЕТ.
  read_with_default "SSH_PORT (только для nftables define, ssh НЕ трогаем):" "22" SSH_PORT
  validate_port "${SSH_PORT}" || die "SSH_PORT невалидный"

  read_with_default "CONTROL_PORT (порт ноды/контроль):" "4431" CONTROL_PORT
  validate_port "${CONTROL_PORT}" || die "CONTROL_PORT невалидный"

  read_with_default "MONITORING_PORT (обычно 9100):" "9100" MONITORING_PORT
  validate_port "${MONITORING_PORT}" || die "MONITORING_PORT невалидный"

  read_with_default "NODE_API_PORT (порт Remnawave node API):" "2041" NODE_API_PORT
  validate_port "${NODE_API_PORT}" || die "NODE_API_PORT невалидный"

  read_nonempty "IPv4 адрес(а) главного сервера (панель/Control plane) (можно несколько через запятую):" CONTROL_IPS 0
  read_nonempty "IPv4 адрес(а) monitoring (если нет отдельного — введи тот же) (можно несколько через запятую):" MONITOR_IPS 0

  # -------------------------------------------------------------------------
  # VPS HARDENING CALLS — ОТКЛЮЧЕНО
  # -------------------------------------------------------------------------
  # set_root_password
  # ensure_run_sshd_dir
  # ssh_hardening_port "${SSH_PORT}"
  # setup_fail2ban
  # setup_sysctl
  # disable_ufw
  # -------------------------------------------------------------------------

  clone_or_update_repo

  apply_nftables_from_repo_example \
    "${SSH_PORT}" \
    "${CONTROL_PORT}" \
    "${MONITORING_PORT}" \
    "${NODE_API_PORT}" \
    "${CONTROL_IPS}" \
    "${MONITOR_IPS}"

  echo
  echo -e "${MG}${B0}=== Установка Blocker + Vector на ноду ===${R0}"
  echo

  read_nonempty "Домен центрального Observer (пример: obs.example.com):" OBS_DOMAIN 0
  OBS_DOMAIN="$(echo "$OBS_DOMAIN" | sed -E 's#^https?://##; s#/.*$##')"
  [[ -n "$OBS_DOMAIN" ]] || die "Домен пустой"

  read_nonempty "RabbitMQ URL (пример: amqps://user:pass@${OBS_DOMAIN}:1234/):" RABBITMQ_URL 0
  [[ -n "$RABBITMQ_URL" ]] || die "RabbitMQ URL пустой"

  ensure_remnanode_paths

  upsert_env_kv_with_blank_before "/opt/remnanode/.env" "RABBITMQ_URL" "${RABBITMQ_URL}"
  ok "Обновлён /opt/remnanode/.env (RABBITMQ_URL)"

  render_vector_toml_exact "${OBS_DOMAIN}"

  start_spinner "Правлю /opt/remnanode/docker-compose.yml (blocker-xray + vector)"
  out="$(patch_compose_add_services)"
  stop_spinner_ok
  if [[ "${out:-}" == "NOCHANGE" ]]; then
    ok "docker-compose.yml уже содержит blocker-xray/vector"
  else
    ok "docker-compose.yml обновлён"
  fi

  compose_apply_safely "${out:-NOCHANGE}"

  echo
  ok "Готово"
  echo

  echo -e "${WT}${B0}Порты на хосте (для проверки):${R0}"
  ss -lntp | grep -E ":${NODE_API_PORT}\b|:80\b|:443\b|:${MONITORING_PORT}\b" || true
  echo

  echo -e "${WT}${B0}Проверка доступа к RabbitMQ:${R0}"
  host="$(echo "$RABBITMQ_URL" | sed -E 's#^[a-zA-Z0-9+.-]+://([^/@]+@)?([^/:]+).*$#\2#')"
  port="$(echo "$RABBITMQ_URL" | sed -nE 's#^[a-zA-Z0-9+.-]+://([^/@]+@)?([^/:]+):([0-9]+).*$#\3#p')"
  [[ -n "${port:-}" ]] || port="38214"
  nc -vz -w2 "$host" "$port" || true
  echo

  show_logs_and_status

  echo
  echo -e "${YL}${B0}ВАЖНО:${R0} nftables разрешает NODE_API_PORT=${NODE_API_PORT} только от CONTROL_IPS (${CONTROL_IPS})."
  echo -e "${YL}${B0}ВАЖНО:${R0} этот скрипт НЕ меняет SSH/пользователей/пароли/Fail2Ban/sysctl/UFW."
}

main "$@"
