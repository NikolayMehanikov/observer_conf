#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C

# ===== Pretty =====
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
warn(){ echo -e "${YL}${B0}⚠${R0} $*"; }
info(){ echo -e "${CY}${B0}➜${R0} $*"; }

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

# ===== Utils =====
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

read_yes_no_default_yes() {
  local prompt="$1"
  local ans=""
  while :; do
    read -r -p "$(echo -e "${B0}${prompt}${R0} ${D0}[Y/n]${R0} ")" ans || true
    ans="$(echo "${ans:-}" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    [[ -z "$ans" ]] && ans="y"
    case "$ans" in
      y|yes) echo "y"; return 0 ;;
      n|no)  echo "n"; return 0 ;;
      *) warn "Введи y или n." ;;
    esac
  done
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
  [[ -z "$value" ]] && value="$def"
  printf -v "${varname}" '%s' "${value}"
}

validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

# ===== Docker =====
ensure_docker() {
  if ! cmd_exists docker; then
    warn "Docker не найден. Ставлю docker.io + compose plugin."
    apt_install ca-certificates curl gnupg lsb-release docker.io docker-compose-plugin
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  docker info >/dev/null 2>&1 || die "Docker не запускается. Проверь: systemctl status docker"
  ok "Docker работает"
}

ensure_git_python_yaml() {
  local need=()
  cmd_exists git || need+=(git)
  cmd_exists python3 || need+=(python3)
  python3 -c "import yaml" >/dev/null 2>&1 || need+=(python3-yaml)
  ((${#need[@]})) && apt_install "${need[@]}" || ok "git/python3/yaml уже есть"
}

# ===== SSH change (safe) =====
detect_ssh_port() {
  if cmd_exists sshd; then
    local p=""
    p="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || true)"
    if [[ -n "${p:-}" ]] && validate_port "$p"; then
      echo "$p"
      return 0
    fi
  fi

  if cmd_exists ss; then
    local p2=""
    p2="$(ss -lntp 2>/dev/null | awk '
      /LISTEN/ && ($0 ~ /sshd|\/sshd/){
        match($0, /:([0-9]{1,5})[[:space:]]/, m);
        if (m[1]!=""){ print m[1]; exit }
      }' || true)"
    if [[ -n "${p2:-}" ]] && validate_port "$p2"; then
      echo "$p2"
      return 0
    fi
  fi

  local ports=()
  local f
  if [[ -f /etc/ssh/sshd_config ]]; then
    while read -r f; do
      [[ -f "$f" ]] || continue
      while read -r p; do
        [[ -n "$p" ]] || continue
        validate_port "$p" && ports+=("$p")
      done < <(awk 'BEGIN{IGNORECASE=1} $1=="port"{print $2}' "$f" 2>/dev/null || true)
    done < <(
      echo /etc/ssh/sshd_config
      ls -1 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
    )
  fi
  if ((${#ports[@]})); then
    echo "${ports[0]}"
    return 0
  fi

  echo "22"
}

detect_ssh_unit() {
  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then echo "ssh"; return 0; fi
  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then echo "sshd"; return 0; fi
  if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then echo "ssh"; return 0; fi
  if systemctl list-units --type=service --all --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then echo "sshd"; return 0; fi
  return 1
}

ensure_run_sshd_dir() {
  mkdir -p /run/sshd
  chmod 0755 /run/sshd
  chown root:root /run/sshd
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
  ensure_run_sshd_dir

  if systemctl list-unit-files --no-pager 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.socket'; then
    systemctl restart ssh.socket >/dev/null 2>&1 || true
  fi

  systemctl restart "${unit}" >/dev/null

  systemctl is-active --quiet "${unit}" || {
    echo -e "${RD}${B0}SSH unit не активен после рестарта.${R0}"
    journalctl -u "${unit}" -n 160 --no-pager || true
    die "SSH не поднялся после применения конфига"
  }

  cmd_exists ss || apt_install iproute2
  if ! ss -lntp 2>/dev/null | grep -qE "LISTEN.+:${new_port}\b"; then
    echo -e "${RD}${B0}sshd не слушает порт ${new_port}.${R0}"
    ss -lntp 2>/dev/null | grep -i ssh || ss -lntp 2>/dev/null || true
    journalctl -u "${unit}" -n 200 --no-pager || true
    die "Порт не применился / sshd не слушает новый порт"
  fi
}

ssh_change_port() {
  local new_port="$1"
  validate_port "$new_port" || die "Неверный порт SSH: $new_port"

  start_spinner "Настройка SSH (порт ${new_port})"

  local dropin_dir="/etc/ssh/sshd_config.d"
  local dropin_file="${dropin_dir}/99-custom.conf"

  mkdir -p "${dropin_dir}"
  ensure_sshd_include_dropins

  backup_file "${dropin_file}"
  cat > "${dropin_file}" <<EOF
# Managed by installer script
Port ${new_port}
PermitRootLogin yes
PasswordAuthentication yes
KbdInteractiveAuthentication yes
PubkeyAuthentication yes
PrintMotd no
Banner none
EOF

  comment_out_other_port_directives "${dropin_file}"
  ensure_run_sshd_dir

  if cmd_exists sshd && ! sshd -t >/dev/null 2>&1; then
    stop_spinner_fail
    sshd -t || true
    die "sshd_config невалиден после изменений. Проверь ${dropin_file}"
  fi

  local unit
  unit="$(detect_ssh_unit)" || { stop_spinner_fail; die "Не нашёл systemd unit ssh/sshd."; }

  restart_ssh_and_verify "${unit}" "${new_port}"

  stop_spinner_ok
  ok "SSH применён. Новый порт: ${new_port}"
  echo -e "${YL}${B0}ВАЖНО:${R0} проверь вход в новой сессии: ${B0}ssh -p ${new_port} root@<IP>${R0}"
}

# ===== Root password =====
generate_root_password() {
  python3 - <<'PY'
import secrets, string
alphabet = string.ascii_letters + string.digits
print(''.join(secrets.choice(alphabet) for _ in range(24)))
PY
}

set_root_password_generated() {
  local pass
  pass="$(generate_root_password)"
  echo "root:${pass}" | chpasswd
  ok "ROOT пароль установлен (сгенерирован)."
  echo -e "${YL}${B0}ROOT PASSWORD:${R0} ${B0}${pass}${R0}"
  echo -e "${D0}Сохрани пароль в безопасном месте.${R0}"
}

# ===== Fail2Ban =====
setup_fail2ban() {
  apt_install fail2ban
  start_spinner "Настройка Fail2Ban (sshd, maxretry=7)"
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
bantime = 30m
findtime = 10m
maxretry = 7
backend = systemd
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
  stop_spinner_ok
  ok "Fail2Ban активирован"
}

# ===== Observer Vector install =====
ensure_remnanode_paths() {
  [[ -d /opt/remnanode ]] || die "Не найден каталог /opt/remnanode (должна быть установлена RemnaWave нода)"
  [[ -f /opt/remnanode/docker-compose.yml ]] || die "Не найден /opt/remnanode/docker-compose.yml"

  mkdir -p /var/log/remnanode
  chown -R 1000:1000 /var/log/remnanode >/dev/null 2>&1 || true
  chmod 755 /var/log/remnanode >/dev/null 2>&1 || true
  ok "Логи remnanode: /var/log/remnanode"
}

render_vector_toml() {
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

patch_compose_add_vector() {
  python3 - <<'PY'
import sys, os, yaml

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

vector = {
  "image": "timberio/vector:0.48.0-alpine",
  "container_name": "vector",
  "hostname": "vector",
  "restart": "unless-stopped",
  "network_mode": "host",
  "command": ["--config", "/etc/vector/vector.toml"],
  "depends_on": ["remnanode"],
  "volumes": ["./vector.toml:/etc/vector/vector.toml:ro","/var/log/remnanode:/var/log/remnanode:ro"],
  "logging": {"driver":"json-file","options":{"max-size":"8m","max-file":"3"}}
}

changed = False
if "vector" not in services:
    services["vector"] = vector
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
  fi

  start_spinner "docker compose up -d"
  (cd /opt/remnanode && docker compose up -d) >/dev/null
  stop_spinner_ok
}

show_logs_and_status() {
  echo -e "${WT}${B0}docker compose ps:${R0}"
  (cd /opt/remnanode && docker compose ps) || true
  echo
  echo -e "${WT}${B0}Логи vector (tail 50):${R0}"
  docker logs --tail 50 vector 2>/dev/null || true
}

# ===== Main =====
main() {
  require_root
  clear || true
  echo -e "${CY}${B0}=== Observer Vector Installer (передача логов Xray → Observer) ===${R0}"
  echo

  local DO_VPS
  DO_VPS="$(read_yes_no_default_yes "Настраивать VPS (root пароль, SSH порт, Fail2Ban)?")"

  # Base deps
  apt_install ca-certificates curl iproute2 coreutils netcat-openbsd openssh-server
  ensure_git_python_yaml
  ensure_docker

  local SSH_PORT_CURRENT=""
  SSH_PORT_CURRENT="$(detect_ssh_port)"
  ok "Текущий SSH порт: ${SSH_PORT_CURRENT}"

  local SSH_PORT_NEW="$SSH_PORT_CURRENT"

  if [[ "$DO_VPS" == "y" ]]; then
    echo
    info "VPS настройка включена"

    local DO_ROOT_PASS
    DO_ROOT_PASS="$(read_yes_no_default_yes "Сменить пароль root (сгенерировать новый)?")"
    if [[ "$DO_ROOT_PASS" == "y" ]]; then
      set_root_password_generated
    else
      warn "Пароль root не меняю."
    fi

    read_nonempty "Новый SSH порт (например 5129):" SSH_PORT_NEW 0
    validate_port "${SSH_PORT_NEW}" || die "Порт SSH невалидный"

    ensure_run_sshd_dir
    ssh_change_port "${SSH_PORT_NEW}"

    setup_fail2ban
  else
    warn "VPS-настройка пропущена: root пароль / SSH порт / Fail2Ban не трогаю."
  fi

  echo
  echo -e "${MG}${B0}=== Установка Vector для передачи логов ===${R0}"
  echo

  local OBS_DOMAIN
  read_nonempty "Домен центрального Observer (пример: obs.example.com):" OBS_DOMAIN 0
  OBS_DOMAIN="$(echo "$OBS_DOMAIN" | sed -E 's#^https?://##; s#/.*$##')"
  [[ -n "$OBS_DOMAIN" ]] || die "Домен пустой"

  ensure_remnanode_paths

  render_vector_toml "${OBS_DOMAIN}"

  start_spinner "Правлю /opt/remnanode/docker-compose.yml (добавляю vector)"
  local out
  out="$(patch_compose_add_vector)"
  stop_spinner_ok

  if [[ "${out:-}" == "NOCHANGE" ]]; then
    ok "docker-compose.yml уже содержит vector"
  else
    ok "docker-compose.yml обновлён"
  fi

  compose_apply_safely "${out:-NOCHANGE}"

  echo
  ok "Готово"
  echo

  echo -e "${WT}${B0}Проверка доступа к Observer (порт 38213):${R0}"
  nc -vz -w2 "$OBS_DOMAIN" 38213 || warn "Не удалось подключиться к ${OBS_DOMAIN}:38213"
  echo

  show_logs_and_status

  echo
  echo -e "${GN}${B0}✅ Vector установлен и запущен!${R0}"
  echo -e "${CY}Логи передаются в Observer: https://${OBS_DOMAIN}:38213/${R0}"
  
  if [[ "$DO_VPS" == "y" ]]; then
    echo -e "${YL}${B0}ВАЖНО:${R0} проверь вход в новой сессии SSH: ${B0}ssh -p ${SSH_PORT_NEW} root@<IP>${R0}"
  fi
}

main "$@"
