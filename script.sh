cat > /opt/remnawave-observer/blocker_conf/install_node.sh << 'EOFSCRIPT'
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

# ===== Observer install =====
ensure_remnanode_paths() {
  [[ -d /opt/remnanode ]] || die "Не найден каталог /opt/remnanode (должна быть установлена RemnaWave нода)"
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
  echo -e "${CY}${B0}=== Observer Vector Installer (только чтение логов Xray → передача в Observer) ===${R0}"
  echo

  # Base deps
  apt_install ca-certificates curl iproute2 coreutils netcat-openbsd
  ensure_git_python_yaml
  ensure_docker

  echo
  echo -e "${MG}${B0}=== Установка Vector для передачи логов Xray ===${R0}"
  echo

  local OBS_DOMAIN
  read_nonempty "Домен центрального Observer (пример: obs.example.com):" OBS_DOMAIN 0
  OBS_DOMAIN="$(echo "$OBS_DOMAIN" | sed -E 's#^https?://##; s#/.*$##')"
  [[ -n "$OBS_DOMAIN" ]] || die "Домен пустой"

  ensure_remnanode_paths

  render_vector_toml_exact "${OBS_DOMAIN}"

  start_spinner "Правлю /opt/remnanode/docker-compose.yml (добавляю vector)"
  local out
  out="$(patch_compose_add_services)"
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
}

main "$@"
EOFSCRIPT

chmod +x /opt/remnawave-observer/blocker_conf/install_node.sh
