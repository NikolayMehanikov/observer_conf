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

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Запусти от root: sudo -i"
}

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  local pkgs=("$@")
  start_spinner "Установка пакетов: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >/dev/null
  stop_spinner_ok
}

ensure_docker() {
  if ! cmd_exists docker; then
    warn "Docker не найден. Ставлю docker.io + compose plugin."
    apt_install ca-certificates curl gnupg lsb-release
    apt_install docker.io docker-compose-plugin
    systemctl enable --now docker >/dev/null 2>&1 || true
  else
    ok "Docker найден"
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

  if [[ -n "$last_line" ]]; then
    printf "\n" >> "$file"
  fi
  printf "%s=%s\n" "$key" "$val" >> "$file"
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
    raise SystemExit("В docker-compose.yml не найден сервис 'remnanode' (нужен для depends_on)")

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
  echo -e "${WT}${B0}Логи blocker-xray (последние 80 строк):${R0}"
  (cd /opt/remnanode && docker logs --tail 80 blocker-xray) || true
  echo
  echo -e "${WT}${B0}Логи vector (последние 80 строк):${R0}"
  (cd /opt/remnanode && docker logs --tail 80 vector) || true
}

main() {
  require_root

  echo -e "${CY}${B0}=== Установка Blocker + Vector на ноду ===${R0}"
  echo

  ensure_git_python_yaml
  ensure_docker

  read_nonempty "Домен Observer (пример: obsexp.core.com):" OBS_DOMAIN 0
  OBS_DOMAIN="$(normalize_domain "${OBS_DOMAIN}")"

  read_nonempty "RabbitMQ URL (пример: amqps://user:pass@${OBS_DOMAIN}:38214/):" RABBITMQ_URL 0

  clone_or_update_repo
  ensure_remnanode_paths

  upsert_env_kv_with_blank_before "/opt/remnanode/.env" "RABBITMQ_URL" "${RABBITMQ_URL}"
  ok "Обновлён /opt/remnanode/.env (RABBITMQ_URL добавлен с пустой строкой перед ним, если файл не пустой)"

  render_vector_toml_exact "${OBS_DOMAIN}"

  start_spinner "Правлю /opt/remnanode/docker-compose.yml (добавляю blocker-xray и vector)"
  out="$(patch_compose_add_services || true)"
  stop_spinner_ok
  if [[ "${out:-}" == "NOCHANGE" ]]; then
    ok "docker-compose.yml уже содержит blocker-xray/vector — пропускаю вставку"
  else
    ok "docker-compose.yml обновлён"
  fi

  compose_down_up

  ok "Готово"
  echo
  show_status
  echo
}

main "$@"
