#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="event-horizon"
APP_DIR="/opt/${SERVICE_NAME}"
ETC_DIR="/etc/${SERVICE_NAME}"
LOG_DIR="/var/log/${SERVICE_NAME}"
CONF_FILE="${ETC_DIR}/${SERVICE_NAME}.conf"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PY_FILE="${APP_DIR}/server.py"
SERVICE_USER="eventhorizon"
SERVER_PY_URL="https://raw.githubusercontent.com/jbswaff/event-horizon/main/server.py"

bold(){ printf "\033[1m%s\033[0m\n" "$*"; }
warn(){ printf "\n[WARNING] %s\n" "$*"; }
info(){ printf "[INFO] %s\n" "$*"; }
err(){ printf "\n[ERROR] %s\n\n" "$*"; }

need_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root. Example: curl ... | sudo bash"
    exit 1
  fi
}

# --- TTY handling for curl | bash installers ---
TTY_FD=3

open_tty(){
  if [[ -t 0 ]]; then
    return 0
  fi

  if [[ -r /dev/tty ]]; then
    exec {TTY_FD}</dev/tty
    return 0
  fi

  err "No interactive TTY available."
  err "Use: curl -fsSL <url> -o install.sh && sudo bash install.sh"
  exit 1
}

read_prompt(){
  local secret="no"
  if [[ "${1:-}" == "-s" ]]; then
    secret="yes"
    shift
  fi
  local prompt_text="$1"
  local __varname="$2"
  local __val=""

  if [[ -t 0 ]]; then
    if [[ "$secret" == "yes" ]]; then
      read -r -s -p "${prompt_text}" __val
      echo
    else
      read -r -p "${prompt_text}" __val
    fi
  else
    if [[ "$secret" == "yes" ]]; then
      read -r -s -u "${TTY_FD}" -p "${prompt_text}" __val
      echo
    else
      read -r -u "${TTY_FD}" -p "${prompt_text}" __val
    fi
  fi

  printf -v "${__varname}" "%s" "${__val}"
}

trim(){
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf "%s" "$s"
}

is_int(){
  [[ "${1}" =~ ^[0-9]+$ ]]
}

valid_port(){
  is_int "$1" && (( $1 >= 1 && $1 <= 65535 ))
}

valid_name(){
  [[ "${1}" =~ ^[A-Za-z0-9_-]+$ ]]
}

detect_ips(){
  local primary=""
  primary="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1 || true)"

  local all_ips=""
  all_ips="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | tr '\n' ' ' | sed 's/[[:space:]]\+$//' || true)"

  printf "%s\n" "${primary}|${all_ips}"
}

prompt(){
  local varname="$1"
  local text="$2"
  local default="${3:-}"
  local secret="${4:-no}"
  local val=""

  while true; do
    if [[ -n "$default" ]]; then
      if [[ "$secret" == "yes" ]]; then
        read_prompt -s "${text} [default hidden]: " val
        val="$(trim "$val")"
        [[ -z "$val" ]] && val="$default"
      else
        read_prompt "${text} [${default}]: " val
        val="$(trim "$val")"
        [[ -z "$val" ]] && val="$default"
      fi
    else
      if [[ "$secret" == "yes" ]]; then
        read_prompt -s "${text}: " val
        val="$(trim "$val")"
      else
        read_prompt "${text}: " val
        val="$(trim "$val")"
      fi
    fi

    if [[ -n "$val" ]]; then
      printf -v "$varname" "%s" "$val"
      return 0
    fi
  done
}

yesno(){
  local varname="$1"
  local text="$2"
  local default="${3:-y}"
  local ans=""

  while true; do
    read_prompt "${text} [y/n] (default ${default}): " ans
    ans="$(trim "$ans")"
    [[ -z "$ans" ]] && ans="$default"
    case "$ans" in
      y|Y) printf -v "$varname" "true"; return 0;;
      n|N) printf -v "$varname" "false"; return 0;;
      *) echo "Enter y or n.";;
    esac
  done
}

mask_pw(){
  local pw="$1"
  local n=${#pw}
  if (( n <= 0 )); then
    printf ""
  elif (( n <= 4 )); then
    printf "****"
  else
    printf "%s" "$(printf '%*s' "$n" '' | tr ' ' '*')"
  fi
}

install_packages(){
  info "Installing prerequisites (python3, curl, ca-certificates)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y python3 curl ca-certificates
}

create_user_and_dirs(){
  info "Creating service user and directories..."
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  fi

  mkdir -p "${APP_DIR}" "${ETC_DIR}" "${LOG_DIR}"
  chmod 0755 "${APP_DIR}"
  chmod 0755 "${ETC_DIR}"
  chmod 0755 "${LOG_DIR}"

  chown -R root:root "${APP_DIR}" "${ETC_DIR}"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
}

download_server_py(){
  info "Downloading server.py from: ${SERVER_PY_URL}"
  if [[ "${SERVER_PY_URL}" == *"<OWNER>"* || "${SERVER_PY_URL}" == *"<REPO>"* ]]; then
    err "SERVER_PY_URL is not set. Edit install.sh and set SERVER_PY_URL before publishing."
    exit 1
  fi
  curl -fsSL "${SERVER_PY_URL}" -o "${PY_FILE}"
  chmod 0755 "${PY_FILE}"
  chown root:root "${PY_FILE}"
}

write_unit(){
  info "Creating systemd unit: ${UNIT_FILE}"
  cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=Event Horizon (Pi-hole v6 disable button server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
Environment=EH_CONF=${CONF_FILE}
ExecStart=/usr/bin/python3 ${PY_FILE}
Restart=on-failure
RestartSec=2

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} ${ETC_DIR}
WorkingDirectory=${APP_DIR}

[Install]
WantedBy=multi-user.target
EOF

  chmod 0644 "${UNIT_FILE}"
}

write_config(){
  info "Writing config: ${CONF_FILE}"
  umask 077
  cat > "${CONF_FILE}" <<EOF
# Event Horizon configuration (Pi-hole v6 only)
# IMPORTANT: This project is NOT compatible with Pi-hole v5.
#
# Security note:
# This service listens on the network. You are responsible for firewalling it.
# It has no login and no TLS by design.

PORT=${PORT}
DISABLE_MINUTES=${DISABLE_MINUTES}
SHOW_LOG_LINK=${SHOW_LOG_LINK}

PIHOLE_COUNT=${PIHOLE_COUNT}
EOF

  local i
  for ((i=1; i<=PIHOLE_COUNT; i++)); do
    local nvar="PIHOLE_${i}_NAME"
    local uvar="PIHOLE_${i}_URL"
    local pvar="PIHOLE_${i}_APP_PASSWORD"
    cat >> "${CONF_FILE}" <<EOF
PIHOLE_${i}_NAME=${!nvar}
PIHOLE_${i}_URL=${!uvar}
PIHOLE_${i}_APP_PASSWORD=${!pvar}
EOF
  done

  chown root:root "${CONF_FILE}"
  chmod 0640 "${CONF_FILE}"
  chgrp "${SERVICE_USER}" "${CONF_FILE}"
}

api_test_one(){
  local baseurl="$1"
  local apppass="$2"

  # POST /api/auth -> sid + csrf
  local auth_json sid csrf
  auth_json="$(curl -fsS --max-time 6 \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${apppass}\"}" \
    "${baseurl}/api/auth" 2>/dev/null || true)"

  sid="$(printf "%s" "${auth_json}" | python3 -c 'import sys,json;
try:
  j=json.load(sys.stdin)
  print(j.get("session",{}).get("sid",""))
except Exception:
  print("")' 2>/dev/null || true)"

  csrf="$(printf "%s" "${auth_json}" | python3 -c 'import sys,json;
try:
  j=json.load(sys.stdin)
  print(j.get("session",{}).get("csrf",""))
except Exception:
  print("")' 2>/dev/null || true)"

  [[ -n "${sid}" && -n "${csrf}" ]] || return 1

  # GET /api/dns/blocking (v6 returns "enabled"/"disabled" and timer)
  local st_json blocking
  st_json="$(curl -fsS --max-time 6 \
    -H "X-FTL-SID: ${sid}" \
    -H "X-FTL-CSRF: ${csrf}" \
    "${baseurl}/api/dns/blocking" 2>/dev/null || true)"

  blocking="$(printf "%s" "${st_json}" | python3 -c 'import sys,json;
try:
  j=json.load(sys.stdin)
  b=j.get("blocking","")
  # v6 commonly returns "enabled" or "disabled"
  if isinstance(b,str) and b in ("enabled","disabled"):
    print(b)
  # allow boolean fallback just in case
  elif b is True:
    print("enabled")
  elif b is False:
    print("disabled")
  else:
    print("")
except Exception:
  print("")' 2>/dev/null || true)"

  [[ "${blocking}" == "enabled" || "${blocking}" == "disabled" ]]
}

show_failure_menu(){
  local -n __fail_idx_ref=$1

  warn "One or more Pi-hole API connectivity tests failed."
  echo
  bold "Current settings"
  echo "Install URL (local display): http://localhost:${PORT}"
  echo "Disable time:               ${DISABLE_MINUTES} minute(s)"
  echo "Show logs link:             ${SHOW_LOG_LINK}"
  echo

  local show_pw=false
  while true; do
    bold "Pi-holes (failed marked with FAIL)"
    local i
    for ((i=1; i<=PIHOLE_COUNT; i++)); do
      local nvar="PIHOLE_${i}_NAME"
      local uvar="PIHOLE_${i}_URL"
      local pvar="PIHOLE_${i}_APP_PASSWORD"

      local status="OK"
      local f
      for f in "${__fail_idx_ref[@]}"; do
        [[ "$f" == "$i" ]] && status="FAIL"
      done

      local pw_disp
      if $show_pw; then
        pw_disp="${!pvar}"
      else
        pw_disp="$(mask_pw "${!pvar}")"
      fi

      echo "  ${i}) [${status}] name=${!nvar} url=${!uvar} password=${pw_disp}"
    done

    echo
    echo "Options:"
    echo "  1) Edit inputs (re-run prompts)"
    echo "  2) Toggle show password ($( $show_pw && echo "ON" || echo "OFF" ))"
    echo "  3) Retry validation"
    echo "  4) Continue anyway (installer could not verify API connectivity)"
    echo "  5) Exit"
    echo

    local choice=""
    read_prompt "Choose [1-5]: " choice
    choice="$(trim "$choice")"
    case "$choice" in
      1) return 10;;
      2) $show_pw && show_pw=false || show_pw=true;;
      3) return 20;;
      4) warn "Continuing without validated API connectivity. Runtime may fail if a Pi-hole is offline or credentials are wrong."; return 0;;
      5) exit 1;;
      *) echo "Enter 1, 2, 3, 4, or 5.";;
    esac
  done
}

collect_settings(){
  local ipinfo primary all
  ipinfo="$(detect_ips)"
  primary="${ipinfo%%|*}"
  all="${ipinfo#*|}"

  bold "Event Horizon installer (Pi-hole v6 only)"
  echo
  warn "This installer does NOT support Pi-hole v5. If you are on v5, stop now."
  warn "This service has NO TLS and NO login. You MUST firewall it yourself."
  echo

  if [[ -n "${primary}" ]]; then
    info "Detected primary LAN IP: ${primary}"
  fi
  if [[ -n "${all}" ]]; then
    info "Detected LAN IPv4(s): ${all}"
  fi
  echo

  prompt PORT "Port to listen on" "8080" "no"
  while ! valid_port "${PORT}"; do
    err "Invalid port."
    prompt PORT "Port to listen on" "8080" "no"
  done

  prompt DISABLE_MINUTES "Disable time in MINUTES (installer converts to seconds)" "10" "no"
  while ! is_int "${DISABLE_MINUTES}" || (( DISABLE_MINUTES < 1 || DISABLE_MINUTES > 1440 )); do
    err "Enter an integer between 1 and 1440."
    prompt DISABLE_MINUTES "Disable time in MINUTES" "10" "no"
  done

  yesno SHOW_LOG_LINK "Show logs link on main page?" "y"

  prompt PIHOLE_COUNT "How many Pi-hole instances will you configure?" "2" "no"
  while ! is_int "${PIHOLE_COUNT}" || (( PIHOLE_COUNT < 1 || PIHOLE_COUNT > 10 )); do
    err "Enter an integer between 1 and 10."
    prompt PIHOLE_COUNT "How many Pi-hole instances will you configure?" "2" "no"
  done

  local i
  for ((i=1; i<=PIHOLE_COUNT; i++)); do
    local nm url pw port
    echo
    bold "Pi-hole #${i}"

    prompt nm "Friendly name (A-Z a-z 0-9 _ - only, no spaces)" "pihole${i}" "no"
    while ! valid_name "${nm}"; do
      err "Invalid friendly name. Use only A-Z a-z 0-9 _ - and no spaces."
      prompt nm "Friendly name" "pihole${i}" "no"
    done

    prompt url "Host/IP or hostname (no scheme). Example: 10.2.70.2 or pihole.local" "" "no"
    while [[ -z "${url}" ]]; do
      err "Host cannot be empty."
      prompt url "Host/IP or hostname" "" "no"
    done

    prompt port "Port for this Pi-hole" "80" "no"
    while ! valid_port "${port}"; do
      err "Invalid port."
      prompt port "Port for this Pi-hole" "80" "no"
    done

    local base="http://${url}:${port}"

    prompt pw "Pi-hole v6 application password (no re-entry)" "" "yes"

    local showpw="n"
    read_prompt "Show password for verification on-screen? [y/n] (default n): " showpw
    showpw="$(trim "$showpw")"
    [[ -z "$showpw" ]] && showpw="n"
    if [[ "$showpw" =~ ^[yY]$ ]]; then
      warn "Password shown: ${pw}"
    fi

    printf -v "PIHOLE_${i}_NAME" "%s" "${nm}"
    printf -v "PIHOLE_${i}_URL" "%s" "${base}"
    printf -v "PIHOLE_${i}_APP_PASSWORD" "%s" "${pw}"
  done

  echo
  bold "Summary"
  echo "Open (local display): http://localhost:${PORT}"
  if [[ -n "${primary}" ]]; then
    echo "Likely LAN URL:       http://${primary}:${PORT}"
  else
    echo "Likely LAN URL:       (LAN IP detection unavailable)"
  fi
  echo "Disable time:         ${DISABLE_MINUTES} minute(s)"
  echo "Show logs link:       ${SHOW_LOG_LINK}"
  echo "Pi-hole count:        ${PIHOLE_COUNT}"
  local j
  for ((j=1; j<=PIHOLE_COUNT; j++)); do
    local nvar="PIHOLE_${j}_NAME"
    local uvar="PIHOLE_${j}_URL"
    echo "  - ${!nvar}: ${!uvar}"
  done
  echo
}

run_api_tests(){
  info "Validating Pi-hole API connectivity..."
  local failures=()
  local i
  for ((i=1; i<=PIHOLE_COUNT; i++)); do
    local nvar="PIHOLE_${i}_NAME"
    local uvar="PIHOLE_${i}_URL"
    local pvar="PIHOLE_${i}_APP_PASSWORD"

    if api_test_one "${!uvar}" "${!pvar}"; then
      info "OK:   ${!nvar}"
    else
      warn "FAIL: ${!nvar} (${!uvar})"
      failures+=("$i")
    fi
  done

  if [[ "${#failures[@]}" -eq 0 ]]; then
    return 0
  fi

  show_failure_menu failures
  return $?
}

main(){
  need_root
  open_tty
  install_packages

  while true; do
    collect_settings

    run_api_tests
    rc=$?

    if [[ "${rc}" -eq 0 ]]; then
      break
    elif [[ "${rc}" -eq 10 ]]; then
      continue
    elif [[ "${rc}" -eq 20 ]]; then
      run_api_tests
      rc2=$?
      [[ "${rc2}" -eq 0 ]] && break
      continue
    else
      break
    fi
  done

  create_user_and_dirs
  download_server_py
  write_unit
  write_config

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}.service"

  local ipinfo primary
  ipinfo="$(detect_ips)"
  primary="${ipinfo%%|*}"

  echo
  bold "Install complete."
  echo "Service: ${SERVICE_NAME}.service"
  echo "Open (local display): http://localhost:${PORT}"
  if [[ -n "${primary}" ]]; then
    echo "LAN URL (detected):   http://${primary}:${PORT}"
  else
    echo "LAN URL (detected):   (LAN IP detection unavailable)"
  fi
  echo
  warn "Security reminder: This service is reachable on your network. You MUST restrict access via firewall/VLAN controls."
  echo
  info "Check status: systemctl status ${SERVICE_NAME}.service --no-pager"
  info "View logs:    journalctl -u ${SERVICE_NAME}.service -n 200 --no-pager"
  info "Requests log: ${LOG_DIR}/requests.log"
  echo
  warn "Pi-hole v6-only reminder: This will not work with Pi-hole v5."
}

main "$@"
