#!/usr/bin/env bash
set -euo pipefail

APP="PAHLAVI"
VERSION="v1.0.1"
CONF="/etc/pahlavi_manager/profiles"
MAX=10

PY="/usr/local/bin/ilyaahmadi.py"   # مسیر فایل پایتون تونل
SCREEN_BIN="$(command -v screen || true)"
PY_BIN="$(command -v python3 || true)"

CLR_RESET=$'\033[0m'
CLR_GREEN=$'\033[32;1m'
CLR_RED=$'\033[31;1m'
CLR_CYAN=$'\033[36;1m'
CLR_GRAY=$'\033[90;1m'
CLR_BOLD=$'\033[1m'

die(){ echo "${CLR_RED}[-]${CLR_RESET} $*" > /dev/tty; exit 1; }
ok(){ echo "${CLR_GREEN}[+]${CLR_RESET} $*" > /dev/tty; }
info(){ echo "${CLR_CYAN}[*]${CLR_RESET} $*" > /dev/tty; }

need_bins(){
  [[ -n "$SCREEN_BIN" ]] || die "screen not found. Install: apt install -y screen"
  [[ -n "$PY_BIN" ]] || die "python3 not found. Install: apt install -y python3"
  [[ -f "$PY" ]] || die "Tunnel python not found at: $PY  (copy it there)"
}

mkdir -p "$CONF"

get_public_ip(){
  (curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)
}

header(){
  clear || true
  echo "${CLR_BOLD}${APP}${CLR_RESET}  ${CLR_GRAY}${VERSION}${CLR_RESET}"
  echo "${CLR_GRAY}----------------------------------------------${CLR_RESET}"
  local ip; ip="$(get_public_ip)"
  echo "Public IP: ${CLR_CYAN}${ip:-Unknown}${CLR_RESET}"
  echo "Roles: ${CLR_GREEN}IRAN = Server${CLR_RESET}  |  ${CLR_GREEN}EU = Client${CLR_RESET}"
  echo "${CLR_GRAY}----------------------------------------------${CLR_RESET}"
}

pause(){ read -r -p "Press Enter to continue..." _ < /dev/tty; }

session_name(){ echo "pahlavi_${1}"; }

is_running(){
  local prof="$1" s; s="$(session_name "$prof")"
  screen -ls 2>/dev/null | grep -qE "[[:space:]]+[0-9]+\.$s[[:space:]]"
}

require_var(){
  local name="$1" val="${2:-}"
  [[ -n "$val" ]] || die "Profile error: missing/empty ${name}"
}

show_profile(){
  local prof="$1" f="$CONF/${prof}.env"
  [[ -f "$f" ]] || die "Profile not found: $prof"
  echo "${CLR_GRAY}--- ${f} ---${CLR_RESET}" > /dev/tty
  cat "$f" > /dev/tty
}

edit_profile(){
  local prof="$1" f="$CONF/${prof}.env" role="${prof%%[0-9]*}"
  echo "" > /dev/tty
  info "Editing: ${CLR_BOLD}${prof}${CLR_RESET}"

  if [[ "$role" == "eu" ]]; then
    echo "${CLR_GRAY}EU role = Client (connects to IRAN server)${CLR_RESET}" > /dev/tty
    read -r -p "IRAN Server IP: " IRAN_IP < /dev/tty
    read -r -p "Bridge port (e.g. 8000): " BRIDGE < /dev/tty
    read -r -p "Sync port   (e.g. 8001): " SYNC < /dev/tty

    : "${IRAN_IP:=}"
    : "${BRIDGE:=}"
    : "${SYNC:=}"

    [[ "$BRIDGE" =~ ^[0-9]+$ ]] || die "BRIDGE must be a number"
    [[ "$SYNC"   =~ ^[0-9]+$ ]] || die "SYNC must be a number"

    cat >"$f" <<EOF
ROLE=eu
IRAN_IP=${IRAN_IP}
BRIDGE=${BRIDGE}
SYNC=${SYNC}
EOF

  else
    echo "${CLR_GRAY}IRAN role = Server (listens)${CLR_RESET}" > /dev/tty
    read -r -p "Bridge port (e.g. 8000): " BRIDGE < /dev/tty
    read -r -p "Sync port   (e.g. 8001): " SYNC < /dev/tty
    read -r -p "Auto-Sync ports from EU? (y/n): " AS < /dev/tty

    : "${BRIDGE:=}"
    : "${SYNC:=}"
    : "${AS:=n}"

    [[ "$BRIDGE" =~ ^[0-9]+$ ]] || die "BRIDGE must be a number"
    [[ "$SYNC"   =~ ^[0-9]+$ ]] || die "SYNC must be a number"

    if [[ "${AS,,}" == "y" ]]; then
      cat >"$f" <<EOF
ROLE=iran
BRIDGE=${BRIDGE}
SYNC=${SYNC}
AUTO_SYNC=true
PORTS=
EOF
    else
      read -r -p "Manual ports CSV (e.g. 80,443,2083): " PORTS < /dev/tty
      : "${PORTS:=}"
      cat >"$f" <<EOF
ROLE=iran
BRIDGE=${BRIDGE}
SYNC=${SYNC}
AUTO_SYNC=false
PORTS=${PORTS}
EOF
    fi
  fi

  ok "Saved: $f"
}

run_slot(){
  local prof="$1" f="$CONF/${prof}.env"
  [[ -f "$f" ]] || die "Profile not found: $prof"

  # امن برای set -u
  set +u
  # shellcheck disable=SC1090
  source "$f"
  set -u

  local role="${ROLE:-}"
  require_var "ROLE" "$role"

  local s; s="$(session_name "$prof")"
  screen -S "$s" -X quit >/dev/null 2>&1 || true

  if [[ "$role" == "eu" ]]; then
    # EU Client
    require_var "IRAN_IP" "${IRAN_IP:-}"
    require_var "BRIDGE"  "${BRIDGE:-}"
    require_var "SYNC"    "${SYNC:-}"

    local input
    input="$(printf "1\n%s\n%s\n%s\n" "${IRAN_IP}" "${BRIDGE}" "${SYNC}")"
    screen -dmS "$s" bash -lc "python3 '$PY' <<'__IN__'
${input}
__IN__"
    ok "Started: $s (EU Client)"

  elif [[ "$role" == "iran" ]]; then
    # IRAN Server
    require_var "BRIDGE" "${BRIDGE:-}"
    require_var "SYNC"   "${SYNC:-}"

    local auto="${AUTO_SYNC:-true}"
    local input

    if [[ "${auto}" == "true" ]]; then
      input="$(printf "2\n%s\n%s\ny\n" "${BRIDGE}" "${SYNC}")"
    else
      input="$(printf "2\n%s\n%s\nn\n%s\n" "${BRIDGE}" "${SYNC}" "${PORTS:-}")"
    fi

    screen -dmS "$s" bash -lc "python3 '$PY' <<'__IN__'
${input}
__IN__"
    ok "Started: $s (IRAN Server)"

  else
    die "Invalid ROLE in profile: ${role}"
  fi
}

stop_slot(){
  local prof="$1" s; s="$(session_name "$prof")"
  screen -S "$s" -X quit >/dev/null 2>&1 || true
  ok "Stopped: $s"
}

status_slot(){
  local prof="$1"
  local st="${CLR_RED}OFF${CLR_RESET}"
  if is_running "$prof"; then st="${CLR_GREEN}ON${CLR_RESET}"; fi
  echo -e "Profile: $prof | Running: $st" > /dev/tty
}

logs_slot(){
  local prof="$1" s; s="$(session_name "$prof")"
  info "Attach: $s (Ctrl+A then D)"
  screen -r "$s" || true
}

delete_slot(){
  local prof="$1" f="$CONF/${prof}.env"
  stop_slot "$prof" >/dev/null 2>&1 || true
  rm -f "$f" || true
  ok "Deleted: $f"
}

pick_role(){
  while true; do
    echo "1) EU (Client)" > /dev/tty
    echo "2) IRAN (Server)" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    [[ "$x" == "1" ]] && { echo "eu"; return; }
    [[ "$x" == "2" ]] && { echo "iran"; return; }
    echo "Invalid." > /dev/tty
  done
}

slot_status(){
  local role="$1" i="$2"
  [[ -f "$CONF/${role}${i}.env" ]] && echo "[saved]" || echo "(empty)"
}

pick_slot(){
  local role="$1"
  echo "" > /dev/tty
  echo "Select ${role} slot (1..${MAX}):" > /dev/tty
  echo "--------------------------------" > /dev/tty
  for i in $(seq 1 "$MAX"); do
    printf "  %s) %s%s %s\n" "$i" "$role" "$i" "$(slot_status "$role" "$i")" > /dev/tty
  done
  echo "--------------------------------" > /dev/tty
  read -r -p "Slot number: " slot < /dev/tty
  [[ "$slot" =~ ^[0-9]+$ ]] && [[ "$slot" -ge 1 ]] && [[ "$slot" -le "$MAX" ]] || die "Invalid slot"
  echo "${role}${slot}"
}

manage_menu(){
  local prof="$1"
  while true; do
    echo "" > /dev/tty
    echo "Manage: ${CLR_BOLD}${prof}${CLR_RESET}" > /dev/tty
    echo "1) Show profile" > /dev/tty
    echo "2) Start" > /dev/tty
    echo "3) Stop" > /dev/tty
    echo "4) Restart" > /dev/tty
    echo "5) Status" > /dev/tty
    echo "6) Logs" > /dev/tty
    echo "7) Delete profile" > /dev/tty
    echo "0) Back" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    case "$x" in
      1) show_profile "$prof"; pause ;;
      2) run_slot "$prof"; pause ;;
      3) stop_slot "$prof"; pause ;;
      4) stop_slot "$prof" >/dev/null 2>&1 || true; sleep 0.3; run_slot "$prof"; pause ;;
      5) status_slot "$prof"; pause ;;
      6) logs_slot "$prof" ;;
      7) delete_slot "$prof"; pause ;;
      0) return ;;
      *) echo "Invalid." > /dev/tty ;;
    esac
  done
}

main_menu(){
  need_bins
  while true; do
    header
    echo "1) Create/Update profile" > /dev/tty
    echo "2) Manage tunnel (select slot)" > /dev/tty
    echo "3) Status (all saved profiles)" > /dev/tty
    echo "0) Exit" > /dev/tty
    echo "${CLR_GRAY}----------------------------------------------${CLR_RESET}" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    case "$x" in
      1)
        role="$(pick_role)"
        prof="$(pick_slot "$role")"
        edit_profile "$prof"
        pause
      ;;
      2)
        role="$(pick_role)"
        prof="$(pick_slot "$role")"
        manage_menu "$prof"
      ;;
      3)
        echo "" > /dev/tty
        for role in eu iran; do
          for i in $(seq 1 "$MAX"); do
            prof="${role}${i}"
            [[ -f "$CONF/${prof}.env" ]] || continue
            status_slot "$prof"
          done
        done
        pause
      ;;
      0) exit 0 ;;
      *) echo "Invalid." > /dev/tty; sleep 0.4 ;;
    esac
  done
}

main_menu
