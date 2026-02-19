#!/usr/bin/env bash
set -euo pipefail

APP="IlyaAhmadi"
TG="@ilyaahmadiii"

PY="/opt/ilyaahmadi/ilyaahmadi.py"
PY_URL="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main/ilyaahmadi.py"

BASE="/etc/ilyaahmadi_manager"
CONF="$BASE/profiles"
MAX=10

need_root(){ [[ "$(id -u)" == "0" ]] || { echo "Run as root"; exit 1; }; }
pause(){ read -r -p "Press Enter to continue..." _ < /dev/tty || true; }

ensure(){
  mkdir -p "$CONF"
  mkdir -p "$(dirname "$PY")"

  command -v screen >/dev/null 2>&1 || (apt update -y && apt install -y screen) || true
  command -v python3 >/dev/null 2>&1 || (apt update -y && apt install -y python3) || true

  if [[ ! -f "$PY" ]]; then
    echo "[*] Python core not found. Downloading: $PY_URL"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$PY_URL" -o "$PY"
    else
      apt update -y && apt install -y wget >/dev/null 2>&1 || true
      wget -qO "$PY" "$PY_URL"
    fi
    chmod +x "$PY"
  fi

  [[ -f "$PY" ]] || { echo "Missing python file: $PY"; exit 1; }
}

# ----------------- (بقیه فایل شما بدون تغییر) -----------------
pick_role(){
  while true; do
    printf "1) EU\n2) IRAN\n" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    if [[ "$x" == "1" ]]; then echo "eu"; return 0
    elif [[ "$x" == "2" ]]; then echo "iran"; return 0
    fi
    echo "Invalid." > /dev/tty
  done
}

slot_status(){
  local role="$1" i="$2"
  local f="$CONF/${role}${i}.env"
  [[ -f "$f" ]] && echo "[saved]" || echo "(empty)"
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
  [[ "$slot" =~ ^[0-9]+$ ]] && [[ "$slot" -ge 1 ]] && [[ "$slot" -le "$MAX" ]] || { echo "Invalid"; exit 1; }
  echo "${role}${slot}"
}

edit_profile(){
  local prof="$1"
  local f="$CONF/${prof}.env"
  local role="${prof%%[0-9]*}"
  echo "" > /dev/tty
  echo "Editing: $prof" > /dev/tty

  if [[ "$role" == "eu" ]]; then
    read -r -p "Iran IP: " IRAN_IP < /dev/tty
    read -r -p "Bridge port (e.g. 7000): " BRIDGE < /dev/tty
    read -r -p "Sync port   (e.g. 7001): " SYNC < /dev/tty
    cat >"$f" <<EOF
ROLE=eu
IRAN_IP=$IRAN_IP
BRIDGE=$BRIDGE
SYNC=$SYNC
EOF
  else
    read -r -p "Bridge port (e.g. 7000): " BRIDGE < /dev/tty
    read -r -p "Sync port   (e.g. 7001): " SYNC < /dev/tty
    read -r -p "Auto-Sync ports from EU? (y/n): " AS < /dev/tty
    if [[ "${AS,,}" == "y" ]]; then
      cat >"$f" <<EOF
ROLE=iran
BRIDGE=$BRIDGE
SYNC=$SYNC
AUTO_SYNC=true
PORTS=
EOF
    else
      read -r -p "Manual ports CSV (e.g. 80,443,2083): " PORTS < /dev/tty
      cat >"$f" <<EOF
ROLE=iran
BRIDGE=$BRIDGE
SYNC=$SYNC
AUTO_SYNC=false
PORTS=$PORTS
EOF
    fi
  fi

  echo "[+] Saved $f" > /dev/tty
}

run_slot(){
  local prof="$1"
  local f="$CONF/${prof}.env"
  [[ -f "$f" ]] || { echo "Profile not found: $prof" > /dev/tty; return 1; }
  # shellcheck disable=SC1090
  source "$f"

  local s="ilya_${prof}"
  screen -S "$s" -X quit >/dev/null 2>&1 || true

  if [[ "$ROLE" == "eu" ]]; then
    screen -dmS "$s" bash -lc "printf '1\n%s\n%s\n%s\n' '$IRAN_IP' '$BRIDGE' '$SYNC' | python3 '$PY'"
  else
    if [[ "${AUTO_SYNC:-true}" == "true" ]]; then
      screen -dmS "$s" bash -lc "printf '2\n%s\n%s\ny\n' '$BRIDGE' '$SYNC' | python3 '$PY'"
    else
      screen -dmS "$s" bash -lc "printf '2\n%s\n%s\nn\n%s\n' '$BRIDGE' '$SYNC' '${PORTS:-}' | python3 '$PY'"
    fi
  fi

  echo "[+] Started in screen session: $s" > /dev/tty
}

stop_slot(){
  local prof="$1"
  local s="ilya_${prof}"
  screen -S "$s" -X quit >/dev/null 2>&1 || true
  echo "[+] Stopped: $s" > /dev/tty
}

logs_slot(){
  local prof="$1"
  local s="ilya_${prof}"
  echo "[i] Attaching to screen: $s (Ctrl+A then D to detach)" > /dev/tty
  screen -r "$s" || true
}

manage_menu(){
  while true; do
    echo "" > /dev/tty
    echo "1) Show profile" > /dev/tty
    echo "2) Start (screen)" > /dev/tty
    echo "3) Stop (screen)" > /dev/tty
    echo "4) Logs (attach screen)" > /dev/tty
    echo "5) Back" > /dev/tty
    read -r -p "Select: " c < /dev/tty
    case "$c" in
      1) role="$(pick_role)"; prof="$(pick_slot "$role")"; cat "$CONF/${prof}.env" > /dev/tty; pause ;;
      2) role="$(pick_role)"; prof="$(pick_slot "$role")"; run_slot "$prof"; pause ;;
      3) role="$(pick_role)"; prof="$(pick_slot "$role")"; stop_slot "$prof"; pause ;;
      4) role="$(pick_role)"; prof="$(pick_slot "$role")"; logs_slot "$prof" ;;
      5) return ;;
      *) echo "Invalid" > /dev/tty ;;
    esac
  done
}

need_root
ensure

while true; do
  clear || true
  echo "=============================================="
  echo " $APP Tunnel Manager | $TG"
  echo "=============================================="
  echo "1) Create/Update profile"
  echo "2) Start slot"
  echo "3) Stop slot"
  echo "4) Logs slot"
  echo "5) Exit"
  echo "----------------------------------------------"
  read -r -p "Select: " c < /dev/tty
  case "$c" in
    1) role="$(pick_role)"; prof="$(pick_slot "$role")"; edit_profile "$prof"; pause ;;
    2) role="$(pick_role)"; prof="$(pick_slot "$role")"; run_slot "$prof"; pause ;;
    3) role="$(pick_role)"; prof="$(pick_slot "$role")"; stop_slot "$prof"; pause ;;
    4) role="$(pick_role)"; prof="$(pick_slot "$role")"; logs_slot "$prof" ;;
    5) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
