#!/usr/bin/env bash
set -euo pipefail

APP="IlyaAhmadi"
TG="@ilyaahmadiii"

PY="/opt/ilyaahmadi/ilyaahmadi.py"
PY_URL="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main/ilyaahmadi.py"

SELF_URL="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main/IlyaAhmadi-tunnel.sh"
INSTALL_PATH="/usr/local/bin/ilya-tunnel"

BASE="/etc/ilyaahmadi_manager"
CONF="$BASE/profiles"
MAX=10

HC_SCRIPT="/usr/local/bin/ilya-health-check"
HC_CRON_TAG="# IlyaAhmadiTunnelHealthCheck"

need_root(){ [[ "$(id -u)" == "0" ]] || { echo "Run as root (sudo -i)"; exit 1; }; }
pause(){ read -r -p "Press Enter to continue..." _ < /dev/tty || true; }

fetch_url_to(){
  local url="$1"
  local out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  else
    command -v wget >/dev/null 2>&1 || (apt update -y && apt install -y wget) || true
    wget -qO "$out" "$url"
  fi
}

ensure(){
  mkdir -p "$CONF"
  mkdir -p "$(dirname "$PY")"

  command -v screen >/dev/null 2>&1 || (apt update -y && apt install -y screen) || true
  command -v python3 >/dev/null 2>&1 || (apt update -y && apt install -y python3) || true

  if [[ ! -f "$PY" ]]; then
    echo "[*] Python core not found. Downloading: $PY_URL" > /dev/tty
    fetch_url_to "$PY_URL" "$PY"
    chmod +x "$PY" || true
  fi

  [[ -f "$PY" ]] || { echo "Missing python file: $PY"; exit 1; }
}

install_script(){
  echo "[*] Installing script to: $INSTALL_PATH" > /dev/tty
  mkdir -p "$(dirname "$INSTALL_PATH")"

  if [[ -f "$0" ]] && [[ "$0" != "bash" ]] && [[ "$0" != "/dev/fd/"* ]]; then
    cp -f "$0" "$INSTALL_PATH"
  else
    fetch_url_to "$SELF_URL" "$INSTALL_PATH"
  fi

  chmod +x "$INSTALL_PATH"
  echo "[+] Installed. Run: sudo ilya-tunnel" > /dev/tty
}

update_script(){
  echo "[*] Updating script from: $SELF_URL" > /dev/tty
  local tmp
  tmp="$(mktemp)"
  fetch_url_to "$SELF_URL" "$tmp"

  if ! head -n 1 "$tmp" | grep -q "bash"; then
    echo "[-] Update failed: invalid file downloaded." > /dev/tty
    rm -f "$tmp"
    return 1
  fi

  chmod +x "$tmp"
  mv -f "$tmp" "$INSTALL_PATH"
  chmod +x "$INSTALL_PATH"

  echo "[+] Updated. Run again: sudo ilya-tunnel" > /dev/tty
}

disable_cron_healthcheck(){
  local tmp
  tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | grep -vF "${HC_CRON_TAG}" >"$tmp" || true
  crontab "$tmp" || true
  rm -f "$tmp"
  echo "[+] Cron disabled." > /dev/tty
}

uninstall_script(){
  disable_cron_healthcheck >/dev/null 2>&1 || true
  rm -f "$HC_SCRIPT" >/dev/null 2>&1 || true
  rm -f "$INSTALL_PATH" >/dev/null 2>&1 || true
  echo "[+] Uninstalled: $INSTALL_PATH" > /dev/tty
}

pick_role(){
  while true; do
    printf "1) EU\n2) IRAN\n" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    if [[ "$x" == "1" ]]; then echo "eu"; return 0; fi
    if [[ "$x" == "2" ]]; then echo "iran"; return 0; fi
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

session_name(){ echo "ilya_$1"; }

is_running(){
  local prof="$1"
  local s; s="$(session_name "$prof")"
  screen -ls 2>/dev/null | grep -q "\.${s}[[:space:]]"
}

run_slot(){
  local prof="$1"
  local f="$CONF/${prof}.env"
  [[ -f "$f" ]] || { echo "Profile not found: $prof" > /dev/tty; return 1; }
  # shellcheck disable=SC1090
  source "$f"

  local s; s="$(session_name "$prof")"
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
  local s; s="$(session_name "$prof")"
  screen -S "$s" -X quit >/dev/null 2>&1 || true
  echo "[+] Stopped: $s" > /dev/tty
}

restart_slot(){
  local prof="$1"
  stop_slot "$prof" >/dev/null 2>&1 || true
  sleep 0.5
  run_slot "$prof"
}

status_slot(){
  local prof="$1"
  local f="$CONF/${prof}.env"
  if [[ ! -f "$f" ]]; then
    echo "Profile not found: $prof" > /dev/tty
    return 1
  fi
  # shellcheck disable=SC1090
  source "$f"
  local s; s="$(session_name "$prof")"
  local st="OFF"
  if is_running "$prof"; then st="ON"; fi

  echo "--------------------------------" > /dev/tty
  echo "Profile: $prof" > /dev/tty
  echo "Session: $s" > /dev/tty
  echo "Running: $st" > /dev/tty
  echo "ROLE=$ROLE BRIDGE=$BRIDGE SYNC=$SYNC" > /dev/tty
  if [[ "${ROLE}" == "eu" ]]; then
    echo "IRAN_IP=$IRAN_IP" > /dev/tty
  else
    echo "AUTO_SYNC=${AUTO_SYNC:-true} PORTS=${PORTS:-}" > /dev/tty
  fi
  echo "--------------------------------" > /dev/tty
}

delete_slot(){
  local prof="$1"
  local f="$CONF/${prof}.env"
  stop_slot "$prof" >/dev/null 2>&1 || true
  if [[ -f "$f" ]]; then
    rm -f "$f"
    echo "[+] Deleted profile: $f" > /dev/tty
  else
    echo "[-] Profile not found: $f" > /dev/tty
  fi
}

logs_slot(){
  local prof="$1"
  local s; s="$(session_name "$prof")"
  echo "[i] Attaching to screen: $s (Ctrl+A then D to detach)" > /dev/tty
  screen -r "$s" || true
}

install_healthcheck_script(){
  cat >"$HC_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail

PY="${PY}"
CONF="${CONF}"
MAX="${MAX}"

session_name(){ echo "ilya_\$1"; }

is_running(){
  local prof="\$1"
  local s; s="\$(session_name "\$prof")"
  screen -ls 2>/dev/null | grep -q "\\.\${s}[[:space:]]"
}

start_from_profile(){
  local prof="\$1"
  local f="\${CONF}/\${prof}.env"
  [[ -f "\$f" ]] || return 0
  # shellcheck disable=SC1090
  source "\$f"
  local s; s="\$(session_name "\$prof")"
  screen -S "\$s" -X quit >/dev/null 2>&1 || true

  if [[ "\${ROLE}" == "eu" ]]; then
    screen -dmS "\$s" bash -lc "printf '1\\n%s\\n%s\\n%s\\n' '\${IRAN_IP}' '\${BRIDGE}' '\${SYNC}' | python3 '\${PY}'"
  else
    if [[ "\${AUTO_SYNC:-true}" == "true" ]]; then
      screen -dmS "\$s" bash -lc "printf '2\\n%s\\n%s\\ny\\n' '\${BRIDGE}' '\${SYNC}' | python3 '\${PY}'"
    else
      screen -dmS "\$s" bash -lc "printf '2\\n%s\\n%s\\nn\\n%s\\n' '\${BRIDGE}' '\${SYNC}' '\${PORTS:-}' | python3 '\${PY}'"
    fi
  fi
}

[[ -f "\$PY" ]] || exit 0

for role in eu iran; do
  for i in \$(seq 1 "\$MAX"); do
    prof="\${role}\${i}"
    f="\${CONF}/\${prof}.env"
    [[ -f "\$f" ]] || continue
    if ! is_running "\$prof"; then
      start_from_profile "\$prof" >/dev/null 2>&1 || true
    fi
  done
done
EOF
  chmod +x "$HC_SCRIPT"
}

enable_cron_healthcheck(){
  install_healthcheck_script
  local line="* * * * * ${HC_SCRIPT} >/dev/null 2>&1 ${HC_CRON_TAG}"
  local tmp
  tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | grep -vF "${HC_CRON_TAG}" >"$tmp" || true
  echo "$line" >>"$tmp"
  crontab "$tmp"
  rm -f "$tmp"
  echo "[+] Cron enabled (every 1 minute)." > /dev/tty
}

manage_menu(){
  while true; do
    echo "" > /dev/tty
    echo "1) Show profile"
    echo "2) Start (screen)"
    echo "3) Stop (screen)"
    echo "4) Restart (screen)"
    echo "5) Status"
    echo "6) Logs (attach screen)"
    echo "7) Delete slot (stop + delete profile)"
    echo "8) Enable cron health-check"
    echo "9) Disable cron health-check"
    echo "10) Back"
    read -r -p "Select: " c < /dev/tty
    case "$c" in
      1) role="$(pick_role)"; prof="$(pick_slot "$role")"; cat "$CONF/${prof}.env" > /dev/tty; pause ;;
      2) role="$(pick_role)"; prof="$(pick_slot "$role")"; run_slot "$prof"; pause ;;
      3) role="$(pick_role)"; prof="$(pick_slot "$role")"; stop_slot "$prof"; pause ;;
      4) role="$(pick_role)"; prof="$(pick_slot "$role")"; restart_slot "$prof"; pause ;;
      5) role="$(pick_role)"; prof="$(pick_slot "$role")"; status_slot "$prof"; pause ;;
      6) role="$(pick_role)"; prof="$(pick_slot "$role")"; logs_slot "$prof" ;;
      7) role="$(pick_role)"; prof="$(pick_slot "$role")"; delete_slot "$prof"; pause ;;
      8) enable_cron_healthcheck; pause ;;
      9) disable_cron_healthcheck; pause ;;
      10) return ;;
      *) echo "Invalid." > /dev/tty ;;
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
  echo "2) Manage tunnel"
  echo "3) Install script (system-wide)"
  echo "4) Update script (self-update)"
  echo "5) Uninstall script"
  echo "6) Exit"
  echo "----------------------------------------------"
  read -r -p "Select: " c < /dev/tty
  case "$c" in
    1) role="$(pick_role)"; prof="$(pick_slot "$role")"; edit_profile "$prof"; pause ;;
    2) manage_menu ;;
    3) install_script; pause ;;
    4) update_script; pause ;;
    5) uninstall_script; pause ;;
    6) exit 0 ;;
    *) echo "Invalid."; sleep 1 ;;
  esac
done
