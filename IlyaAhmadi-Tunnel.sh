#!/usr/bin/env bash
set -euo pipefail

APP="IlyaAhmadi"
TG="@ilyaahmadiii"

PY="/opt/ilyaahmadi/ilyaahmadi.py"
BASE="/etc/ilyaahmadi_manager"
CONF="$BASE/profiles"
MAX=10

need_root(){ [[ "$(id -u)" == "0" ]] || { echo "Run as root"; exit 1; }; }
pause(){ read -r -p "Press Enter to continue..." _ < /dev/tty || true; }

ensure(){
  mkdir -p "$CONF"
  command -v screen >/dev/null 2>&1 || (apt update -y && apt install -y screen) || true
  command -v python3 >/dev/null 2>&1 || (apt update -y && apt install -y python3) || true
  [[ -f "$PY" ]] || { echo "Missing python file: $PY"; exit 1; }
}

pick_role(){
  while true; do
    printf "1) EU\n2) IRAN\n" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    if [[ "$x" == "1" ]]; then
      echo "eu"
      return 0
    elif [[ "$x" == "2" ]]; then
      echo "iran"
      return 0
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
  while true; do
    printf "\nSelect %s slot (1..%d):\n" "$role" "$MAX" > /dev/tty
    printf "--------------------------------\n" > /dev/tty
    for i in $(seq 1 $MAX); do
      printf "  %d) %s%d  %s\n" "$i" "$role" "$i" "$(slot_status "$role" "$i")" > /dev/tty
    done
    printf "--------------------------------\n" > /dev/tty
    read -r -p "Slot number: " n < /dev/tty
    if [[ "$n" =~ ^[0-9]+$ ]] && (( n>=1 && n<=MAX )); then
      echo "${role}${n}"
      return 0
    fi
    echo "Invalid slot." > /dev/tty
  done
}

show_profile(){
  local prof="$1"
  local file="$CONF/${prof}.env"
  if [[ -f "$file" ]]; then
    cat "$file" > /dev/tty
  else
    echo "Empty slot." > /dev/tty
  fi
}

edit_profile(){
  local prof="$1"
  local file="$CONF/${prof}.env"
  local role="${prof//[0-9]/}"

  if [[ -f "$file" ]]; then
    echo "----- current -----" > /dev/tty
    cat "$file" > /dev/tty
    echo "-------------------" > /dev/tty
    read -r -p "Reuse as-is? (y/n) [y]: " a < /dev/tty
    [[ "${a,,}" != "n" ]] && return 0
  fi

  local IRAN_IP="" BRIDGE="" SYNC="" AUTO="" PORTS=""

  if [[ "$role" == "eu" ]]; then
    read -r -p "Iran IP: " IRAN_IP < /dev/tty
  fi

  read -r -p "Bridge port: " BRIDGE < /dev/tty
  read -r -p "Sync port: " SYNC < /dev/tty

  if [[ "$role" == "iran" ]]; then
    read -r -p "Auto-sync? (y/n) [y]: " AS < /dev/tty
    AS="${AS:-y}"
    if [[ "${AS,,}" == "y" ]]; then
      AUTO="y"
      PORTS=""
    else
      AUTO="n"
      read -r -p "Manual ports CSV (e.g. 80,443): " PORTS < /dev/tty
    fi
  fi

  cat >"$file" <<EOF
ROLE=$role
IRAN_IP=$IRAN_IP
BRIDGE=$BRIDGE
SYNC=$SYNC
AUTO=$AUTO
PORTS=$PORTS
EOF

  echo "[+] Saved: $file" > /dev/tty
}

session_name(){ echo "ilya_${1}"; }

run_slot(){
  local prof="$1"
  local file="$CONF/${prof}.env"
  [[ -f "$file" ]] || { echo "Empty slot. Create profile first." > /dev/tty; return 1; }
  # shellcheck disable=SC1090
  source "$file"

  local s; s="$(session_name "$prof")"
  screen -S "$s" -X quit >/dev/null 2>&1 || true

  if [[ "$ROLE" == "eu" ]]; then
    screen -dmS "$s" bash -lc "printf '1\n%s\n%s\n%s\n' '$IRAN_IP' '$BRIDGE' '$SYNC' | python3 '$PY'"
  else
    if [[ "${AUTO:-y}" == "y" ]]; then
      screen -dmS "$s" bash -lc "printf '2\n%s\n%s\ny\n' '$BRIDGE' '$SYNC' | python3 '$PY'"
    else
      screen -dmS "$s" bash -lc "printf '2\n%s\n%s\nn\n%s\n' '$BRIDGE' '$SYNC' '$PORTS' | python3 '$PY'"
    fi
  fi

  echo "[+] Started in screen: $s" > /dev/tty
}

stop_slot(){
  local prof="$1"
  local s; s="$(session_name "$prof")"
  screen -S "$s" -X quit >/dev/null 2>&1 || true
  echo "[+] Stopped: $s" > /dev/tty
}

logs_slot(){
  local prof="$1"
  local s; s="$(session_name "$prof")"
  screen -r "$s"
}

make_service(){
  local prof="$1"
  local svc="ilyaahmadi-${prof}.service"
  cat >/etc/systemd/system/"$svc" <<EOF
[Unit]
Description=$APP Manager Slot $prof | $TG
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/ilyaahmadi-manager.sh start $prof
ExecStop=/usr/local/bin/ilyaahmadi-manager.sh stop $prof
RemainAfterExit=yes
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$svc"
  echo "[+] Service enabled: $svc" > /dev/tty
}

remove_service(){
  local prof="$1"
  local svc="ilyaahmadi-${prof}.service"
  systemctl stop "$svc" >/dev/null 2>&1 || true
  systemctl disable "$svc" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/"$svc"
  systemctl daemon-reload
  echo "[+] Service removed: $svc" > /dev/tty
}

cron_enable(){
  local prof="$1"
  local svc="ilyaahmadi-${prof}.service"
  read -r -p "Interval minutes (e.g. 5): " m < /dev/tty
  [[ "$m" =~ ^[0-9]+$ ]] && (( m>=1 && m<=60 )) || { echo "Invalid" > /dev/tty; return 1; }
  local line="*/$m * * * * systemctl is-active --quiet $svc || systemctl restart $svc"
  (crontab -l 2>/dev/null | grep -v "systemctl is-active --quiet $svc" || true; echo "$line") | crontab -
  echo "[+] Cron watchdog added for $svc" > /dev/tty
}

cron_disable(){
  local prof="$1"
  local svc="ilyaahmadi-${prof}.service"
  (crontab -l 2>/dev/null | grep -v "systemctl is-active --quiet $svc" || true) | crontab -
  echo "[+] Cron watchdog removed for $svc" > /dev/tty
}

manage_menu(){
  local role prof
  role="$(pick_role)"
  prof="$(pick_slot "$role")"

  while true; do
    clear || true
    echo "=============================================="
    echo " Manage: $prof  |  $APP  |  $TG"
    echo "=============================================="
    echo "1) Show config"
    echo "2) Start (screen)"
    echo "3) Stop (screen)"
    echo "4) Restart (screen)"
    echo "5) Logs (attach screen)"
    echo "6) Re-enter settings"
    echo "7) Create/Enable systemd service"
    echo "8) Remove systemd service"
    echo "9) Enable cron watchdog"
    echo "10) Disable cron watchdog"
    echo "11) Back"
    echo "----------------------------------------------"
    read -r -p "Select: " c < /dev/tty
    case "$c" in
      1) show_profile "$prof"; pause ;;
      2) run_slot "$prof"; pause ;;
      3) stop_slot "$prof"; pause ;;
      4) stop_slot "$prof"; run_slot "$prof"; pause ;;
      5) logs_slot "$prof" ;;
      6) edit_profile "$prof"; pause ;;
      7) make_service "$prof"; pause ;;
      8) remove_service "$prof"; pause ;;
      9) cron_enable "$prof"; pause ;;
      10) cron_disable "$prof"; pause ;;
      11) return ;;
      *) echo "Invalid" > /dev/tty; sleep 1 ;;
    esac
  done
}

# CLI subcommands for systemd
cmd="${1:-}"
if [[ "$cmd" == "start" ]]; then
  need_root; ensure; run_slot "${2:?slot}"; exit 0
elif [[ "$cmd" == "stop" ]]; then
  need_root; ensure; stop_slot "${2:?slot}"; exit 0
fi

need_root
ensure

while true; do
  clear || true
  echo "=============================================="
  echo " $APP Tunnel Manager (Wrapper) | $TG"
  echo "=============================================="
  echo "1) Create/Update profile"
  echo "2) Start slot"
  echo "3) Stop slot"
  echo "4) Manage tunnel (menu)"
  echo "5) Exit"
  echo "----------------------------------------------"
  read -r -p "Select: " c < /dev/tty
  case "$c" in
    1) role="$(pick_role)"; prof="$(pick_slot "$role")"; edit_profile "$prof"; pause ;;
    2) role="$(pick_role)"; prof="$(pick_slot "$role")"; run_slot "$prof"; pause ;;
    3) role="$(pick_role)"; prof="$(pick_slot "$role")"; stop_slot "$prof"; pause ;;
    4) manage_menu ;;
    5) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
