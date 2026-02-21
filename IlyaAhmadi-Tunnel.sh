#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Pahlavi"
TG_ID="@ilyaahmadiii"
VERSION="1.0.0"

GITHUB_REPO="github.com/Zehnovik/ilyaahmadi-tunnel"

# MUST match GitHub file name exactly:
SCRIPT_FILENAME="IlyaAhmadi-Tunnel.sh"
SELF_URL="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main/${SCRIPT_FILENAME}"

PY="/opt/pahlavi/ilyaahmadi.py"
PY_URL="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main/ilyaahmadi.py"

INSTALL_PATH="/usr/local/bin/pahlavi-tunnel"

BASE="/etc/pahlavi_manager"
CONF="$BASE/profiles"
MAX=10

HC_SCRIPT="/usr/local/bin/pahlavi-health-check"
HC_CRON_TAG="# PahlaviTunnelHealthCheck"

# Colors
if [[ -t 1 ]]; then
  CLR_RESET="\033[0m"; CLR_DIM="\033[2m"; CLR_BOLD="\033[1m"
  CLR_RED="\033[31m"; CLR_GREEN="\033[32m"; CLR_YELLOW="\033[33m"
  CLR_CYAN="\033[36m"; CLR_WHITE="\033[97m"
else
  CLR_RESET=""; CLR_DIM=""; CLR_BOLD=""
  CLR_RED=""; CLR_GREEN=""; CLR_YELLOW=""
  CLR_CYAN=""; CLR_WHITE=""
fi

need_root(){ [[ "$(id -u)" == "0" ]] || { echo "Run as root (sudo -i)"; exit 1; }; }
pause(){ read -r -p "Press Enter to continue..." _ < /dev/tty || true; }
have(){ command -v "$1" >/dev/null 2>&1; }

apt_try_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y "$@" >/dev/null 2>&1 || true
}

fetch_url_to(){
  local url="$1" out="$2"
  if have curl; then
    curl -fsSL "$url" -o "$out"
  else
    have wget || apt_try_install wget
    wget -qO "$out" "$url"
  fi
}

is_installed(){ [[ -x "$INSTALL_PATH" ]]; }

ensure(){
  mkdir -p "$CONF"
  mkdir -p "$(dirname "$PY")"
  have screen  || apt_try_install screen
  have python3 || apt_try_install python3
  have curl    || apt_try_install curl
  have figlet  || apt_try_install figlet
  have iptables || apt_try_install iptables
  have nft    || apt_try_install nftables
  have haproxy || apt_try_install haproxy
  have socat  || apt_try_install socat
  have ss      || apt_try_install iproute2
  have crontab || apt_try_install cron

  if [[ ! -f "$PY" ]]; then
    echo "[*] Python core not found. Downloading: $PY_URL" > /dev/tty
    fetch_url_to "$PY_URL" "$PY"
    chmod +x "$PY" || true
  fi
  [[ -f "$PY" ]] || { echo "Missing python file: $PY"; exit 1; }
}

install_script(){
  echo "[*] Installing to: $INSTALL_PATH" > /dev/tty
  mkdir -p "$(dirname "$INSTALL_PATH")"

  # If executed from a file path, copy it. Otherwise download from SELF_URL.
  if [[ -f "$0" ]] && [[ "$0" != "bash" ]] && [[ "$0" != "/dev/fd/"* ]]; then
    cp -f "$0" "$INSTALL_PATH"
  else
    fetch_url_to "$SELF_URL" "$INSTALL_PATH"
  fi
  chmod +x "$INSTALL_PATH"
  echo "[+] Installed. Run: sudo pahlavi-tunnel" > /dev/tty
}

update_script(){
  echo "[*] Updating from: $SELF_URL" > /dev/tty
  local tmp; tmp="$(mktemp)"
  fetch_url_to "$SELF_URL" "$tmp"

  if ! head -n 1 "$tmp" | grep -q "bash"; then
    echo "[-] Update failed: invalid file downloaded." > /dev/tty
    rm -f "$tmp"
    return 1
  fi
  chmod +x "$tmp"

  if is_installed; then
    mv -f "$tmp" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo "[+] Updated. Run again: sudo pahlavi-tunnel" > /dev/tty
  else
    mv -f "$tmp" "./${SCRIPT_FILENAME}"
    chmod +x "./${SCRIPT_FILENAME}"
    echo "[+] Updated file saved locally: ./${SCRIPT_FILENAME}" > /dev/tty
  fi
}

disable_cron_healthcheck(){
  local tmp; tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | grep -vF "${HC_CRON_TAG}" >"$tmp" || true
  crontab "$tmp" || true
  rm -f "$tmp"
  echo "[+] Cron disabled." > /dev/tty
}


optimize_server() {
    echo > /dev/tty
    echo "[*] Optimizing network settings and enabling BBR if supported..." > /dev/tty

    modprobe tcp_bbr >/dev/null 2>&1 || true

    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
        echo "[+] BBR is available." > /dev/tty

        sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
        sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true

        local conf="/etc/sysctl.d/99-pahlavi-tunnel.conf"
        cat > "$conf" <<'EOF'
# Pahlavi Tunnel - network tuning
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# Socket buffer ceilings (reasonable defaults)
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF

        sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1 || true

        echo "[+] Applied sysctl tuning." > /dev/tty
        echo "[i] tcp_congestion_control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)" > /dev/tty
        echo "[i] default_qdisc: $(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)" > /dev/tty
    else
        echo "[!] BBR is NOT available on this kernel." > /dev/tty
        echo "[i] Available: $(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo unknown)" > /dev/tty
    fi
}

uninstall_script(){
  disable_cron_healthcheck >/dev/null 2>&1 || true
  rm -f "$HC_SCRIPT" >/dev/null 2>&1 || true
  rm -f "$INSTALL_PATH" >/dev/null 2>&1 || true
  echo "[+] Uninstalled: $INSTALL_PATH" > /dev/tty
}

# Info (best-effort)
get_public_ip(){ curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null || true; }
get_ipinfo_field(){
  local field="$1" ip="$2"
  [[ -n "$ip" ]] || { echo ""; return 0; }
  local json
  json="$(curl -fsSL --max-time 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
  [[ -n "$json" ]] || { echo ""; return 0; }
  echo "$json" | tr -d '\n' | sed -n "s/.*\"${field}\":[ ]*\"\\([^\"]*\\)\".*/\\1/p" | head -n1
}
get_location_string(){
  local ip city region country
  ip="$(get_public_ip)"
  city="$(get_ipinfo_field city "$ip")"
  region="$(get_ipinfo_field region "$ip")"
  country="$(get_ipinfo_field country "$ip")"
  if [[ -n "$city" || -n "$region" || -n "$country" ]]; then
    echo "${city}${city:+, }${region}${region:+, }${country}"
  else
    echo "Unknown"
  fi
}
get_datacenter_string(){
  local ip org
  ip="$(get_public_ip)"
  org="$(get_ipinfo_field org "$ip")"
  [[ -n "$org" ]] && echo "$org" || echo "Unknown"
}

# Profiles
pick_role(){
  while true; do
    printf "1) EU\n2) IRAN\n" > /dev/tty
    read -r -p "Select: " x < /dev/tty
    if [[ "$x" == "1" ]]; then echo "eu"; return 0; fi
    if [[ "$x" == "2" ]]; then echo "iran"; return 0; fi
    echo "Invalid." > /dev/tty
  done
}
slot_status(){ local role="$1" i="$2"; [[ -f "$CONF/${role}${i}.env" ]] && echo "[saved]" || echo "(empty)"; }
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
  local prof="$1" f="$CONF/${prof}.env" role="${prof%%[0-9]*}"
  echo "" > /dev/tty; echo "Editing: $prof" > /dev/tty

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

session_name(){ echo "pahlavi_$1"; }
is_running(){
  local prof="$1" s; s="$(session_name "$prof")"
  screen -ls 2>/dev/null | grep -q "\.${s}[[:space:]]"
}
run_slot(){
  local prof="$1" f="$CONF/${prof}.env"
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
  echo "[+] Started: $s" > /dev/tty
}
stop_slot(){ local prof="$1" s; s="$(session_name "$prof")"; screen -S "$s" -X quit >/dev/null 2>&1 || true; echo "[+] Stopped: $s" > /dev/tty; }
restart_slot(){ local prof="$1"; stop_slot "$prof" >/dev/null 2>&1 || true; sleep 0.5; run_slot "$prof"; }
status_slot(){
  local prof="$1" f="$CONF/${prof}.env"
  [[ -f "$f" ]] || { echo "Profile not found: $prof" > /dev/tty; return 1; }
  local st="${CLR_RED}OFF${CLR_RESET}"
  if is_running "$prof"; then st="${CLR_GREEN}ON${CLR_RESET}"; fi
  echo -e "Profile: $prof | Running: $st" > /dev/tty
}
delete_slot(){
  local prof="$1" f="$CONF/${prof}.env"
  stop_slot "$prof" >/dev/null 2>&1 || true
  if [[ -f "$f" ]]; then rm -f "$f"; echo "[+] Deleted: $f" > /dev/tty; else echo "[-] Not found: $f" > /dev/tty; fi
}
logs_slot(){ local prof="$1" s; s="$(session_name "$prof")"; echo "[i] Attach: $s (Ctrl+A then D)" > /dev/tty; screen -r "$s" || true; }

install_healthcheck_script(){
  cat >"$HC_SCRIPT" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PY="${PY}"
CONF="${CONF}"
MAX="${MAX}"
session_name(){ echo "pahlavi_\$1"; }
is_running(){ local prof="\$1" s; s="\$(session_name "\$prof")"; screen -ls 2>/dev/null | grep -q "\\.\${s}[[:space:]]"; }
start_from_profile(){
  local prof="\$1" f="\${CONF}/\${prof}.env"
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
    [[ -f "\${CONF}/\${prof}.env" ]] || continue
    if ! is_running "\$prof"; then start_from_profile "\$prof" >/dev/null 2>&1 || true; fi
  done
done
EOF
  chmod +x "$HC_SCRIPT"
}
enable_cron_healthcheck(){
  install_healthcheck_script

  echo > /dev/tty
  read -r -p "Enter interval in minutes (default: 1): " interval < /dev/tty
  interval="${interval:-1}"
  if ! [[ "$interval" =~ ^[0-9]+$ ]]; then
    echo "[!] Invalid number. Using default 1 minute." > /dev/tty
    interval=1
  fi
  if (( interval < 1 )); then interval=1; fi

  local line="*/${interval} * * * * ${HC_SCRIPT} >/dev/null 2>&1 ${HC_CRON_TAG}"
  local tmp; tmp="$(mktemp)"
  (crontab -l 2>/dev/null || true) | grep -vF "${HC_CRON_TAG}" >"$tmp" || true
  echo "$line" >>"$tmp"
  crontab "$tmp"
  rm -f "$tmp"
  echo "[+] Cron enabled (every ${interval} minute(s))." > /dev/tty
}

print_banner(){
  local loc dc inst
  loc="$(get_location_string)"
  dc="$(get_datacenter_string)"
  inst="${CLR_RED}NOT INSTALLED${CLR_RESET}"
  if is_installed; then inst="${CLR_GREEN}INSTALLED${CLR_RESET}"; fi

  echo -e "${CLR_CYAN}${CLR_BOLD}"
  if have figlet; then
    figlet -f slant "$APP_NAME" 2>/dev/null || figlet "$APP_NAME" 2>/dev/null || true
  else
    echo "$APP_NAME"
  fi
  echo -e "${CLR_RESET}"

  echo -e "${CLR_GREEN}Version:${CLR_RESET} v${VERSION}"
  echo -e "${CLR_GREEN}GitHub:${CLR_RESET} ${GITHUB_REPO}"
  echo -e "${CLR_GREEN}Telegram ID:${CLR_RESET} ${TG_ID}"
  echo -e "${CLR_DIM}============================================================${CLR_RESET}"
  echo -e "${CLR_CYAN}Location:${CLR_RESET} ${loc}"
  echo -e "${CLR_CYAN}Datacenter:${CLR_RESET} ${dc}"
  echo -e "${CLR_CYAN}Script:${CLR_RESET} ${inst}"
  echo -e "${CLR_DIM}============================================================${CLR_RESET}"
}

manage_slot_menu(){
  local prof="$1"
  while true; do
    echo "" > /dev/tty
    echo -e "${CLR_YELLOW}${CLR_BOLD}Manage slot:${CLR_RESET} ${prof}" > /dev/tty
    echo "1) Show profile" > /dev/tty
    echo "2) Start" > /dev/tty
    echo "3) Stop" > /dev/tty
    echo "4) Restart" > /dev/tty
    echo "5) Status" > /dev/tty
    echo "6) Logs" > /dev/tty
    echo "7) Delete slot" > /dev/tty
    echo "0) Back" > /dev/tty
    read -r -p "Select: " c < /dev/tty
    case "$c" in
      1) cat "$CONF/${prof}.env" 2>/dev/null > /dev/tty || echo "Profile not found." > /dev/tty; pause ;;
      2) run_slot "$prof"; pause ;;
      3) stop_slot "$prof"; pause ;;
      4) restart_slot "$prof"; pause ;;
      5) status_slot "$prof"; pause ;;
      6) logs_slot "$prof" ;;
      7) delete_slot "$prof"; pause ;;
      0) return ;;
      *) echo "Invalid." > /dev/tty ;;
    esac
  done
}

# ===================== Port Forward (iptables DNAT) =====================
port_forward_iptables_menu(){
  echo > /dev/tty
  echo -e "${CLR_WHITE}${CLR_BOLD}Port Forward (IR only)${CLR_RESET}" > /dev/tty
  echo "1) Add port forward" > /dev/tty
  echo "2) Remove port forward" > /dev/tty
  echo "3) Show port forward rules" > /dev/tty
  echo "0) Back" > /dev/tty
  read -r -p "Select: " pf < /dev/tty
  case "$pf" in
    1) port_forward_add; pause ;;
    2) port_forward_remove; pause ;;
    3) port_forward_show; pause ;;
    0) return ;;
    *) echo "Invalid." > /dev/tty; sleep 1 ;;
  esac
}

port_forward_menu(){
  echo > /dev/tty
  echo -e "${CLR_WHITE}${CLR_BOLD}Port Forward (IR only)${CLR_RESET}" > /dev/tty
  echo "1) iptables (DNAT)" > /dev/tty
  echo "2) nftables (DNAT)" > /dev/tty
  echo "3) HAProxy (TCP)" > /dev/tty
  echo "4) socat (TCP relay)" > /dev/tty
  echo "0) Back" > /dev/tty
  read -r -p "Select: " mth < /dev/tty
  case "$mth" in
    1) port_forward_iptables_menu ;;
    2) port_forward_nft_menu ;;
    3) port_forward_haproxy_menu ;;
    4) port_forward_socat_menu ;;
    0) return ;;
    *) echo "Invalid." > /dev/tty; sleep 1 ;;
  esac
}

# --------------------- nftables DNAT ---------------------
_pf_nft_table="inet pahlavi_pf"
_pf_nft_chain_pre="prerouting"
_pf_nft_chain_post="postrouting"

_pf_nft_ensure(){
  command -v nft >/dev/null 2>&1 || { echo "[!] nft not found." > /dev/tty; return 1; }
  # Enable forwarding
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [[ -w /etc/sysctl.d ]]; then
    echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-pahlavi-ipforward.conf
  fi

  nft list table ${_pf_nft_table} >/dev/null 2>&1 || nft add table ${_pf_nft_table} >/dev/null 2>&1 || true

  nft list chain ${_pf_nft_table} ${_pf_nft_chain_pre} >/dev/null 2>&1 || \
    nft add chain ${_pf_nft_table} ${_pf_nft_chain_pre} '{ type nat hook prerouting priority -100; policy accept; }' >/dev/null 2>&1 || true

  nft list chain ${_pf_nft_table} ${_pf_nft_chain_post} >/dev/null 2>&1 || \
    nft add chain ${_pf_nft_table} ${_pf_nft_chain_post} '{ type nat hook postrouting priority 100; policy accept; }' >/dev/null 2>&1 || true
}

port_forward_nft_menu(){
  echo > /dev/tty
  echo -e "${CLR_WHITE}${CLR_BOLD}Port Forward (nftables DNAT)${CLR_RESET}" > /dev/tty
  echo "1) Add port forward" > /dev/tty
  echo "2) Remove port forward" > /dev/tty
  echo "3) Show port forward rules" > /dev/tty
  echo "0) Back" > /dev/tty
  read -r -p "Select: " pf < /dev/tty
  case "$pf" in
    1) nft_forward_add; pause ;;
    2) nft_forward_remove; pause ;;
    3) nft_forward_show; pause ;;
    0) return ;;
    *) echo "Invalid." > /dev/tty; sleep 1 ;;
  esac
}

nft_forward_add(){
  _pf_nft_ensure || return
  echo > /dev/tty
  read -r -p "Protocol (tcp/udp) [tcp]: " proto < /dev/tty
  proto="${proto:-tcp}"; proto="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"
  _pf_validate_proto "$proto" || { echo "[!] Invalid protocol." > /dev/tty; return; }

  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  read -r -p "Destination EU IP (or host) : " dstip < /dev/tty
  [[ -n "$dstip" ]] || { echo "[!] Destination is required." > /dev/tty; return; }

  read -r -p "Destination port on EU      : " dport < /dev/tty
  _pf_validate_port "$dport" || { echo "[!] Invalid destination port." > /dev/tty; return; }

  # Add DNAT rule with comment tag
  local cmt="$(_pf_comment)"
  nft add rule ${_pf_nft_table} ${_pf_nft_chain_pre} meta l4proto $proto $proto dport $lport dnat to ${dstip}:$dport comment "$cmt" 2>/dev/null || \
    echo "[i] Rule may already exist." > /dev/tty

  # Ensure SNAT/MASQ so replies route back through IR
  nft add rule ${_pf_nft_table} ${_pf_nft_chain_post} oifname != "lo" masquerade comment "$cmt" 2>/dev/null || true

  echo "[+] nft forward added: ${proto} :${lport} -> ${dstip}:${dport}" > /dev/tty
}

nft_forward_remove(){
  _pf_nft_ensure || return
  echo > /dev/tty
  read -r -p "Protocol (tcp/udp) [tcp]: " proto < /dev/tty
  proto="${proto:-tcp}"; proto="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"
  _pf_validate_proto "$proto" || { echo "[!] Invalid protocol." > /dev/tty; return; }

  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  # Delete matching rules by handle
  local cmt="$(_pf_comment)"
  local handles
  handles="$(nft -a list chain ${_pf_nft_table} ${_pf_nft_chain_pre} 2>/dev/null | awk "/dport ${lport} .*comment \\"${cmt}\\"/ {print \$NF}")"
  if [[ -z "$handles" ]]; then
    echo "[!] No matching rule found." > /dev/tty
    return
  fi
  while read -r h; do
    [[ -n "$h" ]] || continue
    nft delete rule ${_pf_nft_table} ${_pf_nft_chain_pre} handle "$h" >/dev/null 2>&1 || true
  done <<< "$handles"
  echo "[+] Removed nft rule(s) for :${lport}" > /dev/tty
}

nft_forward_show(){
  command -v nft >/dev/null 2>&1 || { echo "[!] nft not found." > /dev/tty; return; }
  echo > /dev/tty
  nft -a list table ${_pf_nft_table} 2>/dev/null | sed -n '1,200p' > /dev/tty || echo "[i] No nft table ${_pf_nft_table}." > /dev/tty
}

# --------------------- HAProxy TCP forward ---------------------
_pf_haproxy_cfg="/etc/haproxy/pahlavi_pf.cfg"
_pf_haproxy_main="/etc/haproxy/haproxy.cfg"

_pf_haproxy_ensure(){
  command -v haproxy >/dev/null 2>&1 || { echo "[!] haproxy not found." > /dev/tty; return 1; }
  touch "$_pf_haproxy_cfg" >/dev/null 2>&1 || true
  if [[ -f "$_pf_haproxy_main" ]] && ! grep -qF "$_pf_haproxy_cfg" "$_pf_haproxy_main"; then
    echo "" >> "$_pf_haproxy_main"
    echo "# Pahlavi Port Forward includes" >> "$_pf_haproxy_main"
    echo "include $_pf_haproxy_cfg" >> "$_pf_haproxy_main"
  fi
  systemctl enable haproxy >/dev/null 2>&1 || true
  systemctl start haproxy >/dev/null 2>&1 || true
}

port_forward_haproxy_menu(){
  echo > /dev/tty
  echo -e "${CLR_WHITE}${CLR_BOLD}Port Forward (HAProxy TCP)${CLR_RESET}" > /dev/tty
  echo "1) Add port forward" > /dev/tty
  echo "2) Remove port forward" > /dev/tty
  echo "3) Show port forward rules" > /dev/tty
  echo "0) Back" > /dev/tty
  read -r -p "Select: " pf < /dev/tty
  case "$pf" in
    1) haproxy_forward_add; pause ;;
    2) haproxy_forward_remove; pause ;;
    3) haproxy_forward_show; pause ;;
    0) return ;;
    *) echo "Invalid." > /dev/tty; sleep 1 ;;
  esac
}

haproxy_forward_add(){
  _pf_haproxy_ensure || return
  echo > /dev/tty
  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  read -r -p "Destination EU IP (or host) : " dstip < /dev/tty
  [[ -n "$dstip" ]] || { echo "[!] Destination is required." > /dev/tty; return; }

  read -r -p "Destination port on EU      : " dport < /dev/tty
  _pf_validate_port "$dport" || { echo "[!] Invalid destination port." > /dev/tty; return; }

  local tag="pahlavi_pf_${lport}"
  if grep -qF "BEGIN ${tag}" "$_pf_haproxy_cfg"; then
    echo "[!] Forward for :${lport} already exists." > /dev/tty
    return
  fi

  cat >> "$_pf_haproxy_cfg" <<EOF

# BEGIN ${tag}
frontend pf_${lport}
  bind 0.0.0.0:${lport}
  mode tcp
  default_backend be_pf_${lport}

backend be_pf_${lport}
  mode tcp
  server eu1 ${dstip}:${dport} check
# END ${tag}
EOF

  haproxy -c -f "$_pf_haproxy_main" >/dev/null 2>&1 || { echo "[!] HAProxy config check failed. Reverting." > /dev/tty; sed -i "/BEGIN ${tag}/,/END ${tag}/d" "$_pf_haproxy_cfg"; return; }
  systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1 || true
  echo "[+] HAProxy forward added: :${lport} -> ${dstip}:${dport}" > /dev/tty
}

haproxy_forward_remove(){
  _pf_haproxy_ensure || return
  echo > /dev/tty
  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }
  local tag="pahlavi_pf_${lport}"
  if ! grep -qF "BEGIN ${tag}" "$_pf_haproxy_cfg"; then
    echo "[!] No HAProxy forward found for :${lport}" > /dev/tty
    return
  fi
  sed -i "/BEGIN ${tag}/,/END ${tag}/d" "$_pf_haproxy_cfg"
  haproxy -c -f "$_pf_haproxy_main" >/dev/null 2>&1 || true
  systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1 || true
  echo "[+] HAProxy forward removed for :${lport}" > /dev/tty
}

haproxy_forward_show(){
  echo > /dev/tty
  if [[ -s "$_pf_haproxy_cfg" ]]; then
    sed -n '1,200p' "$_pf_haproxy_cfg" > /dev/tty
  else
    echo "[i] No HAProxy forwards configured." > /dev/tty
  fi
}

# --------------------- socat TCP relay (systemd service) ---------------------
_pf_socat_service_dir="/etc/systemd/system"

port_forward_socat_menu(){
  echo > /dev/tty
  echo -e "${CLR_WHITE}${CLR_BOLD}Port Forward (socat TCP relay)${CLR_RESET}" > /dev/tty
  echo "1) Add port forward" > /dev/tty
  echo "2) Remove port forward" > /dev/tty
  echo "3) Show port forward services" > /dev/tty
  echo "0) Back" > /dev/tty
  read -r -p "Select: " pf < /dev/tty
  case "$pf" in
    1) socat_forward_add; pause ;;
    2) socat_forward_remove; pause ;;
    3) socat_forward_show; pause ;;
    0) return ;;
    *) echo "Invalid." > /dev/tty; sleep 1 ;;
  esac
}

socat_forward_add(){
  command -v socat >/dev/null 2>&1 || { echo "[!] socat not found." > /dev/tty; return; }
  echo > /dev/tty
  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  read -r -p "Destination EU IP (or host) : " dstip < /dev/tty
  [[ -n "$dstip" ]] || { echo "[!] Destination is required." > /dev/tty; return; }

  read -r -p "Destination port on EU      : " dport < /dev/tty
  _pf_validate_port "$dport" || { echo "[!] Invalid destination port." > /dev/tty; return; }

  local svc="pahlavi-socat-${lport}.service"
  local path="${_pf_socat_service_dir}/${svc}"

  if [[ -f "$path" ]]; then
    echo "[!] Service already exists: ${svc}" > /dev/tty
    return
  fi

  cat > "$path" <<EOF
[Unit]
Description=Pahlavi socat port forward :${lport} -> ${dstip}:${dport}
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat TCP-LISTEN:${lport},fork,reuseaddr TCP:${dstip}:${dport}
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now "$svc" >/dev/null 2>&1 || true
  echo "[+] socat forward added via systemd: :${lport} -> ${dstip}:${dport}" > /dev/tty
}

socat_forward_remove(){
  echo > /dev/tty
  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  local svc="pahlavi-socat-${lport}.service"
  local path="${_pf_socat_service_dir}/${svc}"

  if [[ ! -f "$path" ]]; then
    echo "[!] No such service: ${svc}" > /dev/tty
    return
  fi

  systemctl disable --now "$svc" >/dev/null 2>&1 || true
  rm -f "$path"
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "[+] socat forward removed: :${lport}" > /dev/tty
}

socat_forward_show(){
  echo > /dev/tty
  systemctl list-units --type=service --all | grep -E "pahlavi-socat-[0-9]+\.service" > /dev/tty || echo "[i] No socat forwards." > /dev/tty
}

_pf_validate_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 ))
}

_pf_validate_proto(){
  local pr="$1"
  [[ "$pr" == "tcp" || "$pr" == "udp" ]]
}

_pf_comment(){
  # stable tag so we can safely list/remove only our own rules
  echo "pahlavi_pf"
}

port_forward_add(){
  command -v iptables >/dev/null 2>&1 || { echo "[!] iptables not found." > /dev/tty; return; }

  echo > /dev/tty
  read -r -p "Protocol (tcp/udp) [tcp]: " proto < /dev/tty
  proto="${proto:-tcp}"
  proto="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"
  _pf_validate_proto "$proto" || { echo "[!] Invalid protocol." > /dev/tty; return; }

  read -r -p "Listen port on IR (incoming) : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  read -r -p "Destination EU IP (or host)     : " dstip < /dev/tty
  [[ -n "$dstip" ]] || { echo "[!] Destination is required." > /dev/tty; return; }

  read -r -p "Destination port on EU          : " dport < /dev/tty
  _pf_validate_port "$dport" || { echo "[!] Invalid destination port." > /dev/tty; return; }

  # enable IPv4 forwarding (runtime + persist)
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [[ -w /etc/sysctl.d ]]; then
    cat > /etc/sysctl.d/99-pahlavi-ipforward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null 2>&1 || true
  fi

  local cmt; cmt="$(_pf_comment)"

  # PREROUTING DNAT
  if ! iptables -t nat -C PREROUTING -p "$proto" --dport "$lport" -m comment --comment "$cmt" -j DNAT --to-destination "${dstip}:${dport}" 2>/dev/null; then
    iptables -t nat -A PREROUTING -p "$proto" --dport "$lport" -m comment --comment "$cmt" -j DNAT --to-destination "${dstip}:${dport}"
  fi

  # FORWARD allow
  if ! iptables -C FORWARD -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j ACCEPT
  fi

  # POSTROUTING MASQUERADE so replies work
  if ! iptables -t nat -C POSTROUTING -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j MASQUERADE
  fi

  echo "[+] Port forward added: ${proto} :${lport}  ->  ${dstip}:${dport}" > /dev/tty
  echo "[i] Note: rules are runtime. If you need persistence across reboot, install iptables-persistent or save/restore via your own method." > /dev/tty
}

port_forward_remove(){
  command -v iptables >/dev/null 2>&1 || { echo "[!] iptables not found." > /dev/tty; return; }

  echo > /dev/tty
  read -r -p "Protocol (tcp/udp) [tcp]: " proto < /dev/tty
  proto="${proto:-tcp}"
  proto="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"
  _pf_validate_proto "$proto" || { echo "[!] Invalid protocol." > /dev/tty; return; }

  read -r -p "Listen port on IR to remove : " lport < /dev/tty
  _pf_validate_port "$lport" || { echo "[!] Invalid listen port." > /dev/tty; return; }

  read -r -p "Destination EU IP (same as added): " dstip < /dev/tty
  [[ -n "$dstip" ]] || { echo "[!] Destination is required." > /dev/tty; return; }

  read -r -p "Destination port on EU          : " dport < /dev/tty
  _pf_validate_port "$dport" || { echo "[!] Invalid destination port." > /dev/tty; return; }

  local cmt; cmt="$(_pf_comment)"

  # remove (loop until not present)
  while iptables -t nat -C PREROUTING -p "$proto" --dport "$lport" -m comment --comment "$cmt" -j DNAT --to-destination "${dstip}:${dport}" 2>/dev/null; do
    iptables -t nat -D PREROUTING -p "$proto" --dport "$lport" -m comment --comment "$cmt" -j DNAT --to-destination "${dstip}:${dport}" || break
  done

  while iptables -C FORWARD -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j ACCEPT 2>/dev/null; do
    iptables -D FORWARD -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j ACCEPT || break
  done

  while iptables -t nat -C POSTROUTING -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j MASQUERADE 2>/dev/null; do
    iptables -t nat -D POSTROUTING -p "$proto" -d "$dstip" --dport "$dport" -m comment --comment "$cmt" -j MASQUERADE || break
  done

  echo "[+] Port forward removed: ${proto} :${lport}  ->  ${dstip}:${dport}" > /dev/tty
}

port_forward_show(){
  command -v iptables >/dev/null 2>&1 || { echo "[!] iptables not found." > /dev/tty; return; }
  local cmt; cmt="$(_pf_comment)"
  echo > /dev/tty
  echo "---- nat PREROUTING (our rules) ----" > /dev/tty
  iptables -t nat -S PREROUTING | grep -F -- "$cmt" > /dev/tty || true
  echo "---- filter FORWARD (our rules) ----" > /dev/tty
  iptables -S FORWARD | grep -F -- "$cmt" > /dev/tty || true
  echo "---- nat POSTROUTING (our rules) ----" > /dev/tty
  iptables -t nat -S POSTROUTING | grep -F -- "$cmt" > /dev/tty || true
}

# ===================== Main =====================
need_root
ensure

while true; do
  clear || true
  print_banner

  echo -e "${CLR_WHITE}${CLR_BOLD}1.${CLR_RESET} Create/Update profile"
  echo -e "${CLR_WHITE}${CLR_BOLD}2.${CLR_RESET} Manage tunnel (select slot)"
  echo -e "${CLR_WHITE}${CLR_BOLD}3.${CLR_RESET} Enable cron health-check"
  echo -e "${CLR_WHITE}${CLR_BOLD}4.${CLR_RESET} Disable cron health-check"
  echo -e "${CLR_WHITE}${CLR_BOLD}5.${CLR_RESET} Install script (system-wide)"
  echo -e "${CLR_WHITE}${CLR_BOLD}6.${CLR_RESET} Update script (self-update)"
  echo -e "${CLR_WHITE}${CLR_BOLD}7.${CLR_RESET} Uninstall script"
  echo -e "${CLR_WHITE}${CLR_BOLD}8.${CLR_RESET} Port forward (multi-method)"
  echo -e "${CLR_WHITE}${CLR_BOLD}9.${CLR_RESET} Optimize server (BBR + sysctl)"
  echo -e "${CLR_WHITE}${CLR_BOLD}0.${CLR_RESET} Exit"
  echo -e "${CLR_DIM}------------------------------------------------------------${CLR_RESET}"

  read -r -p "Select: " c < /dev/tty
  case "$c" in
    1) role="$(pick_role)"; prof="$(pick_slot "$role")"; edit_profile "$prof"; pause ;;
    2) role="$(pick_role)"; prof="$(pick_slot "$role")"; manage_slot_menu "$prof" ;;
    3) enable_cron_healthcheck; pause ;;
    4) disable_cron_healthcheck; pause ;;
    5) install_script; pause ;;
    6) update_script; pause ;;
    7) uninstall_script; pause ;;
    8) port_forward_menu ;;
    9) optimize_server; pause ;;
    0) exit 0 ;;
    *) echo "Invalid."; sleep 1 ;;
  esac
done
