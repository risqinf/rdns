#!/usr/bin/env bash
# ========================================================
# RDNS Exit Node (Server) Automated Installer & Setup
# Author / Credit: github: @risqinf
# Supported OS: Debian, Ubuntu, Rocky, AlmaLinux, CentOS, Alpine Linux
# ========================================================
set -euo pipefail

# --- Color Definitions ---
NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
ORANGE='\033[38;5;208m'
PINK='\033[38;5;205m'

ui_rep() { local ch="$1" n="$2" out=""; while (( n > 0 )); do out+="$ch"; ((n--)); done; printf '%s' "$out"; }
ui_rule() { echo -e "${CYAN}$(ui_rep '═' 58)${NC}"; }
ui_header() {
  ui_rule
  echo -e "  ${WHITE}$1${NC}"
  ui_rule
}
ok()   { echo -e " ${GREEN}[OK]${NC} $1"; }
info() { echo -e " ${BLUE}[INFO]${NC} $1"; }
warn() { echo -e " ${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e " ${RED}[ERROR]${NC} $1"; }

# --- Check Help First ---
for arg in "$@"; do
  if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
    echo "Usage: $0 [--ip <PUBLIC_IP>] [--tunnel-port <443|NAT_PORT>] [--dns-port <53|NAT_PORT>] [--profile <my|id>]"
    exit 0
  fi
done

if [[ $EUID -ne 0 ]]; then
  err "Skrip ini harus dijalankan sebagai root (sudo -i)."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RDNS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# --- Arch Detection ---
UNAME_M="$(uname -m)"
case "$UNAME_M" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    err "Arsitektur CPU tidak didukung: $UNAME_M"
    exit 1
    ;;
esac

is_valid_ip() {
  local ip="${1:-}"
  local rx="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
  if [[ "$ip" =~ $rx ]]; then
    local IFS="."
    local i1 i2 i3 i4
    read -r i1 i2 i3 i4 <<< "$ip"
    (( i1 <= 255 && i2 <= 255 && i3 <= 255 && i4 <= 255 ))
    return $?
  fi
  if [[ "$ip" =~ : ]]; then
    return 0
  fi
  return 1
}

is_valid_port() {
  local p="${1:-}"
  [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

# --- Auto-detect Public IP ---
DETECTED_IP="$(curl -s4 --max-time 3 https://api.ipify.org || curl -s4 --max-time 3 https://ifconfig.me || curl -s4 --max-time 3 https://ip.sb || echo "")"
DETECTED_IP="$(echo "$DETECTED_IP" | tr -d '[:space:]\\')"

# --- Parse Flags or Prompt ---
INPUT_IP=""
INPUT_TUNNEL_PORT="443"
INPUT_DNS_PORT="53"
INPUT_PROFILE="my"
AUTO_YES="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip) INPUT_IP="$2"; shift 2 ;;
    --tunnel-port) INPUT_TUNNEL_PORT="$2"; shift 2 ;;
    --dns-port) INPUT_DNS_PORT="$2"; shift 2 ;;
    --profile) INPUT_PROFILE="$2"; shift 2 ;;
    -y|--yes) AUTO_YES="true"; shift ;;
    -h|--help)
      echo "Usage: $0 [--ip <PUBLIC_IP>] [--tunnel-port <443|NAT_PORT>] [--dns-port <53|NAT_PORT>] [--profile <my|id>] [-y|--yes]"
      exit 0
      ;;
    *) shift ;;
  esac
done

clear
ui_header "RDNS SERVER / EXIT NODE INSTALLER"
echo -e " ${WHITE}Credit:${NC} ${PINK}github: @risqinf${NC}"
echo -e " ${WHITE}Platform:${NC} ${CYAN}Linux (${ARCH})${NC}"
echo ""

# Helper for interactive prompt that supports both normal execution and curl | bash
prompt_read() {
  local prompt_text="$1"
  local var_name="$2"
  local default_val="$3"
  local val=""
  if [[ -t 0 ]]; then
    read -rp "$prompt_text" val || true
  elif [[ -e /dev/tty ]]; then
    read -rp "$prompt_text" val </dev/tty || true
  fi
  # Clean val: strip carriage returns, newlines, and trailing/leading spaces or stray backslashes
  val="$(echo "$val" | tr -d '\r\n')"
  val="$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ "$val" == "\\" || -z "$val" ]]; then
    val="$default_val"
  fi
  printf -v "$var_name" '%s' "$val"
}

if [[ "$AUTO_YES" == "true" ]]; then
  SERVER_IP="${INPUT_IP:-$DETECTED_IP}"
  TUNNEL_PORT="$INPUT_TUNNEL_PORT"
  DNS_PORT="$INPUT_DNS_PORT"
  PROFILE="$INPUT_PROFILE"
  info "Mode otomatis aktif (-y). Menggunakan parameter default:"
  echo -e "  - IP Server    : ${CYAN}${SERVER_IP}${NC}"
  echo -e "  - Port Tunnel  : ${CYAN}${TUNNEL_PORT}${NC}"
  echo -e "  - Port DNS     : ${CYAN}${DNS_PORT}${NC}"
  echo -e "  - Profil       : ${CYAN}${PROFILE}${NC}"
else
  if [[ -z "$INPUT_IP" ]]; then
    prompt_read " Masukkan IP Publik Server ini [default: ${DETECTED_IP}]: " SERVER_IP "$DETECTED_IP"
  else
    SERVER_IP="$INPUT_IP"
  fi

  prompt_read " Port Tunnel mTLS (Yamux) [default: ${INPUT_TUNNEL_PORT}]: " TUNNEL_PORT "$INPUT_TUNNEL_PORT"
  prompt_read " Port DNS Upstream [default: ${INPUT_DNS_PORT}]: " DNS_PORT "$INPUT_DNS_PORT"
  prompt_read " Nama Profil / Kode Negara (misal: my, id, sg) [default: ${INPUT_PROFILE}]: " PROFILE "$INPUT_PROFILE"
fi

# Sanitize and validate SERVER_IP
SERVER_IP="$(echo "${SERVER_IP:-}" | tr -d '[:space:]\\')"
if ! is_valid_ip "$SERVER_IP"; then
  if is_valid_ip "${DETECTED_IP:-}"; then
    warn "IP Server yang dimasukkan ('$SERVER_IP') tidak valid. Menggunakan IP terdeteksi otomatis: ${DETECTED_IP}"
    SERVER_IP="$DETECTED_IP"
  else
    err "IP Publik Server '$SERVER_IP' tidak valid. Harap masukkan IPv4 yang benar (contoh: 172.235.251.67)."
    exit 1
  fi
fi

# Sanitize and validate TUNNEL_PORT
TUNNEL_PORT="$(echo "${TUNNEL_PORT:-}" | tr -d '[:space:]\\')"
if ! is_valid_port "$TUNNEL_PORT"; then
  warn "Port tunnel ('$TUNNEL_PORT') tidak valid. Menggunakan default: 443"
  TUNNEL_PORT="443"
fi

# Sanitize and validate DNS_PORT
DNS_PORT="$(echo "${DNS_PORT:-}" | tr -d '[:space:]\\')"
if ! is_valid_port "$DNS_PORT"; then
  warn "Port DNS ('$DNS_PORT') tidak valid. Menggunakan default: 53"
  DNS_PORT="53"
fi

# Sanitize PROFILE
PROFILE="$(echo "${PROFILE:-my}" | tr -d '[:space:]\\' | tr '[:upper:]' '[:lower:]')"
if [[ -z "$PROFILE" ]]; then
  PROFILE="my"
fi

echo ""
info "Menyiapkan instalasi RDNS Server..."

# --- Install Binaries ---
mkdir -p /usr/local/bin /etc/rdns/certs /var/log /var/lib/rdns/acme

# 1. Check local prebuilt binaries if available
BIN_SERVER=""
BIN_CERTS=""

if [[ -n "${RDNS_ROOT:-}" && -x "$RDNS_ROOT/dist/rdns-server-linux-$ARCH" ]]; then
  BIN_SERVER="$RDNS_ROOT/dist/rdns-server-linux-$ARCH"
elif [[ -n "${RDNS_ROOT:-}" && -x "$RDNS_ROOT/bin/rdns-server-linux" ]]; then
  BIN_SERVER="$RDNS_ROOT/bin/rdns-server-linux"
elif [[ -x "/usr/local/bin/rdns-server" ]]; then
  BIN_SERVER="/usr/local/bin/rdns-server"
fi

if [[ -n "${RDNS_ROOT:-}" && -x "$RDNS_ROOT/dist/rdns-certs-linux-$ARCH" ]]; then
  BIN_CERTS="$RDNS_ROOT/dist/rdns-certs-linux-$ARCH"
elif [[ -n "${RDNS_ROOT:-}" && -x "$RDNS_ROOT/bin/rdns-certs-linux" ]]; then
  BIN_CERTS="$RDNS_ROOT/bin/rdns-certs-linux"
elif [[ -x "/usr/local/bin/rdns-certs" ]]; then
  BIN_CERTS="/usr/local/bin/rdns-certs"
fi

# 2. If not found locally, auto-download prebuilt static binaries from GitHub Releases
GH_TAG="v0.2.0"
RELEASE_BASE="https://github.com/risqinf/rdns/releases/download/${GH_TAG}"

if [[ -z "$BIN_SERVER" || "$BIN_SERVER" != "/usr/local/bin/rdns-server" ]]; then
  if [[ -n "$BIN_SERVER" ]]; then
    cp -f "$BIN_SERVER" /usr/local/bin/rdns-server
  else
    info "Mengunduh binary static rdns-server (${ARCH}) dari GitHub Release (${GH_TAG})..."
    if ! curl -sSL --connect-timeout 10 --max-time 60 -o /usr/local/bin/rdns-server "${RELEASE_BASE}/rdns-server-linux-${ARCH}"; then
      err "Gagal mengunduh rdns-server dari GitHub Release (${RELEASE_BASE}/rdns-server-linux-${ARCH})."
      exit 1
    fi
  fi
fi

if [[ -z "$BIN_CERTS" || "$BIN_CERTS" != "/usr/local/bin/rdns-certs" ]]; then
  if [[ -n "$BIN_CERTS" ]]; then
    cp -f "$BIN_CERTS" /usr/local/bin/rdns-certs
  else
    info "Mengunduh binary static rdns-certs (${ARCH}) dari GitHub Release (${GH_TAG})..."
    if ! curl -sSL --connect-timeout 10 --max-time 60 -o /usr/local/bin/rdns-certs "${RELEASE_BASE}/rdns-certs-linux-${ARCH}"; then
      err "Gagal mengunduh rdns-certs dari GitHub Release (${RELEASE_BASE}/rdns-certs-linux-${ARCH})."
      exit 1
    fi
  fi
fi

chmod 755 /usr/local/bin/rdns-server /usr/local/bin/rdns-certs

# Quick sanity check on binaries
if ! /usr/local/bin/rdns-server -help &>/dev/null && ! /usr/local/bin/rdns-server -version &>/dev/null; then
  err "Binary rdns-server tidak valid atau gagal dijalankan pada arsitektur $ARCH."
  exit 1
fi
if ! /usr/local/bin/rdns-certs --help &>/dev/null && ! /usr/local/bin/rdns-certs -h &>/dev/null && ! /usr/local/bin/rdns-certs help &>/dev/null && ! /usr/local/bin/rdns-certs -help &>/dev/null; then
  err "Binary rdns-certs tidak valid atau gagal dijalankan pada arsitektur $ARCH."
  exit 1
fi

ok "Binary rdns-server & rdns-certs siap dan terpasang di /usr/local/bin"

# --- Generate CA & Server Certificates ---
if [[ ! -f /etc/rdns/ca.crt || ! -f /etc/rdns/ca.key ]]; then
  info "Membuat Root Certificate Authority (CA)..."
  /usr/local/bin/rdns-certs ca -name "rdns-ca-${PROFILE}" -out /etc/rdns
  chmod 600 /etc/rdns/ca.key
  chmod 644 /etc/rdns/ca.crt
  ok "CA dibuat: /etc/rdns/ca.crt"
else
  info "Menggunakan CA yang sudah ada: /etc/rdns/ca.crt"
fi

info "Membuat sertifikat Server untuk IP ${SERVER_IP}..."
server_args=(
  server
  -ca /etc/rdns/ca.crt
  -cakey /etc/rdns/ca.key
  -name "exit-${PROFILE}"
  -dns "exit-${PROFILE}.rdns,${SERVER_IP}"
  -ip "${SERVER_IP}"
  -out /etc/rdns/certs
)
/usr/local/bin/rdns-certs "${server_args[@]}"

chmod 600 "/etc/rdns/certs/exit-${PROFILE}.key"
chmod 644 "/etc/rdns/certs/exit-${PROFILE}.crt"
ok "Sertifikat server dibuat: /etc/rdns/certs/exit-${PROFILE}.crt"

# --- Generate /etc/rdns/server.yaml ---
cat > /etc/rdns/server.yaml <<EOF
listen:
  dns:    "0.0.0.0:${DNS_PORT}"
  tunnel: "0.0.0.0:${TUNNEL_PORT}"

tls:
  cert_file:  /etc/rdns/certs/exit-${PROFILE}.crt
  key_file:   /etc/rdns/certs/exit-${PROFILE}.key
  client_cas: /etc/rdns/ca.crt

acl:
  allowed:
    - 0.0.0.0/0
  rate_per_sec: 200
  burst: 400

dns:
  upstreams: [system]
  timeout: 3s

logging:
  level: info
  file: "/var/log/rdns-server.log"
EOF
chmod 644 /etc/rdns/server.yaml
ok "Konfigurasi dibuat: /etc/rdns/server.yaml"

# --- Install Service (systemd or openrc) ---
if command -v systemctl &>/dev/null; then
  cat > /etc/systemd/system/rdns-server.service <<EOF
[Unit]
Description=rdns-server (exit node: ACL DNS answer + mTLS yamux relay)
Documentation=https://github.com/risqinf/rdns
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rdns-server -config /etc/rdns/server.yaml
SyslogIdentifier=rdns-server
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/rdns /var/log /run
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536
Restart=always
RestartSec=5
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable rdns-server >/dev/null 2>&1 || true
  systemctl restart rdns-server
  ok "Service systemd rdns-server berhasil dijalankan."
elif command -v rc-service &>/dev/null; then
  cat > /etc/init.d/rdns-server <<'EOF'
#!/sbin/openrc-run
description="rdns-server (exit node: ACL DNS answer + mTLS yamux relay)"
command="/usr/local/bin/rdns-server"
command_args="-config /etc/rdns/server.yaml"
command_background=true
pidfile="/run/rdns-server.pid"

depend() {
    need net
}
EOF
  chmod 755 /etc/init.d/rdns-server
  rc-update add rdns-server default >/dev/null 2>&1 || true
  rc-service rdns-server restart
  ok "Service OpenRC rdns-server berhasil dijalankan."
fi

# --- Create CLI Helper: rdns-server-cli ---
cat > /usr/local/bin/rdns-server-cli <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG="/etc/rdns/server.yaml"
CA_KEY="/etc/rdns/ca.key"

case "${1:-}" in
  mint)
    prof="${2:-exit}"
    days="${3:-365}"
    if [[ ! -f "$CONFIG" ]]; then
      echo "Config file not found: $CONFIG" >&2
      exit 1
    fi
    /usr/local/bin/rdns-server -mint-token -config "$CONFIG" -cakey "$CA_KEY" -profile "$prof"
    ;;
  status)
    if command -v systemctl &>/dev/null; then
      systemctl status rdns-server
    elif command -v rc-service &>/dev/null; then
      rc-service rdns-server status
    fi
    ;;
  logs)
    if [[ -f /var/log/rdns-server.log ]]; then
      tail -f /var/log/rdns-server.log
    elif command -v journalctl &>/dev/null; then
      journalctl -u rdns-server -f
    fi
    ;;
  restart)
    if command -v systemctl &>/dev/null; then
      systemctl restart rdns-server
      echo "rdns-server restarted."
    elif command -v rc-service &>/dev/null; then
      rc-service rdns-server restart
    fi
    ;;
  *)
    echo "Usage: rdns-server-cli {mint [profile_name] [days]|status|logs|restart}"
    ;;
esac
EOF
chmod 755 /usr/local/bin/rdns-server-cli

# --- Mint First Client Token ---
token_args=(
  token
  -ca /etc/rdns/ca.crt
  -cakey /etc/rdns/ca.key
  -profile "$PROFILE"
  -server "${SERVER_IP}:${TUNNEL_PORT}"
  -server-name "exit-${PROFILE}.rdns"
  -dns "${SERVER_IP}:${DNS_PORT}"
)
PAIRING_TOKEN="$(/usr/local/bin/rdns-certs "${token_args[@]}")"

echo ""
ui_rule
echo -e " ${GREEN}INSTALLASI EXIT NODE BERHASIL!${NC}"
ui_rule
printf " ${WHITE}%-16s${NC} ${CYAN}:${NC} %b\n" "IP Server" "${SERVER_IP}"
printf " ${WHITE}%-16s${NC} ${CYAN}:${NC} %b\n" "Port Tunnel" "${TUNNEL_PORT}"
printf " ${WHITE}%-16s${NC} ${CYAN}:${NC} %b\n" "Port DNS" "${DNS_PORT}"
printf " ${WHITE}%-16s${NC} ${CYAN}:${NC} %b\n" "Profile Name" "${PROFILE}"
printf " ${WHITE}%-16s${NC} ${CYAN}:${NC} %b\n" "Server Helper" "rdns-server-cli"
ui_rule
echo -e " ${YELLOW}TOKEN PAIRING (Copy & Paste ke Client Autoscript):${NC}"
echo -e "${CYAN}${PAIRING_TOKEN}${NC}"
ui_rule
echo -e " ${WHITE}Perintah 1-Click di VPS Client (Autoscript Singapore / Decision Node):${NC}"
echo -e " ${PINK}rdns-manager pair \"${PAIRING_TOKEN}\"${NC}"
echo ""
echo -e " ${WHITE}Atau buka menu autoscript:${NC} ${GREEN}menu${NC} ➔ ${WHITE}Pilih Menu SmartDNS / RDNS${NC} ➔ ${WHITE}Pilih [1] Pair Exit Node Baru${NC}"
ui_rule
echo -e " ${WHITE}Jika ingin membuat token baru untuk client lain di kemudian hari:${NC}"
echo -e " ${CYAN}rdns-server-cli mint <nama_profil>${NC}"
ui_rule
