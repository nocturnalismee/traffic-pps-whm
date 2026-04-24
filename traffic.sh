#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#
#   ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
#      ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
#      ██║   ██████╔╝███████║█████╗  █████╗  ██║██║
#      ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║
#      ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
#      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝
#
#   Traffic Monitor & Analysis — for cPanel / WHM Edition
#   Version  : 1.2
#   Mode     : READ-ONLY  |  SAFETY FIRST
#   Purpose  : Real-time traffic analysis, PPS monitoring, connection insight,
#              and domain/source correlation for cPanel / WHM servers
#   Contributors : nocturnalismee <https://github.com/nocturnalismee>
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# CONFIGURATION — Tune these values to match your server environment
# -----------------------------------------------------------------------------
IFACE="eno1"          # Network interface  (check available: ip link show)
PPS_WARN=10000        # PPS warning threshold  (yellow)
PPS_CRIT=20000        # PPS critical threshold (red)
CONN_WARN=50          # Connections per IP warning
CONN_CRIT=100         # Connections per IP critical
REQ_WARN=5000         # HTTP requests per domain warning
REQ_CRIT=10000        # HTTP requests per domain critical
TOP_N=15              # Number of rows to display per section
LOG_TAIL=20000        # Lines to read from each domain log
REFRESH=15            # Screen refresh interval in seconds

# -----------------------------------------------------------------------------
# PATHS — Standard cPanel/WHM locations
# -----------------------------------------------------------------------------
DOMLOGS="/usr/local/apache/domlogs"
USERDOMAINS="/etc/userdomains"
DOMAINIPS="/etc/domainips"

# -----------------------------------------------------------------------------
# TERMINAL COLORS
# -----------------------------------------------------------------------------
C_RED='\033[0;31m'
C_YEL='\033[1;33m'
C_GRN='\033[0;32m'
C_CYN='\033[0;36m'
C_BLU='\033[0;34m'
C_MAG='\033[0;35m'
C_WHT='\033[1;37m'
C_DIM='\033[2m'
C_BLD='\033[1m'
C_RST='\033[0m'

# Colors kept for future customization.
: "${C_BLU}" "${C_MAG}"

# -----------------------------------------------------------------------------
# RUNTIME STATE — Cached data and validation metadata used during each refresh
# -----------------------------------------------------------------------------
TMPDIR_TMA=""
DOMAINIPS_MODE="unavailable"
DOMAINIPS_WARNING=""
SHUTDOWN_REQUESTED=0
NET_RX_PPS=0
NET_TX_PPS=0
NET_TOTAL_PPS=0
NET_RX_KB=0
NET_TX_KB=0

cleanup() {
  if [[ -n "$TMPDIR_TMA" && -d "$TMPDIR_TMA" ]]; then
    rm -rf "$TMPDIR_TMA"
  fi
}

request_shutdown() {
  SHUTDOWN_REQUESTED=1
  trap - INT TERM EXIT
  cleanup
  exit 130
}

trap cleanup EXIT
trap request_shutdown INT TERM

init_tmpdir() {
  TMPDIR_TMA=$(mktemp -d /tmp/tma_session_XXXXXX 2>/dev/null) || {
    echo "Failed to create temp directory" >&2
    exit 1
  }
}

# -----------------------------------------------------------------------------
# HELPERS — Shared utilities for rendering, parsing, validation, and caching
# -----------------------------------------------------------------------------
separator() {
  echo -e "${C_DIM}  ────────────────────────────────────────────────────────${C_RST}"
}

is_positive_integer() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

validate_config() {
  local ok=1

  if ! is_positive_integer "$REFRESH" || (( REFRESH < 2 )); then
    echo -e "  ${C_RED}✘${C_RST}  Invalid REFRESH      : ${C_RED}${REFRESH}${C_RST} (must be integer >= 2)"
    ok=0
  fi

  if ! is_positive_integer "$TOP_N"; then
    echo -e "  ${C_RED}✘${C_RST}  Invalid TOP_N        : ${C_RED}${TOP_N}${C_RST} (must be integer > 0)"
    ok=0
  fi

  if ! is_positive_integer "$LOG_TAIL"; then
    echo -e "  ${C_RED}✘${C_RST}  Invalid LOG_TAIL     : ${C_RED}${LOG_TAIL}${C_RST} (must be integer > 0)"
    ok=0
  fi

  if ! is_positive_integer "$PPS_WARN" || ! is_positive_integer "$PPS_CRIT" || (( PPS_WARN >= PPS_CRIT )); then
    echo -e "  ${C_RED}✘${C_RST}  Invalid PPS thresholds (warn must be < crit)"
    ok=0
  fi

  if ! is_positive_integer "$CONN_WARN" || ! is_positive_integer "$CONN_CRIT" || (( CONN_WARN >= CONN_CRIT )); then
    echo -e "  ${C_RED}✘${C_RST}  Invalid CONN thresholds (warn must be < crit)"
    ok=0
  fi

  if ! is_positive_integer "$REQ_WARN" || ! is_positive_integer "$REQ_CRIT" || (( REQ_WARN >= REQ_CRIT )); then
    echo -e "  ${C_RED}✘${C_RST}  Invalid REQ thresholds (warn must be < crit)"
    ok=0
  fi

  if (( ok == 0 )); then
    echo -e "\n  ${C_RED}Configuration validation failed. Fix CONFIGURATION values and rerun.${C_RST}\n"
    exit 1
  fi
}

resolve_owner() {
  local domain="$1"
  local owner
  [[ -f "$USERDOMAINS" ]] || { echo "n/a"; return; }
  owner=$(awk -v dom="$domain" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      if (match(line, /^[[:space:]]*([^:=[:space:]]+)[[:space:]]*[:=][[:space:]]*(.+)$/, m)) {
        key = trim(m[1])
        val = trim(m[2])
        if (key == dom) {
          print val
          exit
        }
      }
    }
  ' "$USERDOMAINS" 2>/dev/null)
  echo "${owner:-n/a}"
}

severity_badge() {
  local val="$1"
  local warn="$2"
  local crit="$3"

  if ! [[ "$val" =~ ^[0-9]+$ ]]; then
    printf '%b' "${C_GRN}● NORMAL  ${C_RST}"
    return
  fi

  if (( val > crit )); then
    printf '%b' "${C_RED}● CRITICAL${C_RST}"
  elif (( val > warn )); then
    printf '%b' "${C_YEL}● WARNING ${C_RST}"
  else
    printf '%b' "${C_GRN}● NORMAL  ${C_RST}"
  fi
}

logfiles_for_domain() {
  local domain="$1"
  local ssl="${DOMLOGS}/${domain}-ssl_log"
  local http="${DOMLOGS}/${domain}"

  [[ -f "$ssl" && -s "$ssl" ]] && printf '%s\n' "$ssl"
  [[ -f "$http" && -s "$http" ]] && printf '%s\n' "$http"
}

proto_tag() {
  local domain="$1"
  local ssl="${DOMLOGS}/${domain}-ssl_log"
  local http="${DOMLOGS}/${domain}"

  if [[ -f "$ssl" && -s "$ssl" && -f "$http" && -s "$http" ]]; then
    printf '%b' "${C_CYN}HTTP+HTTPS${C_RST}"
  elif [[ -f "$ssl" && -s "$ssl" ]]; then
    printf '%b' "${C_CYN}HTTPS${C_RST}"
  elif [[ -f "$http" && -s "$http" ]]; then
    printf '%b' "${C_YEL}HTTP ${C_RST}"
  else
    printf '%b' "${C_DIM}NONE ${C_RST}"
  fi
}

build_domain_list() {
  local cache_file="${TMPDIR_TMA}/domain_list"
  [[ -n "$TMPDIR_TMA" && -d "$TMPDIR_TMA" ]] || return
  : > "$cache_file"

  [[ -d "$DOMLOGS" ]] || return

  local entry basename
  for entry in "${DOMLOGS}"/*; do
    (( SHUTDOWN_REQUESTED == 1 )) && return
    [[ -f "$entry" ]] || continue
    basename="${entry##*/}"
    case "$basename" in
      *-ssl_log|*-bytes_log|*.offset|*.bkup|*-ftp_log|*.localhost) continue ;;
    esac
    printf '%s\n' "$basename" >> "$cache_file"
  done
}

cache_ss_output() {
  ss -ntu state established 2>/dev/null > "${TMPDIR_TMA}/ss_output"
}

sample_network() {
  local sys="/sys/class/net/${IFACE}/statistics"
  local rx1 tx1 rxb1 txb1 rx2 tx2 rxb2 txb2

  rx1=$(cat "${sys}/rx_packets" 2>/dev/null) || rx1=0
  tx1=$(cat "${sys}/tx_packets" 2>/dev/null) || tx1=0
  rxb1=$(cat "${sys}/rx_bytes" 2>/dev/null) || rxb1=0
  txb1=$(cat "${sys}/tx_bytes" 2>/dev/null) || txb1=0

  sleep 1

  rx2=$(cat "${sys}/rx_packets" 2>/dev/null) || rx2=0
  tx2=$(cat "${sys}/tx_packets" 2>/dev/null) || tx2=0
  rxb2=$(cat "${sys}/rx_bytes" 2>/dev/null) || rxb2=0
  txb2=$(cat "${sys}/tx_bytes" 2>/dev/null) || txb2=0

  NET_RX_PPS=$(( rx2 - rx1 ))
  NET_TX_PPS=$(( tx2 - tx1 ))
  NET_TOTAL_PPS=$(( NET_RX_PPS + NET_TX_PPS ))
  NET_RX_KB=$(( (rxb2 - rxb1) / 1024 ))
  NET_TX_KB=$(( (txb2 - txb1) / 1024 ))
}

cache_log_data() {
  local cache_file="${TMPDIR_TMA}/log_data"
  local domain_counts="${TMPDIR_TMA}/domain_counts"
  local domain_list="${TMPDIR_TMA}/domain_list"
  local tail_tmp="${TMPDIR_TMA}/_tail_tmp"

  [[ -n "$TMPDIR_TMA" && -d "$TMPDIR_TMA" ]] || return
  : > "$cache_file"
  : > "$domain_counts"
  [[ -s "$domain_list" ]] || return

  local domain logfile lc
  while IFS= read -r domain; do
    (( SHUTDOWN_REQUESTED == 1 )) && return
    lc=0
    : > "$tail_tmp"

    while IFS= read -r logfile; do
      [[ -n "$logfile" && -r "$logfile" ]] || continue
      tail -n "$LOG_TAIL" "$logfile" 2>/dev/null >> "$tail_tmp"
    done < <(logfiles_for_domain "$domain")

    lc=$(wc -l < "$tail_tmp" 2>/dev/null)
    lc=${lc// /}

    if [[ -n "$lc" && "$lc" -gt 0 ]] 2>/dev/null; then
      printf "%d %s\n" "$lc" "$domain" >> "$domain_counts"
      awk -v dom="$domain" '
        $1 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $1 ~ /^[0-9A-Fa-f:]+$/ {
          print $1, dom
        }
      ' "$tail_tmp" >> "$cache_file"
    fi
  done < "$domain_list"

  rm -f "$tail_tmp"
}

parse_ss_ips() {
  local field="$1"
  local ss_file="${TMPDIR_TMA}/ss_output"

  awk -v fld="$field" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function extract_host(addr,   host, rest, n, parts, i) {
      addr = trim(addr)
      if (addr == "" || addr == "*" || addr == "*:*") return ""

      if (addr ~ /^\[/) {
        if (match(addr, /^\[([^]]+)\](:.*)?$/, m)) {
          return m[1]
        }
      }

      if (match(addr, /^(.*):([^:]*)$/, m)) {
        host = m[1]
      } else {
        host = addr
      }

      host = trim(host)
      if (host == "" || host == "*" || host == "0.0.0.0" || host == "::") return ""
      return host
    }
    NR > 1 {
      host = extract_host($fld)
      if (host != "") {
        print host
      }
    }
  ' "$ss_file" 2>/dev/null
}

detect_domainips_mode() {
  DOMAINIPS_MODE="unavailable"
  DOMAINIPS_WARNING=""

  [[ -f "$DOMAINIPS" ]] || return

  local sample
  sample=$(awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    { print; exit }
  ' "$DOMAINIPS" 2>/dev/null)

  [[ -n "$sample" ]] || {
    DOMAINIPS_MODE="empty"
    DOMAINIPS_WARNING="no usable entries found"
    return
  }

  if awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function is_ipv4(s) {
      return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/
    }
    function parse_pair(line,   m) {
      if (match(line, /^([^:=[:space:]]+)[[:space:]]*[:=][[:space:]]*([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      if (match(line, /^([^[:space:]]+)[[:space:]]+([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      return 0
    }
    BEGIN { ok = 1 }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = trim($0)
      if (!parse_pair(line) || !is_ipv4(first)) { ok = 0; exit }
    }
    END { exit ok ? 0 : 1 }
  ' "$DOMAINIPS" 2>/dev/null; then
    DOMAINIPS_MODE="ip-first"
    return
  fi

  if awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function is_ipv4(s) {
      return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/
    }
    function parse_pair(line,   m) {
      if (match(line, /^([^:=[:space:]]+)[[:space:]]*[:=][[:space:]]*([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      if (match(line, /^([^[:space:]]+)[[:space:]]+([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      return 0
    }
    BEGIN { ok = 1 }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = trim($0)
      if (!parse_pair(line) || !is_ipv4(second)) { ok = 0; exit }
    }
    END { exit ok ? 0 : 1 }
  ' "$DOMAINIPS" 2>/dev/null; then
    DOMAINIPS_MODE="domain-first"
    return
  fi

  DOMAINIPS_MODE="unknown"
  DOMAINIPS_WARNING="unsupported format detected"
}

# -----------------------------------------------------------------------------
# STARTUP — Validate configuration and environment before entering the monitor loop
# -----------------------------------------------------------------------------
validate_environment() {
  local ok=1

  echo -e "\n${C_BLD}${C_WHT}  Validating environment...${C_RST}\n"

  validate_config
  detect_domainips_mode

  if [[ -f "/sys/class/net/${IFACE}/statistics/rx_packets" ]]; then
    echo -e "  ${C_GRN}✔${C_RST}  Network interface  : ${C_BLD}${IFACE}${C_RST}"
  else
    echo -e "  ${C_RED}✘${C_RST}  Network interface  : ${C_RED}${IFACE} not found${C_RST}"
    echo -e "     Available interfaces: $(ls /sys/class/net/ 2>/dev/null | tr '\n' ' ')"
    echo -e "     ${C_DIM}Update IFACE in the CONFIGURATION section.${C_RST}"
    ok=0
  fi

  if [[ -d "$DOMLOGS" ]]; then
    local dom_count=0 ssl_count=0 entry bname
    for entry in "${DOMLOGS}"/*; do
      [[ -f "$entry" ]] || continue
      bname="${entry##*/}"
      case "$bname" in
        *-ssl_log) (( ssl_count++ )) ;;
        *-bytes_log|*.offset|*.bkup) ;;
        *) (( dom_count++ )) ;;
      esac
    done
    echo -e "  ${C_GRN}✔${C_RST}  Domain logs        : ${C_BLD}${dom_count}${C_RST} domains  (${ssl_count} with SSL log)"
  else
    echo -e "  ${C_RED}✘${C_RST}  Domain logs        : ${C_RED}${DOMLOGS} not found${C_RST}"
    ok=0
  fi

  if [[ -f "$USERDOMAINS" ]]; then
    local map_count
    map_count=$(wc -l < "$USERDOMAINS" 2>/dev/null)
    echo -e "  ${C_GRN}✔${C_RST}  Domain map         : ${C_BLD}${map_count}${C_RST} entries in ${USERDOMAINS}"
  else
    echo -e "  ${C_YEL}!${C_RST}  Domain map         : ${C_YEL}${USERDOMAINS} not found — owner lookup disabled${C_RST}"
  fi

  if [[ -f "$DOMAINIPS" ]]; then
    local ip_count
    ip_count=$(wc -l < "$DOMAINIPS" 2>/dev/null)
    case "$DOMAINIPS_MODE" in
      ip-first)
        echo -e "  ${C_GRN}✔${C_RST}  Dedicated IPs      : ${C_BLD}${ip_count}${C_RST} entries in ${DOMAINIPS} (ip-first format)"
        ;;
      domain-first)
        echo -e "  ${C_GRN}✔${C_RST}  Dedicated IPs      : ${C_BLD}${ip_count}${C_RST} entries in ${DOMAINIPS} (domain-first format)"
        ;;
      *)
        echo -e "  ${C_YEL}!${C_RST}  Dedicated IPs      : ${C_YEL}${DOMAINIPS}${C_RST} ${DOMAINIPS_WARNING:-format could not be validated}"
        ;;
    esac
  else
    echo -e "  ${C_YEL}!${C_RST}  Dedicated IPs      : ${C_YEL}${DOMAINIPS} not found — dedicated IP section disabled${C_RST}"
  fi

  echo ""

  if [[ "$ok" -eq 0 ]]; then
    echo -e "  ${C_RED}One or more critical checks failed.${C_RST}"
    echo -e "  Press ${C_BLD}Enter${C_RST} to continue anyway, or ${C_BLD}Ctrl+C${C_RST} to abort.\n"
    read -r
  else
    echo -e "  ${C_GRN}All checks passed.${C_RST} Starting monitor in 2 seconds...\n"
    sleep 2
  fi
}

# -----------------------------------------------------------------------------
# SECTION: PPS — Packets Per Second (1-second sampled snapshot)
# -----------------------------------------------------------------------------
section_pps() {
  local badge
  badge=$(severity_badge "$NET_RX_PPS" "$PPS_WARN" "$PPS_CRIT")

  printf "  ${C_DIM}%-18s${C_RST}  %s pps   %b\n" "RX  (inbound)" "$NET_RX_PPS" "$badge"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n" "TX  (outbound)" "$NET_TX_PPS"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n" "Total" "$NET_TOTAL_PPS"
  printf "  ${C_DIM}%-18s${C_RST}  warn=${C_YEL}%s${C_RST}  crit=${C_RED}%s${C_RST}\n" \
    "Thresholds" "${PPS_WARN} pps" "${PPS_CRIT} pps"
}

# -----------------------------------------------------------------------------
# SECTION: Bandwidth — Throughput in KB/s (same 1-second sample window)
# -----------------------------------------------------------------------------
section_bandwidth() {
  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Download (RX)" "$NET_RX_KB"
  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Upload   (TX)" "$NET_TX_KB"
}

# -----------------------------------------------------------------------------
# SECTION: Top domains by request count (aggregated from cached domlog reads)
# -----------------------------------------------------------------------------
section_top_domains() {
  local domain_counts="${TMPDIR_TMA}/domain_counts"

  if [[ -s "$domain_counts" ]]; then
    sort -rn "$domain_counts" | head -n "$TOP_N" | \
      while read -r count domain; do
        local owner proto badge
        owner=$(resolve_owner "$domain")
        [[ -n "$owner" ]] || owner="n/a"
        proto=$(proto_tag "$domain")
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  [%b]  %-38s  owner: %-14s  %b\n" \
          "$count" "$proto" "$domain" "$owner" "$badge"
      done
  else
    echo -e "  ${C_DIM}No domain log data available.${C_RST}"
  fi
}

# -----------------------------------------------------------------------------
# SECTION: Active connections per peer IP (live, from cached ss output)
# -----------------------------------------------------------------------------
section_active_connections() {
  local result
  result=$(parse_ss_ips 5 | \
    grep -Ev '^$|^127\.|^::1$|^\*$' | \
    sort | uniq -c | sort -rn | head -n "$TOP_N")

  if [[ -n "$result" ]]; then
    echo "$result" | \
      while read -r count ip; do
        local badge
        badge=$(severity_badge "$count" "$CONN_WARN" "$CONN_CRIT")
        printf "  %6s conn  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No active connections detected.${C_RST}"
  fi
}

# -----------------------------------------------------------------------------
# SECTION: Top source IPs aggregated across all cached domain log samples
# -----------------------------------------------------------------------------
section_top_ips_global() {
  local log_data="${TMPDIR_TMA}/log_data"

  if [[ -s "$log_data" ]]; then
    awk '{print $1}' "$log_data" | sort | uniq -c | sort -rn | head -n "$TOP_N" | \
      while read -r count ip; do
        local badge
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi
}

# -----------------------------------------------------------------------------
# SECTION: Source IP → target domain correlation
# -----------------------------------------------------------------------------
section_ip_to_domain() {
  local log_data="${TMPDIR_TMA}/log_data"

  if [[ -s "$log_data" ]]; then
    sort "$log_data" | uniq -c | sort -rn | head -n "$TOP_N" | \
      while read -r count ip domain; do
        local owner
        owner=$(resolve_owner "$domain")
        [[ -n "$owner" ]] || owner="n/a"
        printf "  %9s req  %-28s  →  %-34s  owner: %s\n" \
          "$count" "$ip" "$domain" "$owner"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi
}

# -----------------------------------------------------------------------------
# SECTION: Dedicated IP connection activity derived from live socket data
# -----------------------------------------------------------------------------
section_dedicated_ips() {
  if [[ ! -f "$DOMAINIPS" ]]; then
    echo -e "  ${C_DIM}${DOMAINIPS} not found — section unavailable.${C_RST}"
    return
  fi

  if [[ "$DOMAINIPS_MODE" == "unknown" || "$DOMAINIPS_MODE" == "empty" || "$DOMAINIPS_MODE" == "unavailable" ]]; then
    echo -e "  ${C_YEL}${DOMAINIPS} skipped — ${DOMAINIPS_WARNING:-format unavailable}.${C_RST}"
    return
  fi

  local found=0
  local pairs
  local local_ips
  pairs=$(awk -v mode="$DOMAINIPS_MODE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function parse_pair(line,   m) {
      if (match(line, /^([^:=[:space:]]+)[[:space:]]*[:=][[:space:]]*([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      if (match(line, /^([^[:space:]]+)[[:space:]]+([^[:space:]]+)$/, m)) {
        first = trim(m[1]); second = trim(m[2]); return 1
      }
      return 0
    }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = trim($0)
      if (!parse_pair(line)) next
    }
    mode == "ip-first" {
      print first, second
      next
    }
    mode == "domain-first" {
      print second, first
    }
  ' "$DOMAINIPS" 2>/dev/null | sort -u)

  if [[ -z "$pairs" ]]; then
    echo -e "  ${C_DIM}No dedicated IP entries matched the detected format.${C_RST}"
    return
  fi

  local_ips=$(parse_ss_ips 5)

  while read -r ded_ip ded_label; do
    local conn_count badge owner
    [[ -n "$ded_ip" ]] || continue

    conn_count=$(printf '%s\n' "$local_ips" | awk -v ip="$ded_ip" '$0 == ip { c++ } END { print c + 0 }')
    if (( conn_count > 0 )); then
      badge=$(severity_badge "$conn_count" "$CONN_WARN" "$CONN_CRIT")
      owner=$(resolve_owner "$ded_label")
      [[ -n "$owner" ]] || owner="$ded_label"
      printf "  %6s conn  %-24s  label: %-16s  %b\n" \
        "$conn_count" "$ded_ip" "$owner" "$badge"
      found=1
    fi
  done <<< "$pairs"

  [[ "$found" -eq 0 ]] && \
    echo -e "  ${C_DIM}No active connections to dedicated IPs at this time.${C_RST}"
}

# -----------------------------------------------------------------------------
# SECTION: Server summary and quick capacity snapshot
# -----------------------------------------------------------------------------
section_summary() {
  local total_conn load_avg mem_info uptime_str dom_count ssl_count entry

  total_conn=$(awk 'NR>1' "${TMPDIR_TMA}/ss_output" 2>/dev/null | wc -l)
  load_avg=$(awk '{print $1"  "$2"  "$3}' /proc/loadavg 2>/dev/null)
  mem_info=$(free -m 2>/dev/null | \
    awk 'NR==2{ printf "used %s MB / total %s MB  (%.0f%%)", $3, $2, $3/$2*100 }')
  uptime_str=$(uptime -p 2>/dev/null || uptime)
  dom_count=$(wc -l < "${TMPDIR_TMA}/domain_list" 2>/dev/null)
  ssl_count=0

  for entry in "${DOMLOGS}"/*-ssl_log; do
    [[ -f "$entry" ]] && (( ssl_count++ ))
  done

  printf "  ${C_DIM}%-22s${C_RST}  %s\n" "Active connections" "$total_conn"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n" "Load average (1/5/15)" "$load_avg"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n" "Memory" "$mem_info"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n" "Uptime" "$uptime_str"
  printf "  ${C_DIM}%-22s${C_RST}  %s domains  (%s with SSL log)\n" \
    "Hosted domains" "$dom_count" "$ssl_count"
}

# -----------------------------------------------------------------------------
# RENDER — Collect fresh data, then draw the full-screen dashboard
# -----------------------------------------------------------------------------
draw_screen() {
  local ts
  ts=$(date '+%Y-%m-%d  %H:%M:%S')

  sample_network
  cache_ss_output
  build_domain_list
  cache_log_data

  clear

  echo -e "${C_BLD}${C_WHT}  Traffic Monitor Analysis${C_RST}  ${C_DIM}cPanel / WHM v1.2${C_RST}"
  printf  "  ${C_DIM}%s${C_RST}  |  interface: ${C_BLD}%s${C_RST}\n" "${ts}" "${IFACE}"
  separator

  echo -e "  ${C_BLD}${C_CYN}▸  PACKETS PER SECOND${C_RST}  ${C_DIM}(1-second live sample)${C_RST}"
  separator
  section_pps
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  BANDWIDTH${C_RST}  ${C_DIM}(1-second live sample)${C_RST}"
  separator
  section_bandwidth
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP DOMAINS BY REQUEST COUNT${C_RST}  ${C_DIM}(http + https aggregated)${C_RST}"
  separator
  section_top_domains
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  ACTIVE CONNECTIONS PER IP${C_RST}  ${C_DIM}(live via ss)${C_RST}"
  separator
  section_active_connections
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP SOURCE IPs  —  ALL DOMAINS${C_RST}  ${C_DIM}(aggregated from domlogs)${C_RST}"
  separator
  section_top_ips_global
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  SOURCE IP  →  TARGET DOMAIN${C_RST}  ${C_DIM}(attack vector mapping)${C_RST}"
  separator
  section_ip_to_domain
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  DEDICATED IP  —  CONNECTION ACTIVITY${C_RST}"
  separator
  section_dedicated_ips
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  SERVER SUMMARY${C_RST}"
  separator
  section_summary
  echo ""

  separator
  printf "  ${C_DIM}Refreshing in %s seconds   |   Press Ctrl+C to exit${C_RST}\n" \
    "$((REFRESH - 1))"
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================
clear
echo ""
echo -e "${C_BLD}${C_WHT}  Traffic Monitor Analysis${C_RST}  ${C_DIM}cPanel / WHM v1.2${C_RST}"
separator

validate_environment
init_tmpdir

while true; do
  draw_screen
  sleep $(( REFRESH - 1 ))
done
