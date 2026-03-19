#!/bin/bash
# =============================================================================
#
#   ████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗
#      ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝
#      ██║   ██████╔╝███████║█████╗  █████╗  ██║██║
#      ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║
#      ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╗
#      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝
#
#   Traffic Monitor & Analysis — for cPanel / WHM Edition
#   Version  : 1.0
#   Mode     : READ-ONLY  |  SAFETY FIRST
#   Purpose  : Real-time traffic analysis, PPS monitoring, domain mapping
#   Contributors : nocturnalismee <https://github.com/nocturnalismee>
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION — Adjust to match your server environment
# -----------------------------------------------------------------------------
IFACE="eth0"          # Network interface  (check available: ip link show)
PPS_WARN=10000        # PPS warning threshold  (yellow)
PPS_CRIT=20000        # PPS critical threshold (red)
CONN_WARN=50          # Connections per IP warning
CONN_CRIT=100         # Connections per IP critical
REQ_WARN=5000         # HTTP requests per domain warning
REQ_CRIT=10000        # HTTP requests per domain critical
TOP_N=15              # Number of rows to display per section
LOG_TAIL=50000        # Lines to read from each domain log
REFRESH=5             # Screen refresh interval in seconds

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

# -----------------------------------------------------------------------------
# HELPER: Print a horizontal separator line
# -----------------------------------------------------------------------------
separator() {
  echo -e "${C_DIM}  ────────────────────────────────────────────────────────${C_RST}"
}

# -----------------------------------------------------------------------------
# HELPER: Resolve domain owner from /etc/userdomains
# -----------------------------------------------------------------------------
resolve_owner() {
  local domain="$1"
  [ -f "$USERDOMAINS" ] || { echo "n/a"; return; }
  local owner
  owner=$(grep "^${domain}=" "$USERDOMAINS" 2>/dev/null | head -1 | cut -d= -f2)
  echo "${owner:-n/a}"
}

# -----------------------------------------------------------------------------
# HELPER: Return severity badge based on value vs thresholds
# -----------------------------------------------------------------------------
severity_badge() {
  local val="$1"
  local warn="$2"
  local crit="$3"
  if [ "$val" -gt "$crit" ] 2>/dev/null; then
    printf "${C_RED}● CRITICAL${C_RST}"
  elif [ "$val" -gt "$warn" ] 2>/dev/null; then
    printf "${C_YEL}● WARNING ${C_RST}"
  else
    printf "${C_GRN}● NORMAL  ${C_RST}"
  fi
}

# -----------------------------------------------------------------------------
# HELPER: Select best available log file for a domain
#   Priority: ssl_log (HTTPS) → plain HTTP log → none
# -----------------------------------------------------------------------------
best_logfile() {
  local domain="$1"
  local ssl="${DOMLOGS}/${domain}-ssl_log"
  local http="${DOMLOGS}/${domain}"
  if   [ -f "$ssl"  ] && [ -s "$ssl"  ]; then echo "$ssl"
  elif [ -f "$http" ] && [ -s "$http" ]; then echo "$http"
  else echo ""
  fi
}

# -----------------------------------------------------------------------------
# HELPER: Protocol tag based on log file path
# -----------------------------------------------------------------------------
proto_tag() {
  local logfile="$1"
  case "$logfile" in
    *-ssl_log) printf "${C_CYN}HTTPS${C_RST}" ;;
    *)         printf "${C_YEL}HTTP ${C_RST}" ;;
  esac
}

# -----------------------------------------------------------------------------
# STARTUP: Validate environment before entering the monitor loop
# -----------------------------------------------------------------------------
validate_environment() {
  local ok=1

  echo -e "\n${C_BLD}${C_WHT}  Validating environment...${C_RST}\n"

  # Check network interface
  if [ -f "/sys/class/net/${IFACE}/statistics/rx_packets" ]; then
    echo -e "  ${C_GRN}✔${C_RST}  Network interface  : ${C_BLD}${IFACE}${C_RST}"
  else
    echo -e "  ${C_RED}✘${C_RST}  Network interface  : ${C_RED}${IFACE} not found${C_RST}"
    echo -e "     Available interfaces: $(ls /sys/class/net/ 2>/dev/null | tr '\n' ' ')"
    echo -e "     ${C_DIM}Update IFACE in the CONFIGURATION section.${C_RST}"
    ok=0
  fi

  # Check domlogs directory
  if [ -d "$DOMLOGS" ]; then
    local dom_count
    dom_count=$(ls "$DOMLOGS" 2>/dev/null | \
      grep -Ev '\-ssl_log$|\-bytes_log|\.offset|\.bkup' | wc -l)
    local ssl_count
    ssl_count=$(ls "$DOMLOGS" 2>/dev/null | grep -c '\-ssl_log$' || echo 0)
    echo -e "  ${C_GRN}✔${C_RST}  Domain logs        : ${C_BLD}${dom_count}${C_RST} domains  (${ssl_count} with SSL log)"
  else
    echo -e "  ${C_RED}✘${C_RST}  Domain logs        : ${C_RED}${DOMLOGS} not found${C_RST}"
    ok=0
  fi

  # Check userdomains mapping
  if [ -f "$USERDOMAINS" ]; then
    local map_count
    map_count=$(wc -l < "$USERDOMAINS" 2>/dev/null || echo 0)
    echo -e "  ${C_GRN}✔${C_RST}  Domain map         : ${C_BLD}${map_count}${C_RST} entries in ${USERDOMAINS}"
  else
    echo -e "  ${C_YEL}!${C_RST}  Domain map         : ${C_YEL}${USERDOMAINS} not found — owner lookup disabled${C_RST}"
  fi

  # Check dedicated IP file
  if [ -f "$DOMAINIPS" ]; then
    local ip_count
    ip_count=$(wc -l < "$DOMAINIPS" 2>/dev/null || echo 0)
    echo -e "  ${C_GRN}✔${C_RST}  Dedicated IPs      : ${C_BLD}${ip_count}${C_RST} entries in ${DOMAINIPS}"
  else
    echo -e "  ${C_YEL}!${C_RST}  Dedicated IPs      : ${C_YEL}${DOMAINIPS} not found — dedicated IP section disabled${C_RST}"
  fi

  echo ""

  if [ "$ok" -eq 0 ]; then
    echo -e "  ${C_RED}One or more critical checks failed.${C_RST}"
    echo -e "  Press ${C_BLD}Enter${C_RST} to continue anyway, or ${C_BLD}Ctrl+C${C_RST} to abort.\n"
    read -r
  else
    echo -e "  ${C_GRN}All checks passed.${C_RST} Starting monitor in 2 seconds...\n"
    sleep 2
  fi
}

# -----------------------------------------------------------------------------
# SECTION: PPS — Packets Per Second (1-second sample)
# -----------------------------------------------------------------------------
section_pps() {
  local rx1 tx1 rx2 tx2
  rx1=$(cat /sys/class/net/"${IFACE}"/statistics/rx_packets 2>/dev/null || echo 0)
  tx1=$(cat /sys/class/net/"${IFACE}"/statistics/tx_packets 2>/dev/null || echo 0)
  sleep 1
  rx2=$(cat /sys/class/net/"${IFACE}"/statistics/rx_packets 2>/dev/null || echo 0)
  tx2=$(cat /sys/class/net/"${IFACE}"/statistics/tx_packets 2>/dev/null || echo 0)

  local rx_pps tx_pps total_pps
  rx_pps=$(( rx2 - rx1 ))
  tx_pps=$(( tx2 - tx1 ))
  total_pps=$(( rx_pps + tx_pps ))

  local badge
  badge=$(severity_badge "$rx_pps" "$PPS_WARN" "$PPS_CRIT")

  printf "  ${C_DIM}%-18s${C_RST}  %s pps   %b\n" "RX  (inbound)"  "$rx_pps"    "$badge"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n"       "TX  (outbound)" "$tx_pps"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n"       "Total"          "$total_pps"
  printf "  ${C_DIM}%-18s${C_RST}  warn=${C_YEL}%s${C_RST}  crit=${C_RED}%s${C_RST}\n" \
    "Thresholds" "${PPS_WARN} pps" "${PPS_CRIT} pps"
}

# -----------------------------------------------------------------------------
# SECTION: Bandwidth — bytes/sec (1-second sample)
# -----------------------------------------------------------------------------
section_bandwidth() {
  local rxb1 txb1 rxb2 txb2
  rxb1=$(cat /sys/class/net/"${IFACE}"/statistics/rx_bytes 2>/dev/null || echo 0)
  txb1=$(cat /sys/class/net/"${IFACE}"/statistics/tx_bytes 2>/dev/null || echo 0)
  sleep 1
  rxb2=$(cat /sys/class/net/"${IFACE}"/statistics/rx_bytes 2>/dev/null || echo 0)
  txb2=$(cat /sys/class/net/"${IFACE}"/statistics/tx_bytes 2>/dev/null || echo 0)

  local rx_kb tx_kb
  rx_kb=$(( (rxb2 - rxb1) / 1024 ))
  tx_kb=$(( (txb2 - txb1) / 1024 ))

  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Download (RX)" "$rx_kb"
  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Upload   (TX)" "$tx_kb"
}

# -----------------------------------------------------------------------------
# SECTION: Top domains by request count (reads domlogs)
# -----------------------------------------------------------------------------
section_top_domains() {
  local tmpfile
  tmpfile=$(mktemp /tmp/tma_domains_XXXXXX 2>/dev/null) || return

  ls "$DOMLOGS" 2>/dev/null | \
    grep -Ev '\-ssl_log$|\-bytes_log|\.offset|\.bkup' | \
    while read -r domain; do
      local logfile
      logfile=$(best_logfile "$domain")
      [ -z "$logfile" ] && continue
      [ -r "$logfile" ]  || continue
      local count
      count=$(tail -n "$LOG_TAIL" "$logfile" 2>/dev/null | wc -l)
      [ "$count" -gt 0 ] && printf "%d %s\n" "$count" "$domain"
    done | sort -rn > "$tmpfile"

  if [ -s "$tmpfile" ]; then
    head -n "$TOP_N" "$tmpfile" | \
      while read -r count domain; do
        local owner proto logfile badge
        owner=$(resolve_owner "$domain")
        logfile=$(best_logfile "$domain")
        proto=$(proto_tag "$logfile")
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  [%b]  %-38s  owner: %-14s  %b\n" \
          "$count" "$proto" "$domain" "$owner" "$badge"
      done
  else
    echo -e "  ${C_DIM}No domain log data available.${C_RST}"
  fi

  rm -f "$tmpfile"
}

# -----------------------------------------------------------------------------
# SECTION: Active connections per IP (live, from ss)
# -----------------------------------------------------------------------------
section_active_connections() {
  local result
  result=$(ss -ntu state established 2>/dev/null | \
    awk 'NR>1 {print $6}' | \
    cut -d: -f1 | \
    grep -Ev '^$|^:|^127\.|^::1$|^\*$' | \
    sort | uniq -c | sort -rn | head -n "$TOP_N")

  if [ -n "$result" ]; then
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
# SECTION: Top source IPs aggregated across all domain logs
# -----------------------------------------------------------------------------
section_top_ips_global() {
  local tmpfile
  tmpfile=$(mktemp /tmp/tma_ipglob_XXXXXX 2>/dev/null) || return

  ls "$DOMLOGS" 2>/dev/null | \
    grep -Ev '\-ssl_log$|\-bytes_log|\.offset|\.bkup' | \
    while read -r domain; do
      local logfile
      logfile=$(best_logfile "$domain")
      [ -z "$logfile" ] && continue
      [ -r "$logfile" ]  || continue
      tail -n "$LOG_TAIL" "$logfile" 2>/dev/null | awk '{print $1}'
    done >> "$tmpfile"

  if [ -s "$tmpfile" ]; then
    sort "$tmpfile" | uniq -c | sort -rn | head -n "$TOP_N" | \
      while read -r count ip; do
        local badge
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi

  rm -f "$tmpfile"
}

# -----------------------------------------------------------------------------
# SECTION: Source IP → target domain mapping
# -----------------------------------------------------------------------------
section_ip_to_domain() {
  local tmpfile
  tmpfile=$(mktemp /tmp/tma_ip2dom_XXXXXX 2>/dev/null) || return

  ls "$DOMLOGS" 2>/dev/null | \
    grep -Ev '\-ssl_log$|\-bytes_log|\.offset|\.bkup' | \
    while read -r domain; do
      local logfile
      logfile=$(best_logfile "$domain")
      [ -z "$logfile" ] && continue
      [ -r "$logfile" ]  || continue
      tail -n "$LOG_TAIL" "$logfile" 2>/dev/null | \
        awk -v dom="$domain" '{print $1, dom}'
    done >> "$tmpfile"

  if [ -s "$tmpfile" ]; then
    sort "$tmpfile" | uniq -c | sort -rn | head -n "$TOP_N" | \
      while read -r count ip domain; do
        local owner
        owner=$(resolve_owner "$domain")
        printf "  %9s req  %-28s  →  %-34s  owner: %s\n" \
          "$count" "$ip" "$domain" "$owner"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi

  rm -f "$tmpfile"
}

# -----------------------------------------------------------------------------
# SECTION: Dedicated IP connection activity
# -----------------------------------------------------------------------------
section_dedicated_ips() {
  [ -f "$DOMAINIPS" ] || {
    echo -e "  ${C_DIM}${DOMAINIPS} not found — section unavailable.${C_RST}"
    return
  }

  local found=0
  while read -r entry; do
    local ded_ip ded_acct conn_count badge
    ded_ip=$(echo "$entry" | awk '{print $1}')
    ded_acct=$(echo "$entry" | awk '{print $2}')
    [ -z "$ded_ip" ] && continue

    conn_count=$(ss -ntu state established 2>/dev/null | \
      awk '{print $5}' | cut -d: -f1 | \
      grep -c "^${ded_ip}$" 2>/dev/null || echo 0)

    if [ "$conn_count" -gt 0 ]; then
      badge=$(severity_badge "$conn_count" "$CONN_WARN" "$CONN_CRIT")
      printf "  %6s conn  %-24s  account: %-16s  %b\n" \
        "$conn_count" "$ded_ip" "$ded_acct" "$badge"
      found=1
    fi
  done < "$DOMAINIPS"

  [ "$found" -eq 0 ] && \
    echo -e "  ${C_DIM}No active connections to dedicated IPs at this time.${C_RST}"
}

# -----------------------------------------------------------------------------
# SECTION: Server summary
# -----------------------------------------------------------------------------
section_summary() {
  local total_conn load_avg mem_info uptime_str dom_count ssl_count

  total_conn=$(ss -ntu state established 2>/dev/null | awk 'NR>1' | wc -l)
  load_avg=$(awk '{print $1"  "$2"  "$3}' /proc/loadavg 2>/dev/null)
  mem_info=$(free -m 2>/dev/null | \
    awk 'NR==2{ printf "used %s MB / total %s MB  (%.0f%%)", $3, $2, $3/$2*100 }')
  uptime_str=$(uptime -p 2>/dev/null || uptime)
  dom_count=$(ls "$DOMLOGS" 2>/dev/null | \
    grep -Ev '\-ssl_log$|\-bytes_log|\.offset|\.bkup' | wc -l)
  ssl_count=$(ls "$DOMLOGS" 2>/dev/null | grep -c '\-ssl_log$' || echo 0)

  printf "  ${C_DIM}%-22s${C_RST}  %s\n"   "Active connections"    "$total_conn"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n"   "Load average (1/5/15)" "$load_avg"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n"   "Memory"                "$mem_info"
  printf "  ${C_DIM}%-22s${C_RST}  %s\n"   "Uptime"                "$uptime_str"
  printf "  ${C_DIM}%-22s${C_RST}  %s domains  (%s with SSL log)\n" \
    "Hosted domains" "$dom_count" "$ssl_count"
}

# -----------------------------------------------------------------------------
# RENDER: Full screen draw
# -----------------------------------------------------------------------------
draw_screen() {
  local ts
  ts=$(date '+%Y-%m-%d  %H:%M:%S')

  clear

  # ── Header ────────────────────────────────────────────────────────────────
  echo -e "${C_BLD}${C_WHT}"
  echo    "  ╔══════════════════════════════════════════════════════════════════╗"
  echo    "  ║        T R A F F I C   M O N I T O R   A N A L Y S I S         ║"
  echo    "  ║                   cPanel / WHM  Edition  v3.0                   ║"
  printf  "  ║  %-66s  ║\n" "${ts}   |   interface: ${IFACE}"
  echo    "  ╚══════════════════════════════════════════════════════════════════╝"
  echo -e "${C_RST}"

  # ── Section 1: PPS ────────────────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  PACKETS PER SECOND${C_RST}  ${C_DIM}(1-second live sample)${C_RST}"
  separator
  section_pps
  echo ""

  # ── Section 2: Bandwidth ──────────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  BANDWIDTH${C_RST}  ${C_DIM}(1-second live sample)${C_RST}"
  separator
  section_bandwidth
  echo ""

  # ── Section 3: Top Domains ────────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  TOP DOMAINS BY REQUEST COUNT${C_RST}  ${C_DIM}(ssl_log preferred → http log)${C_RST}"
  separator
  section_top_domains
  echo ""

  # ── Section 4: Active Connections ─────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  ACTIVE CONNECTIONS PER IP${C_RST}  ${C_DIM}(live via ss)${C_RST}"
  separator
  section_active_connections
  echo ""

  # ── Section 5: Top IPs Global ─────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  TOP SOURCE IPs  —  ALL DOMAINS${C_RST}  ${C_DIM}(aggregated from domlogs)${C_RST}"
  separator
  section_top_ips_global
  echo ""

  # ── Section 6: IP → Domain ────────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  SOURCE IP  →  TARGET DOMAIN${C_RST}  ${C_DIM}(attack vector mapping)${C_RST}"
  separator
  section_ip_to_domain
  echo ""

  # ── Section 7: Dedicated IPs ──────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  DEDICATED IP  —  CONNECTION ACTIVITY${C_RST}"
  separator
  section_dedicated_ips
  echo ""

  # ── Section 8: Server Summary ─────────────────────────────────────────────
  echo -e "  ${C_BLD}${C_CYN}▸  SERVER SUMMARY${C_RST}"
  separator
  section_summary
  echo ""

  # ── Footer ────────────────────────────────────────────────────────────────
  separator
  printf "  ${C_DIM}Refreshing in %s seconds   |   Press Ctrl+C to exit${C_RST}\n" \
    "$((REFRESH - 2))"
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================
clear
echo -e "\n${C_BLD}${C_WHT}"
echo    "  ╔══════════════════════════════════════════════════════════════════╗"
echo    "  ║        T R A F F I C   M O N I T O R   A N A L Y S I S         ║"
echo    "  ║                   cPanel / WHM  Edition  v3.0                   ║"
echo    "  ╚══════════════════════════════════════════════════════════════════╝"
echo -e "${C_RST}"

validate_environment

# Main loop
while true; do
  draw_screen
  sleep $(( REFRESH - 2 ))
done
