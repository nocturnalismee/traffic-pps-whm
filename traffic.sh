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
#   Version  : 1.4-fix
#   Mode     : READ-ONLY  |  SAFETY FIRST
#   Purpose  : DDoS / bot-oriented traffic analysis with PPS monitoring,
#              connection insight, and domain/source correlation for
#              cPanel / WHM servers
#   Contributors : nocturnalismee <https://github.com/nocturnalismee>
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# CONFIGURATION — Tune these values to match your server environment
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
ATTACK_SCORE_WARN=2   # Attack signal score threshold for warning
ATTACK_SCORE_CRIT=4   # Attack signal score threshold for critical
REQ_VIEW_MODE="delta" # Request ranking mode: "delta" or "window"


# PATHS — Standard cPanel/WHM locations
DOMLOGS="/usr/local/apache/domlogs"
USERDOMAINS="/etc/userdomains"
DOMAINIPS="/etc/domainips"


# TERMINAL COLORS
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

: "${C_BLU}" "${C_MAG}"


# RUNTIME STATE
TMPDIR_TMA=""
DOMAINIPS_MODE="unavailable"
DOMAINIPS_WARNING=""
SHUTDOWN_REQUESTED=0
NET_RX_PPS=0
NET_TX_PPS=0
NET_TOTAL_PPS=0
NET_RX_KB=0
NET_TX_KB=0
WEB_PORTS_REGEX='^(80|443)$'

# FIX #6: Owner cache — associative array loaded once at startup
declare -A OWNER_CACHE_MAP

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

# HELPERS
separator() {
  echo -e "${C_DIM}  ────────────────────────────────────────────────────────${C_RST}"
}

is_positive_integer() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

# FIX #8: Sanitize integer — prevent arithmetic errors from empty/non-numeric values
sanitize_int() {
  [[ "$1" =~ ^[0-9]+$ ]] && printf '%d' "$1" || printf '0'
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

  if ! is_positive_integer "$ATTACK_SCORE_WARN" || ! is_positive_integer "$ATTACK_SCORE_CRIT" || (( ATTACK_SCORE_WARN >= ATTACK_SCORE_CRIT )); then
    echo -e "  ${C_RED}✘${C_RST}  Invalid ATTACK score thresholds (warn must be < crit)"
    ok=0
  fi

  if [[ "$REQ_VIEW_MODE" != "delta" && "$REQ_VIEW_MODE" != "window" ]]; then
    echo -e "  ${C_RED}✘${C_RST}  Invalid REQ_VIEW_MODE : ${C_RED}${REQ_VIEW_MODE}${C_RST} (use \"delta\" or \"window\")"
    ok=0
  fi

  if (( ok == 0 )); then
    echo -e "\n  ${C_RED}Configuration validation failed. Fix CONFIGURATION values and rerun.${C_RST}\n"
    exit 1
  fi
}

# FIX #6: Preload owner cache from /etc/userdomains
preload_owner_cache() {
  [[ -f "$USERDOMAINS" ]] || return
  while IFS=$'\t' read -r domain owner; do
    [[ -n "$domain" ]] && OWNER_CACHE_MAP["$domain"]="$owner"
  done < <(awk -F'[:=]' '
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      sub(/^[[:space:]]+/, "", $1)
      sub(/[[:space:]]+$/, "", $1)
      sub(/^[[:space:]]+/, "", $2)
      sub(/[[:space:]]+$/, "", $2)
      if ($1 != "") print $1 "\t" $2
    }
  ' "$USERDOMAINS" 2>/dev/null)
}

# FIX #6: resolve_owner now uses in-memory cache — no awk per call
resolve_owner() {
  local domain="$1"
  if [[ -n "${OWNER_CACHE_MAP[$domain]+_}" ]]; then
    echo "${OWNER_CACHE_MAP[$domain]}"
  else
    echo "n/a"
  fi
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

attack_badge() {
  local score="$1"
  if ! [[ "$score" =~ ^[0-9]+$ ]]; then
    printf '%b' "${C_GRN}● NORMAL  ${C_RST}"
    return
  fi

  if (( score >= ATTACK_SCORE_CRIT )); then
    printf '%b' "${C_RED}● ATTACK LIKELY${C_RST}"
  elif (( score >= ATTACK_SCORE_WARN )); then
    printf '%b' "${C_YEL}● SUSPICIOUS   ${C_RST}"
  else
    printf '%b' "${C_GRN}● NORMAL       ${C_RST}"
  fi
}

request_view_suffix() {
  if [[ "$REQ_VIEW_MODE" == "delta" ]]; then
    printf 'delta'
  else
    printf 'current'
  fi
}

request_view_hint() {
  if [[ "$REQ_VIEW_MODE" == "delta" ]]; then
    printf 'delta since previous refresh'
  else
    printf 'recent cached log window'
  fi
}

delta_baseline_ready() {
  [[ -f "${TMPDIR_TMA}/delta_ready" ]]
}

delta_output_ready() {
  [[ -f "${TMPDIR_TMA}/delta_output_ready" ]]
}

count_view_file() {
  local stem="$1"
  printf '%s/%s_%s' "$TMPDIR_TMA" "$stem" "$(request_view_suffix)"
}

# FIX #9: New aggregation for "count key" input format (sums instead of uniq -c)
aggregate_sum_counts() {
  local input_file="$1"
  local output_file="$2"

  if [[ -s "$input_file" ]]; then
    awk '{
      key = $2
      for (i = 3; i <= NF; i++) key = key " " $i
      total[key] += $1
    }
    END {
      for (key in total) print total[key], key
    }' "$input_file" > "$output_file"
  else
    : > "$output_file"
  fi
}

aggregate_simple_counts() {
  local input_file="$1"
  local output_file="$2"

  if [[ -s "$input_file" ]]; then
    sort "$input_file" | uniq -c | \
      awk '{ key=$2; for (i=3; i<=NF; i++) key=key " " $i; print $1, key }' > "$output_file"
  else
    : > "$output_file"
  fi
}

# FIX #3: Don't clear previous_file when current is empty — preserve baseline
compute_delta_counts() {
  local current_file="$1"
  local previous_file="$2"
  local delta_file="$3"

  if [[ ! -s "$current_file" ]]; then
    : > "$delta_file"
    # FIX: removed `: > "$previous_file"` — keep baseline for next cycle
    return
  fi

  if [[ -s "$previous_file" ]]; then
    awk '
      NR == FNR {
        key = $2
        for (i = 3; i <= NF; i++) key = key " " $i
        prev[key] = $1
        next
      }
      {
        key = $2
        for (i = 3; i <= NF; i++) key = key " " $i
        delta = $1 - ((key in prev) ? prev[key] : 0)
        if (delta < 0) delta = 0
        print delta, key
      }
    ' "$previous_file" "$current_file" > "$delta_file"
  else
    : > "$delta_file"
  fi

  cp "$current_file" "$previous_file"
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

# FIX #8: Sanitize all /sys reads + handle negative PPS on counter reset
sample_network() {
  local sys="/sys/class/net/${IFACE}/statistics"
  local rx1 tx1 rxb1 txb1 rx2 tx2 rxb2 txb2

  rx1=$(sanitize_int "$(cat "${sys}/rx_packets" 2>/dev/null)")
  tx1=$(sanitize_int "$(cat "${sys}/tx_packets" 2>/dev/null)")
  rxb1=$(sanitize_int "$(cat "${sys}/rx_bytes" 2>/dev/null)")
  txb1=$(sanitize_int "$(cat "${sys}/tx_bytes" 2>/dev/null)")

  sleep 1

  rx2=$(sanitize_int "$(cat "${sys}/rx_packets" 2>/dev/null)")
  tx2=$(sanitize_int "$(cat "${sys}/tx_packets" 2>/dev/null)")
  rxb2=$(sanitize_int "$(cat "${sys}/rx_bytes" 2>/dev/null)")
  txb2=$(sanitize_int "$(cat "${sys}/tx_bytes" 2>/dev/null)")

  # FIX #12: Clamp to 0 on counter reset (negative values)
  NET_RX_PPS=$(( rx2 - rx1 )); (( NET_RX_PPS < 0 )) && NET_RX_PPS=0
  NET_TX_PPS=$(( tx2 - tx1 )); (( NET_TX_PPS < 0 )) && NET_TX_PPS=0
  NET_TOTAL_PPS=$(( NET_RX_PPS + NET_TX_PPS ))
  NET_RX_KB=$(( (rxb2 - rxb1) / 1024 )); (( NET_RX_KB < 0 )) && NET_RX_KB=0
  NET_TX_KB=$(( (txb2 - txb1) / 1024 )); (( NET_TX_KB < 0 )) && NET_TX_KB=0
}

cache_log_data() {
  local cache_file="${TMPDIR_TMA}/log_data"
  local domain_counts_raw="${TMPDIR_TMA}/domain_counts_raw"
  local domain_list="${TMPDIR_TMA}/domain_list"
  local tail_tmp="${TMPDIR_TMA}/_tail_tmp"
  local path_counts="${TMPDIR_TMA}/path_counts"
  local ua_counts="${TMPDIR_TMA}/ua_counts"
  local status_counts="${TMPDIR_TMA}/status_counts"
  local ip_hits="${TMPDIR_TMA}/ip_hits"
  local domain_error_hits="${TMPDIR_TMA}/domain_error_hits"
  local ip_error_hits="${TMPDIR_TMA}/ip_error_hits"
  local domain_counts_current="${TMPDIR_TMA}/domain_counts_current"
  local domain_counts_previous="${TMPDIR_TMA}/domain_counts_previous"
  local domain_counts_delta="${TMPDIR_TMA}/domain_counts_delta"
  local ip_counts_current="${TMPDIR_TMA}/ip_counts_current"
  local ip_counts_previous="${TMPDIR_TMA}/ip_counts_previous"
  local ip_counts_delta="${TMPDIR_TMA}/ip_counts_delta"
  local domain_error_counts_current="${TMPDIR_TMA}/domain_error_counts_current"
  local domain_error_counts_previous="${TMPDIR_TMA}/domain_error_counts_previous"
  local domain_error_counts_delta="${TMPDIR_TMA}/domain_error_counts_delta"
  local ip_error_counts_current="${TMPDIR_TMA}/ip_error_counts_current"
  local ip_error_counts_previous="${TMPDIR_TMA}/ip_error_counts_previous"
  local ip_error_counts_delta="${TMPDIR_TMA}/ip_error_counts_delta"
  local had_previous=0

  [[ -n "$TMPDIR_TMA" && -d "$TMPDIR_TMA" ]] || return
  : > "$cache_file"
  : > "$domain_counts_raw"
  : > "$path_counts"
  : > "$ua_counts"
  : > "$status_counts"
  : > "$ip_hits"
  : > "$domain_error_hits"
  : > "$ip_error_hits"
  [[ -s "$domain_list" ]] || return

  [[ -s "$domain_counts_previous" ]] && had_previous=1

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
      printf "%d %s\n" "$lc" "$domain" >> "$domain_counts_raw"

      # FIX #4: Replaced all 3-arg match() with portable alternatives
      # FIX #9: Write count+key directly instead of one-line-per-occurrence
      awk -v dom="$domain" -v ip_file="$cache_file" -v path_file="$path_counts" \
        -v ua_file="$ua_counts" -v status_file="$status_counts" \
        -v ip_hits_file="$ip_hits" -v domain_error_hits_file="$domain_error_hits" \
        -v ip_error_hits_file="$ip_error_hits" '
        function trim(s) {
          sub(/^[[:space:]]+/, "", s)
          sub(/[[:space:]]+$/, "", s)
          return s
        }
        function short_ua(s, maxlen) {
          s = trim(s)
          if (s == "" || s == "-") return "-"
          if (length(s) > maxlen) return substr(s, 1, maxlen - 3) "..."
          return s
        }
        {
          ip = $1
          is_valid_ip = (ip ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || ip ~ /^[0-9A-Fa-f:]+$/)

          if (is_valid_ip) {
            # FIX #9: accumulate counts in arrays, write aggregated in END
            ip_dom_key = ip SUBSEP dom
            ip_dom_seen[ip_dom_key]++
            ip_seen[ip]++
          }

          quote_count = split($0, q, "\"")
          request = (quote_count >= 2 ? q[2] : "")
          rest = (quote_count >= 3 ? q[3] : "")
          ua = (quote_count >= 6 ? q[6] : "-")

          split(request, req_parts, " ")
          path = trim(req_parts[2])
          if (path == "" || path == "-") path = "/"
          sub(/\?.*$/, "", path)
          if (path == "") path = "/"

          # FIX #4: Portable status extraction — no 3-arg match()
          status = ""
          sub(/^[[:space:]]+/, "", rest)
          split(rest, rest_arr, /[[:space:]]+/)
          if (rest_arr[1] ~ /^[0-9]{3}$/) {
            status = rest_arr[1]
          }

          path_seen[path]++
          if (status != "") {
            status_seen[status]++
            if (status ~ /^(4|5)[0-9][0-9]$/) {
              error_domain_seen[dom]++
              if (is_valid_ip) {
                error_ip_seen[ip]++
              }
            }
          }
          ua = short_ua(ua, 72)
          ua_seen[ua]++
        }
        END {
          for (path in path_seen) {
            print path_seen[path], path >> path_file
          }
          for (ua in ua_seen) {
            print ua_seen[ua], ua >> ua_file
          }
          for (status in status_seen) {
            print status_seen[status], status >> status_file
          }
          # FIX #9: Write count+key directly (not one line per occurrence)
          for (ip_dom_key in ip_dom_seen) {
            split(ip_dom_key, parts, SUBSEP)
            print ip_dom_seen[ip_dom_key], parts[1], parts[2] >> ip_file
          }
          for (ip_key in ip_seen) {
            print ip_seen[ip_key], ip_key >> ip_hits_file
          }
          for (domain_key in error_domain_seen) {
            print error_domain_seen[domain_key], domain_key >> domain_error_hits_file
          }
          for (ip_key in error_ip_seen) {
            print error_ip_seen[ip_key], ip_key >> ip_error_hits_file
          }
        }
      ' "$tail_tmp"
    fi
  done < "$domain_list"

  cp "$domain_counts_raw" "$domain_counts_current"

  # FIX #9: Use aggregate_sum_counts for pre-aggregated "count key" data
  aggregate_sum_counts "$ip_hits" "$ip_counts_current"
  aggregate_sum_counts "$domain_error_hits" "$domain_error_counts_current"
  aggregate_sum_counts "$ip_error_hits" "$ip_error_counts_current"

  compute_delta_counts "$domain_counts_current" "$domain_counts_previous" "$domain_counts_delta"
  compute_delta_counts "$ip_counts_current" "$ip_counts_previous" "$ip_counts_delta"
  compute_delta_counts "$domain_error_counts_current" "$domain_error_counts_previous" "$domain_error_counts_delta"
  compute_delta_counts "$ip_error_counts_current" "$ip_error_counts_previous" "$ip_error_counts_delta"

  if ! delta_baseline_ready; then
    : > "${TMPDIR_TMA}/delta_ready"
  fi

  if (( had_previous == 1 )); then
    : > "${TMPDIR_TMA}/delta_output_ready"
  else
    rm -f "${TMPDIR_TMA}/delta_output_ready"
  fi

  rm -f "$tail_tmp"
}

# FIX #4: Replaced 3-arg match() with portable index()/substr()
parse_ss_ips() {
  local field="$1"
  local ss_file="${TMPDIR_TMA}/ss_output"

  awk -v fld="$field" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function extract_host(addr,   host, rest, bidx) {
      addr = trim(addr)
      if (addr == "" || addr == "*" || addr == "*:*") return ""

      # Handle IPv6 bracket notation [ip]:port
      if (addr ~ /^\[/) {
        rest = substr(addr, 2)
        bidx = index(rest, "]")
        if (bidx > 0) return substr(rest, 1, bidx - 1)
      }

      # Split on last colon to separate host:port
      if (match(addr, /:[^:]*$/)) {
        host = substr(addr, 1, RSTART - 1)
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

# FIX #2: Corrected field positions — $5=Local, $6=Peer (was $4/$5)
# FIX #4: Replaced 3-arg match() with portable alternatives
parse_ss_web_peer_ips() {
  local ss_file="${TMPDIR_TMA}/ss_output"
  local web_ports_regex="${1:-$WEB_PORTS_REGEX}"

  awk -v web_ports_regex="$web_ports_regex" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function extract_host(addr,   host, rest, bidx) {
      addr = trim(addr)
      if (addr == "" || addr == "*" || addr == "*:*") return ""

      if (addr ~ /^\[/) {
        rest = substr(addr, 2)
        bidx = index(rest, "]")
        if (bidx > 0) return substr(rest, 1, bidx - 1)
      }

      if (match(addr, /:[^:]*$/)) {
        host = substr(addr, 1, RSTART - 1)
      } else {
        host = addr
      }

      host = trim(host)
      if (host == "" || host == "*" || host == "0.0.0.0" || host == "::") return ""
      return host
    }
    function extract_port(addr,   rest) {
      addr = trim(addr)
      if (addr == "" || addr == "*" || addr == "*:*") return ""
      if (match(addr, /:[0-9]+$/)) {
        rest = substr(addr, RSTART + 1)
        return rest
      }
      return ""
    }
    NR > 1 {
      # FIX #2: Corrected field positions for ss output
      # $5 = Local Address:Port, $6 = Peer Address:Port
      local_port = extract_port($5)
      peer_host = extract_host($6)
      if (local_port ~ web_ports_regex && peer_host != "") {
        print peer_host
      }
    }
  ' "$ss_file" 2>/dev/null
}

# FIX #4: Replaced 3-arg match() with portable index()/substr()
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

  # FIX #4: Portable parse_pair using index() instead of 3-arg match()
  if awk '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function parse_pair(line,   idx) {
      idx = index(line, ":")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      idx = index(line, "=")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      if (match(line, /[^[:space:]]+[[:space:]]+[^[:space:]]+/)) {
        rest = substr(line, RSTART)
        n = split(rest, parts, /[[:space:]]+/)
        if (n >= 2) { first = parts[1]; second = parts[2]; return 1 }
      }
      return 0
    }
    function is_ipv4(s) {
      return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/
    }
    BEGIN { ok = 1 }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
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
    function parse_pair(line,   idx) {
      idx = index(line, ":")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      idx = index(line, "=")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      if (match(line, /[^[:space:]]+[[:space:]]+[^[:space:]]+/)) {
        rest = substr(line, RSTART)
        n = split(rest, parts, /[[:space:]]+/)
        if (n >= 2) { first = parts[1]; second = parts[2]; return 1 }
      }
      return 0
    }
    function is_ipv4(s) {
      return s ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/
    }
    BEGIN { ok = 1 }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
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


# STARTUP

validate_environment() {
  local ok=1

  echo -e "\n${C_BLD}${C_WHT}  Validating environment...${C_RST}\n"

  validate_config
  detect_domainips_mode

  # FIX: Check for required commands
  local cmd missing=""
  for cmd in ss awk sort uniq wc tail grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing="$missing $cmd"
    fi
  done
  if [[ -n "$missing" ]]; then
    echo -e "  ${C_RED}✘${C_RST}  Missing commands   :${C_RED}${missing}${C_RST}"
    ok=0
  else
    echo -e "  ${C_GRN}✔${C_RST}  Required commands  : all present"
  fi

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
    # FIX #5: Don't hang on non-interactive stdin
    if [[ -t 0 ]]; then
      echo -e "  Press ${C_BLD}Enter${C_RST} to continue anyway, or ${C_BLD}Ctrl+C${C_RST} to abort.\n"
      read -r
    else
      echo -e "  ${C_RED}Non-interactive mode — aborting.${C_RST}\n"
      exit 1
    fi
  else
    echo -e "  ${C_GRN}All checks passed.${C_RST} Starting monitor in 2 seconds...\n"
    sleep 2
  fi
}


# SECTIONS

section_pps() {
  local badge
  badge=$(severity_badge "$NET_RX_PPS" "$PPS_WARN" "$PPS_CRIT")

  printf "  ${C_DIM}%-18s${C_RST}  %s pps   %b\n" "RX  (inbound)" "$NET_RX_PPS" "$badge"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n" "TX  (outbound)" "$NET_TX_PPS"
  printf "  ${C_DIM}%-18s${C_RST}  %s pps\n" "Total" "$NET_TOTAL_PPS"
  printf "  ${C_DIM}%-18s${C_RST}  warn=${C_YEL}%s${C_RST}  crit=${C_RED}%s${C_RST}\n" \
    "Thresholds" "${PPS_WARN} pps" "${PPS_CRIT} pps"
}

section_bandwidth() {
  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Download (RX)" "$NET_RX_KB"
  printf "  ${C_DIM}%-18s${C_RST}  %s KB/s\n" "Upload   (TX)" "$NET_TX_KB"
}

# FIX #7: Cache parse_ss_web_peer_ips result — avoid double parse
section_attack_summary() {
  local domain_counts
  local ip_counts
  local status_counts="${TMPDIR_TMA}/status_counts"
  local score=0
  local top_domain_req=0 top_domain_name="n/a"
  local top_ip_req=0 top_ip_name="n/a"
  local top_web_conn_count=0
  local status_errors=0
  local badge

  domain_counts=$(count_view_file "domain_counts")
  ip_counts=$(count_view_file "ip_counts")

  if [[ "$REQ_VIEW_MODE" == "delta" && ! delta_output_ready ]]; then
    echo -e "  ${C_DIM}Building baseline for delta mode — wait for the next refresh.${C_RST}"
    return
  fi

  if [[ -s "$domain_counts" ]]; then
    read -r top_domain_req top_domain_name < <(sort -rn "$domain_counts" | head -n 1)
    [[ "$top_domain_req" =~ ^[0-9]+$ ]] || top_domain_req=0
  fi

  if [[ -s "$ip_counts" ]]; then
    read -r top_ip_req top_ip_name < <(sort -rn "$ip_counts" | head -n 1)
    [[ "$top_ip_req" =~ ^[0-9]+$ ]] || top_ip_req=0
  fi

  # FIX #7: Cache web peer IPs — parse only once
  local web_peers
  web_peers=$(parse_ss_web_peer_ips | grep -Ev '^$|^127\.|^::1$|^\*$')
  if [[ -n "$web_peers" ]]; then
    read -r top_web_conn_count _ < <(echo "$web_peers" | sort | uniq -c | sort -rn | head -n 1)
    [[ "$top_web_conn_count" =~ ^[0-9]+$ ]] || top_web_conn_count=0
  fi

  if [[ -s "$status_counts" ]]; then
    status_errors=$(awk '$2 ~ /^(4|5)[0-9][0-9]$/ { sum += $1 } END { print sum + 0 }' "$status_counts")
  fi

  (( NET_RX_PPS > PPS_WARN )) && (( score++ ))
  (( top_domain_req > REQ_WARN )) && (( score++ ))
  (( top_ip_req > REQ_WARN )) && (( score++ ))
  (( top_web_conn_count > CONN_WARN )) && (( score++ ))
  (( status_errors > REQ_WARN )) && (( score++ ))

  badge=$(attack_badge "$score")

  printf "  ${C_DIM}%-18s${C_RST}  %s / 5   %b\n" "Signal score" "$score" "$badge"
  printf "  ${C_DIM}%-18s${C_RST}  %-32s  %s req\n" "Top domain" "$top_domain_name" "$top_domain_req"
  printf "  ${C_DIM}%-18s${C_RST}  %-32s  %s req\n" "Top source IP" "$top_ip_name" "$top_ip_req"
  printf "  ${C_DIM}%-18s${C_RST}  %s web peer connections\n" "Top peer IP" "$top_web_conn_count"
  printf "  ${C_DIM}%-18s${C_RST}  %s responses (4xx/5xx)\n" "HTTP errors" "$status_errors"
}

# FIX #11: Removed local from piped while-loop bodies
section_top_domains() {
  local domain_counts
  domain_counts=$(count_view_file "domain_counts")

  if [[ "$REQ_VIEW_MODE" == "delta" && ! delta_output_ready ]]; then
    echo -e "  ${C_DIM}Baseline collected. Delta data will appear on the next refresh.${C_RST}"
    return
  fi

  local count domain owner proto badge
  if [[ -s "$domain_counts" ]]; then
    sort -rn "$domain_counts" | head -n "$TOP_N" | \
      while read -r count domain; do
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

section_active_connections() {
  local result
  # FIX #2: parse_ss_web_peer_ips now correctly uses $5/$6 — peer IPs are extracted properly
  result=$(parse_ss_web_peer_ips | \
    grep -Ev '^$|^127\.|^::1$|^\*$' | \
    sort | uniq -c | sort -rn | head -n "$TOP_N")

  local count ip badge
  if [[ -n "$result" ]]; then
    echo "$result" | \
      while read -r count ip; do
        badge=$(severity_badge "$count" "$CONN_WARN" "$CONN_CRIT")
        printf "  %6s conn  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No active web connections detected on ports 80/443.${C_RST}"
  fi
}

section_top_paths() {
  local path_counts="${TMPDIR_TMA}/path_counts"

  local count path badge
  if [[ -s "$path_counts" ]]; then
    awk '{
      count = $1
      $1 = ""
      key = substr($0, 2)
      total[key] += count
    }
    END {
      for (key in total) {
        print total[key], key
      }
    }' "$path_counts" | sort -rn | head -n "$TOP_N" | \
      while read -r count path; do
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s hit  %-52s  %b\n" "$count" "$path" "$badge"
      done
  else
    echo -e "  ${C_DIM}No path data available.${C_RST}"
  fi
}

section_top_ips_global() {
  local ip_counts
  ip_counts=$(count_view_file "ip_counts")

  if [[ "$REQ_VIEW_MODE" == "delta" && ! delta_output_ready ]]; then
    echo -e "  ${C_DIM}Baseline collected. Delta data will appear on the next refresh.${C_RST}"
    return
  fi

  local count ip badge
  if [[ -s "$ip_counts" ]]; then
    sort -rn "$ip_counts" | head -n "$TOP_N" | \
      while read -r count ip; do
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi
}

section_top_domains_errors() {
  local error_counts
  error_counts=$(count_view_file "domain_error_counts")

  if [[ "$REQ_VIEW_MODE" == "delta" && ! delta_output_ready ]]; then
    echo -e "  ${C_DIM}Baseline collected. Delta error data will appear on the next refresh.${C_RST}"
    return
  fi

  local count domain owner badge
  if [[ -s "$error_counts" ]]; then
    sort -rn "$error_counts" | head -n "$TOP_N" | \
      while read -r count domain; do
        owner=$(resolve_owner "$domain")
        [[ -n "$owner" ]] || owner="n/a"
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s err  %-38s  owner: %-14s  %b\n" \
          "$count" "$domain" "$owner" "$badge"
      done
  else
    echo -e "  ${C_DIM}No 4xx/5xx domain data available.${C_RST}"
  fi
}

section_top_ips_errors() {
  local error_counts
  error_counts=$(count_view_file "ip_error_counts")

  if [[ "$REQ_VIEW_MODE" == "delta" && ! delta_output_ready ]]; then
    echo -e "  ${C_DIM}Baseline collected. Delta error data will appear on the next refresh.${C_RST}"
    return
  fi

  local count ip badge
  if [[ -s "$error_counts" ]]; then
    sort -rn "$error_counts" | head -n "$TOP_N" | \
      while read -r count ip; do
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s err  %-30s  %b\n" "$count" "$ip" "$badge"
      done
  else
    echo -e "  ${C_DIM}No 4xx/5xx IP data available.${C_RST}"
  fi
}

section_top_user_agents() {
  local ua_counts="${TMPDIR_TMA}/ua_counts"

  local count ua badge
  if [[ -s "$ua_counts" ]]; then
    awk '{
      count = $1
      $1 = ""
      key = substr($0, 2)
      total[key] += count
    }
    END {
      for (key in total) {
        print total[key], key
      }
    }' "$ua_counts" | sort -rn | head -n "$TOP_N" | \
      while read -r count ua; do
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s req  %-52s  %b\n" "$count" "$ua" "$badge"
      done
  else
    echo -e "  ${C_DIM}No user-agent data available.${C_RST}"
  fi
}

section_status_codes() {
  local status_counts="${TMPDIR_TMA}/status_counts"

  local count status badge
  if [[ -s "$status_counts" ]]; then
    awk '{
      total[$2] += $1
    }
    END {
      for (key in total) {
        print total[key], key
      }
    }' "$status_counts" | sort -rn | head -n "$TOP_N" | \
      while read -r count status; do
        badge=$(severity_badge "$count" "$REQ_WARN" "$REQ_CRIT")
        printf "  %9s resp  %-8s  %b\n" "$count" "$status" "$badge"
      done
  else
    echo -e "  ${C_DIM}No HTTP status data available.${C_RST}"
  fi
}

# FIX #9: Updated to handle "count ip domain" format from aggregated log_data
section_ip_to_domain() {
  local log_data="${TMPDIR_TMA}/log_data"

  local count ip domain owner
  if [[ -s "$log_data" ]]; then
    # Data is already in "count ip domain" format from aggregate_sum_counts
    sort -rn "$log_data" | head -n "$TOP_N" | \
      while read -r count ip domain; do
        owner=$(resolve_owner "$domain")
        [[ -n "$owner" ]] || owner="n/a"
        printf "  %9s req  %-28s  →  %-34s  owner: %s\n" \
          "$count" "$ip" "$domain" "$owner"
      done
  else
    echo -e "  ${C_DIM}No data available.${C_RST}"
  fi
}

# FIX #2: parse_ss_ips 5 gets Local Address:Port — correct for dedicated IP matching
# FIX #4: Portable AWK in parse_pair
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

  # FIX #4: Portable parse_pair using index() instead of 3-arg match()
  pairs=$(awk -v mode="$DOMAINIPS_MODE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }
    function parse_pair(line,   idx) {
      idx = index(line, ":")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      idx = index(line, "=")
      if (idx > 0) {
        first = substr(line, 1, idx - 1)
        second = substr(line, idx + 1)
        sub(/^[[:space:]]+/, "", first); sub(/[[:space:]]+$/, "", first)
        sub(/^[[:space:]]+/, "", second); sub(/[[:space:]]+$/, "", second)
        if (first != "" && second != "") return 1
      }
      return 0
    }
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
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

  # Field 5 = Local Address:Port — correct for finding connections TO dedicated IPs
  local_ips=$(parse_ss_ips 5)

  local ded_ip ded_label conn_count badge owner
  while read -r ded_ip ded_label; do
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


# RENDER

draw_screen() {
  local ts
  ts=$(date '+%Y-%m-%d  %H:%M:%S')

  sample_network
  cache_ss_output
  build_domain_list
  cache_log_data

  clear

  echo -e "${C_BLD}${C_WHT}  Traffic Monitor Analysis${C_RST}  ${C_DIM}cPanel / WHM v1.4-fix${C_RST}"
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

  echo -e "  ${C_BLD}${C_CYN}▸  ATTACK SUMMARY${C_RST}  ${C_DIM}(current sample window)${C_RST}"
  separator
  section_attack_summary
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP DOMAINS BY REQUEST COUNT${C_RST}  ${C_DIM}($(request_view_hint))${C_RST}"
  separator
  section_top_domains
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  ACTIVE WEB CONNECTIONS PER IP${C_RST}  ${C_DIM}(local ports 80/443 via ss)${C_RST}"
  separator
  section_active_connections
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP SOURCE IPs  —  ALL DOMAINS${C_RST}  ${C_DIM}($(request_view_hint))${C_RST}"
  separator
  section_top_ips_global
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP DOMAINS BY 4xx/5xx${C_RST}  ${C_DIM}($(request_view_hint))${C_RST}"
  separator
  section_top_domains_errors
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP IPs BY 4xx/5xx${C_RST}  ${C_DIM}($(request_view_hint))${C_RST}"
  separator
  section_top_ips_errors
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP REQUEST PATHS${C_RST}  ${C_DIM}(recent cached log sample)${C_RST}"
  separator
  section_top_paths
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  TOP USER-AGENTS${C_RST}  ${C_DIM}(recent cached log sample)${C_RST}"
  separator
  section_top_user_agents
  echo ""

  echo -e "  ${C_BLD}${C_CYN}▸  HTTP STATUS CODES${C_RST}  ${C_DIM}(parsed responses from recent cached log sample)${C_RST}"
  separator
  section_status_codes
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
  printf "  ${C_DIM}Next refresh in ~%s seconds   |   Press Ctrl+C to exit${C_RST}\n" \
    "$REFRESH"
  echo ""
}

# MAIN  — FIX #1: Wrapped in main() function (removed dangling })
main() {
  clear
  echo ""
  echo -e "${C_BLD}${C_WHT}  Traffic Monitor Analysis${C_RST}  ${C_DIM}cPanel / WHM v1.4-fix${C_RST}"
  separator

  validate_environment
  init_tmpdir
  preload_owner_cache

  # FIX #10: Track wall-clock time for accurate refresh interval
  while true; do
    (( SHUTDOWN_REQUESTED == 1 )) && break
    local cycle_start cycle_end elapsed sleep_time
    cycle_start=$(date +%s)

    draw_screen

    cycle_end=$(date +%s)
    elapsed=$(( cycle_end - cycle_start ))
    sleep_time=$(( REFRESH - elapsed ))
    (( sleep_time < 1 )) && sleep_time=1
    sleep "$sleep_time"
  done
}

main "$@"
