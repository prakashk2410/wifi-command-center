#!/bin/bash
# =============================================================================
# recon.sh  --  focused, ALLOWLIST-GATED recon of ONE target AP (Kali module)
#
#   Usage:  recon.sh <BSSID> [chan]
#
#   Enumerates the stations (clients) associated with a chosen AP via a short,
#   channel-locked airodump-ng capture. The radio only LISTENS here (airodump
#   is receive-only), but because this focuses on a specific target it is still
#   put behind the HARD allowlist gate: a BSSID that is not (uncommented) in
#   authorized-targets.txt is REFUSED. There is no override in this path.
#
#   Prints the AP's ESSID/encryption plus each associated client (MAC, signal,
#   packet count) and a machine-readable RESULT= line.
#
#   Tunable (env):  SCAN_T=25   AUTHORIZED TARGETS ONLY.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "recon (focused, allowlist-gated)"

B="${1:-}"
FORCECH="${2:-}"
SCAN_T="${SCAN_T:-25}"
BASE=/tmp/cc-recon
CSV="$BASE-01.csv"

[ -z "$B" ] && cc_die "ERROR_USAGE recon.sh <BSSID> [chan]" 1

# clamp scan window to a sane 5..120s so it can never run away
case "$SCAN_T" in (*[!0-9]*|'') SCAN_T=25;; esac
[ "$SCAN_T" -lt 5 ] && SCAN_T=5
[ "$SCAN_T" -gt 120 ] && SCAN_T=120

cc_need airodump-ng
trap cc_cleanup EXIT

# --- safety: soft reset FIRST, then the HARD allowlist gate ------------------
cc_soft_reset
cc_auth_gate "$B"
B="$(cc_norm "$B")"
IF="$(cc_iface)"

# --- lock the AP channel (given, or located) --------------------------------
CH="$(cc_lock_channel "$B" "$FORCECH")" || true
[ -z "$CH" ] && cc_die "AP_NOT_FOUND bssid=$B (AP off / out of range / on 5GHz)" 0
cc_log "AP on channel $CH"

# --- focused, channel-locked capture (receive-only, time-bounded) -----------
sudo rm -f "$BASE"* 2>/dev/null
cc_log "enumerating clients of $B on ch $CH for ${SCAN_T}s (passive listen) ..."
sudo iw dev "$IF" set channel "$CH" 2>/dev/null
# shellcheck disable=SC2024  # /tmp capture is caller-owned; the radio op is the sudo'd part
sudo timeout "$SCAN_T" airodump-ng -c "$CH" --bssid "$B" "$IF" -w "$BASE" --output-format csv >/dev/null 2>&1 || true

[ -f "$CSV" ] || cc_die "RECON_NO_DATA bssid=$B chan=$CH (airodump wrote no CSV; adapter flaky?)" 0

# --- AP metadata from the AP section (ESSID / privacy) ----------------------
APINFO="$(awk -F, -v ap="$B" '
  /^Station MAC/{exit}
  $1 ~ /^([0-9A-Fa-f]{2}:){5}/ {
    b=toupper($1); gsub(/ /,"",b);
    if (b==ap) { e=$14; gsub(/^[ ]+|[ ]+$/,"",e); priv=$6; gsub(/ /,"",priv);
                 printf "essid=\"%s\" enc=%s", e, priv; exit }
  }' "$CSV")"

# --- client (station) section: only rows associated with THIS AP ------------
# station columns: Station MAC, First, Last, Power, # packets, BSSID, Probes
CLIENTS="$(awk -F, -v ap="$B" '
  /^Station MAC/{sec=1; next}
  sec==1 && $1 ~ /^([0-9A-Fa-f]{2}:){5}/ {
    bs=toupper($6); gsub(/ /,"",bs);
    if (bs==ap) {
      mac=toupper($1); gsub(/ /,"",mac);
      pw=$4+0; pk=$5+0;
      printf "%s|%ddBm|%dpkts\n", mac, pw, pk;
    }
  }' "$CSV")"

N=0
[ -n "$CLIENTS" ] && N="$(printf '%s\n' "$CLIENTS" | grep -c .)"

if [ "$N" -gt 0 ]; then
  cc_log "clients associated with $B:"
  printf '%s\n' "$CLIENTS" | sed 's/^/        /' >&2
else
  cc_log "no associated clients seen this pass (idle AP, or clients quiet)."
fi

cc_result "RECON_DONE bssid=$B chan=$CH ${APINFO:-essid=? enc=?} clients=$N window=${SCAN_T}s"
