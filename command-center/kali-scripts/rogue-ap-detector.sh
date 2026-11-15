#!/bin/bash
# =============================================================================
# rogue-ap-detector.sh  --  DEFENSIVE evil-twin / rogue-AP detector (Kali module)
#
#   Usage:  rogue-ap-detector.sh <your_SSID>
#
#   This is a DETECTOR. It only LISTENS (passive monitor capture) and reports.
#   It does NOT transmit, does NOT deauth, does NOT stand up any AP, and -- by
#   deliberate design -- contains NO fake-login / captive-portal / credential
#   capture of any kind. It answers one question: "is someone impersonating or
#   attacking MY network right now?"
#
#   It flags three things around <your_SSID>:
#     1) EVIL TWIN      -- your ESSID beaconed by more than one BSSID.
#     2) DEAUTH FLOOD   -- a spike of deauth/disassoc frames (someone kicking
#                          clients off, often paired with an evil twin).
#     3) KARMA / MANA   -- one radio answering probe requests for many different
#                          SSIDs (a "say-yes-to-everything" rogue AP).
#
#   Tunables (env):  SCAN_T=40  DEAUTH_THRESH=50  KARMA_THRESH=5
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "rogue-ap-detector (defensive, listen-only)"

SSID="${1:-}"
SCAN_T="${SCAN_T:-40}"
DEAUTH_THRESH="${DEAUTH_THRESH:-50}"
KARMA_THRESH="${KARMA_THRESH:-5}"
BASE=/tmp/cc-rogue
CAP="$BASE-01.cap"
CSV="$BASE-01.csv"

[ -z "$SSID" ] && cc_die "ERROR_USAGE rogue-ap-detector.sh <your_SSID>" 1

cc_need airodump-ng
trap cc_cleanup EXIT

# listen-only: still need monitor mode, but there is no target and no auth gate
cc_soft_reset
IF="$(cc_iface)"

# --- capture the whole 2.4GHz band (channel-hopping) + CSV -------------------
sudo rm -f "$BASE"* 2>/dev/null
cc_log "listening across 2.4GHz for ${SCAN_T}s (passive) ..."
sudo timeout "$SCAN_T" airodump-ng "$IF" -w "$BASE" --output-format pcap,csv >/dev/null 2>&1 || true

AP_COUNT=0
[ -f "$CSV" ] && AP_COUNT=$(awk -F, '/Station MAC/{exit} $1 ~ /^([0-9A-Fa-f]{2}:){5}/{n++} END{print n+0}' "$CSV")
echo "ROGUE_SCAN ssid=\"$SSID\" aps_seen=$AP_COUNT window=${SCAN_T}s"

# =========================== 1) EVIL TWIN ===================================
# every BSSID whose ESSID equals your SSID -> if 2+, one of them is not yours.
TWINS_RAW=""
[ -f "$CSV" ] && TWINS_RAW=$(awk -F, -v want="$SSID" '
  /^Station MAC/{sec=2}
  sec!=2 && $1 ~ /^([0-9A-Fa-f]{2}:){5}/ {
    b=toupper($1); gsub(/ /,"",b);
    ch=$4; gsub(/ /,"",ch);
    pw=$9+0; e=$14; gsub(/^[ ]+|[ ]+$/,"",e);
    if (e==want) printf "%s|ch%s|%ddBm\n", b, ch, pw;
  }' "$CSV")
TWIN_N=0
[ -n "$TWINS_RAW" ] && TWIN_N=$(printf '%s\n' "$TWINS_RAW" | grep -c .)

if [ "$TWIN_N" -ge 2 ]; then
  cc_warn "FINDING EVIL_TWIN: \"$SSID\" is beaconed by $TWIN_N BSSIDs -- one is likely an impersonator:"
  printf '%s\n' "$TWINS_RAW" | sed 's/^/        /' >&2
  cc_warn "        -> keep the BSSID that is yours; the other(s) are suspect."
elif [ "$TWIN_N" -eq 1 ]; then
  cc_log "ok: \"$SSID\" seen on exactly one BSSID ($TWINS_RAW) -- no twin."
else
  cc_log "ok: \"$SSID\" not currently on the air (no AP seen with that name)."
fi

# =================== 2) DEAUTH FLOOD  + 3) KARMA ============================
DEAUTH=0; DISASSOC=0; KARMA_APS=0; HAVE_TSHARK=no
if cc_have tshark && [ -f "$CAP" ]; then
  HAVE_TSHARK=yes
  DEAUTH=$(timeout 30 tshark -r "$CAP" -Y 'wlan.fc.type_subtype==12' 2>/dev/null | grep -c . || true)
  DISASSOC=$(timeout 30 tshark -r "$CAP" -Y 'wlan.fc.type_subtype==10' 2>/dev/null | grep -c . || true)
  if [ "$((DEAUTH + DISASSOC))" -ge "$DEAUTH_THRESH" ]; then
    TOPSRC=$(timeout 30 tshark -r "$CAP" -Y 'wlan.fc.type_subtype==12||wlan.fc.type_subtype==10' \
               -T fields -e wlan.sa 2>/dev/null | sort | uniq -c | sort -nr | head -1 | awk '{print $2" ("$1")"}')
    cc_warn "FINDING DEAUTH_FLOOD: $DEAUTH deauth + $DISASSOC disassoc frames in ${SCAN_T}s (top src: ${TOPSRC:-?})"
    cc_warn "        -> someone is kicking clients off nearby -- classic evil-twin companion."
  else
    cc_log "ok: deauth/disassoc volume normal ($DEAUTH/$DISASSOC in ${SCAN_T}s)."
  fi

  # karma: a single source answering probe-requests for many distinct SSIDs
  KARMA_LIST=$(timeout 30 tshark -r "$CAP" -Y 'wlan.fc.type_subtype==5' -T fields -e wlan.sa -e wlan.ssid 2>/dev/null \
    | awk -F'\t' '$2!=""{ if(!((($1) SUBSEP ($2)) in s)){ s[$1 SUBSEP $2]=1; c[$1]++ } } END{ for(k in c) print c[k]"|"k }' \
    | sort -nr)
  if [ -n "$KARMA_LIST" ]; then
    KARMA_APS=$(printf '%s\n' "$KARMA_LIST" | awk -F'|' -v t="$KARMA_THRESH" '$1>=t' | grep -c . || true)
  fi
  if [ "$KARMA_APS" -ge 1 ]; then
    cc_warn "FINDING KARMA_AP: $KARMA_APS radio(s) answered probes for >= $KARMA_THRESH distinct SSIDs:"
    printf '%s\n' "$KARMA_LIST" | awk -F'|' -v t="$KARMA_THRESH" '$1>=t{printf "        %s  (%s distinct SSIDs)\n",$2,$1}' >&2
    cc_warn "        -> a 'responds-to-everything' rogue AP (Karma/MANA) is nearby."
  else
    cc_log "ok: no Karma-style probe responder seen."
  fi
else
  cc_warn "tshark not available (or no capture) -- deauth-flood and Karma checks skipped; evil-twin check still ran."
fi

cc_result "ROGUE_SCAN_DONE ssid=\"$SSID\" twins=$TWIN_N deauth=$DEAUTH disassoc=$DISASSOC karma_aps=$KARMA_APS aps=$AP_COUNT tshark=$HAVE_TSHARK window=${SCAN_T}s"
