#!/bin/bash
# =============================================================================
# pmkid.sh  --  allowlist-gated clientless PMKID capture (Kali module)
#
#   Usage:  pmkid.sh <BSSID> [chan]
#
#   Captures a PMKID (RSN) straight from the AP with hcxdumptool -- no client
#   needed -- to /tmp/pmkid.pcapng, then verifies it with hcxpcapngtool.
#
#   SAFETY: hcxdumptool left unfiltered solicits EVERY AP in range. That would
#   touch non-allowlisted neighbours, so this script runs it ONLY with a
#   single-AP filter locked to <BSSID>. If the installed hcxdumptool build
#   lacks per-AP filtering, it refuses to run it and falls back to the
#   BSSID-scoped handshake path (grab.sh) instead.
#
#   Best-effort in a VM: USB-passthrough timing makes PMKID flaky, so on no
#   PMKID it automatically falls back to a 4-way handshake capture.
#
#   Tunable (env):  CAP_T=60   AUTHORIZED TARGETS ONLY.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "pmkid"

B="${1:-}"
FORCECH="${2:-}"
CAP_T="${CAP_T:-60}"
OUT=/tmp/pmkid.pcapng
HC=/tmp/pmkid.hc22000
GRAB=/home/kali/grab.sh

[ -z "$B" ] && cc_die "ERROR_USAGE pmkid.sh <BSSID> [chan]" 1

cc_need hcxdumptool airodump-ng
trap cc_cleanup EXIT

# --- safety: soft reset, then the HARD allowlist gate -----------------------
cc_soft_reset
cc_auth_gate "$B"
B="$(cc_norm "$B")"
IF="$(cc_iface)"

# --- lock the AP channel (given, or located) --------------------------------
CH="$(cc_lock_channel "$B" "$FORCECH")" || true
[ -z "$CH" ] && cc_die "AP_NOT_FOUND bssid=$B (AP off / out of range / on 5GHz)" 0
cc_log "AP on channel $CH"

# --- single-AP filter (never run hcxdumptool against the whole band) --------
APMAC="$(printf '%s' "$B" | tr -d ':' | tr 'A-F' 'a-f')"
FLT=/tmp/cc-pmkid-ap.txt; printf '%s\n' "$APMAC" > "$FLT"

HELP="$(hcxdumptool --help 2>&1 || true)"
SCOPED=1; FILT=()
if printf '%s' "$HELP" | grep -q 'filterlist_ap'; then
  FILT=(--filterlist_ap="$FLT" --filtermode=2)
elif printf '%s' "$HELP" | grep -qE '\-\-filterlist([ =])'; then
  FILT=(--filterlist="$FLT" --filtermode=2)
else
  SCOPED=0
fi

fallback_handshake() {  # reuse the proven, BSSID-scoped capture
  if [ -f "$GRAB" ]; then
    cc_log "falling back to 4-way handshake capture via grab.sh ..."
    sudo bash "$GRAB" "$B" "$CH"
    exit $?
  fi
  cc_result "NO_PMKID bssid=$B chan=$CH (no PMKID; grab.sh not present for handshake fallback)"
  exit 0
}

if [ "$SCOPED" = 0 ]; then
  cc_warn "this hcxdumptool build has no per-AP filter flag; refusing to run it unfiltered."
  fallback_handshake
fi

# --- capture (bounded; classic -o pcapng) -----------------------------------
sudo rm -f "$OUT" "$HC" 2>/dev/null
cc_log "PMKID capture on ch $CH for ${CAP_T}s (clientless) ..."
sudo iw dev "$IF" set channel "$CH" 2>/dev/null
# shellcheck disable=SC2024  # /tmp log is caller-owned; the pcapng itself is written root-side via -o
sudo timeout "$CAP_T" hcxdumptool -i "$IF" -o "$OUT" -c "$CH" "${FILT[@]}" >/tmp/cc-pmkid.log 2>&1 || true

if [ ! -s "$OUT" ]; then
  cc_warn "hcxdumptool wrote no capture (see /tmp/cc-pmkid.log)."
  fallback_handshake
fi

# --- verify: did we get a PMKID (type 01) for THIS AP? ----------------------
if cc_have hcxpcapngtool; then
  hcxpcapngtool -o "$HC" "$OUT" >/tmp/cc-pmkid-conv.log 2>&1 || true
fi
if [ -s "$HC" ] && awk -F'*' -v m="$APMAC" 'BEGIN{u=toupper(m)} $2=="01" && toupper($4)==u{f=1} END{exit !f}' "$HC"; then
  cc_result "PMKID_CAPTURED bssid=$B chan=$CH pcapng=$OUT hash=$HC (crack on Mac GPU: crack-mac.sh $OUT)"
  exit 0
fi
if [ -s "$HC" ] && awk -F'*' -v m="$APMAC" 'BEGIN{u=toupper(m)} $2=="02" && toupper($4)==u{f=1} END{exit !f}' "$HC"; then
  cc_result "HANDSHAKE_CAPTURED bssid=$B chan=$CH pcapng=$OUT hash=$HC (no PMKID, but an EAPOL handshake landed; crack-mac.sh $OUT)"
  exit 0
fi

cc_warn "no PMKID for $B this pass (common in a VM)."
fallback_handshake
