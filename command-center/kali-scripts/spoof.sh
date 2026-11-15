#!/bin/bash
# =============================================================================
# spoof.sh  --  randomize the Kali adapter's OWN MAC address (Kali module)
#
#   Usage:  spoof.sh [random|restore|AA:BB:CC:DD:EE:FF]
#
#     (no arg) / random   -> random MAC               (macchanger -r)
#     restore             -> permanent hardware MAC    (macchanger -p)
#     AA:BB:CC:DD:EE:FF    -> a specific MAC           (macchanger --mac)
#
#   This changes ONLY your own local adapter. It has no target, transmits no
#   frames at any network, and touches nothing on the air -- so, unlike the
#   attack modules, it is deliberately NOT behind the allowlist gate.
#
#   macchanger needs the interface down, so this brings $IFACE down, changes
#   the MAC, and brings it back up. AUTHORIZED / own-adapter use only.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$HERE/common.sh" 2>/dev/null || { echo "RESULT=ERROR missing common.sh beside this script"; exit 1; }

cc_banner "spoof-mac (own adapter -- no target, no gate)"

ARG="${1:-random}"
LOG=/tmp/cc-spoof.log; : > "$LOG"

cc_need macchanger ip
IF="$(cc_iface)"

# bring the interface down (macchanger requires it) ---------------------------
cc_log "bringing $IF down to change its MAC ..."
sudo pkill -9 airodump-ng aireplay-ng hcxdumptool mdk4 reaver bully wash 2>/dev/null
sleep 1
sudo ip link set "$IF" down 2>/dev/null

OLD="$(cat "/sys/class/net/$IF/address" 2>/dev/null)"

case "$ARG" in
  random|-r|'')
    MODE=random
    sudo macchanger -r "$IF" >>"$LOG" 2>&1 || true ;;
  restore|-p|permanent)
    MODE=restore
    sudo macchanger -p "$IF" >>"$LOG" 2>&1 || true ;;
  *)
    if cc_valid_mac "$ARG"; then
      MODE=set
      sudo macchanger --mac="$(printf '%s' "$ARG" | tr 'A-F' 'a-f')" "$IF" >>"$LOG" 2>&1 || true
    else
      sudo ip link set "$IF" up 2>/dev/null
      cc_warn "bad MAC '$ARG' -- use: random | restore | AA:BB:CC:DD:EE:FF"
      cc_die "REFUSED_BAD_MAC input='$ARG'" 2
    fi ;;
esac

# bring it back up ------------------------------------------------------------
sudo ip link set "$IF" up 2>/dev/null
sleep 1
NEW="$(cat "/sys/class/net/$IF/address" 2>/dev/null)"

if [ -n "$NEW" ] && [ "$NEW" != "$OLD" ]; then
  cc_result "SPOOF_DONE iface=$IF mode=$MODE old=${OLD:-?} new=$NEW"
elif [ -n "$NEW" ]; then
  cc_result "SPOOF_NOCHANGE iface=$IF mode=$MODE mac=$NEW (address unchanged; see $LOG)"
else
  cc_result "SPOOF_ERROR iface=$IF mode=$MODE (could not read new MAC; see $LOG)"
fi
