#!/bin/bash
# =============================================================================
# common.sh  --  shared helpers for the Command Center Kali modules.
#
# Sourced by:  deauth.sh  wps-attack.sh  pmkid.sh  rogue-ap-detector.sh
# Deploy it ALONGSIDE them to /home/kali/ (deploy.sh does this for you).
#
# What it gives every module:
#   * cc_soft_reset   -- the fix-adapter.sh pattern (down -> monitor -> up).
#                        NEVER modprobe: reloading the driver drops the
#                        passed-through USB adapter out of the VM.
#   * cc_auth_gate    -- the HARD authorized-targets gate. Nothing that is not
#                        (uncommented) in authorized-targets.txt may be attacked.
#                        There is no AI / judgment override in this path.
#   * cc_lock_channel -- robust 2.4GHz channel locate + lock (flaky rtl8xxxu).
#   * cc_result       -- the machine-readable  RESULT=...  line (stdout).
#   * cc_log/cc_warn  -- human chatter (stderr, so it never pollutes RESULT).
#
# For AUTHORIZED testing only (your own gear / sanctioned competition / lab).
# =============================================================================
set -uo pipefail

# ---- config (override via environment) --------------------------------------
: "${IFACE:=}"                                      # auto-detected when empty
: "${AUTH_FILE:=/home/kali/authorized-targets.txt}" # the allowlist that gates everything
: "${USBID:=2357:010C}"                             # TP-Link RTL8188EUS (for the hard-reset hint)
CC_CHANS=(6 1 11 2 3 4 5 7 8 9 10 12 13)            # 2.4GHz sweep order (adapter is 2.4-only)

# ---- logging ----------------------------------------------------------------
cc_log()    { printf '[*] %s\n'   "$*" >&2; }
cc_warn()   { printf '[!] %s\n'   "$*" >&2; }
cc_result() { printf 'RESULT=%s\n' "$1"; }          # stdout: the one line callers parse
# cc_die MSG [exit_code]: print the RESULT line ($1 only -- NOT $*, or the exit
# code arg would leak into the machine-parsed RESULT=... string) then exit.
cc_die()    { cc_result "$1"; exit "${2:-1}"; }

cc_banner() {  # $1 = module label
  printf '================================================================\n' >&2
  printf '  Command Center :: %s\n' "$1" >&2
  printf '  AUTHORIZED TARGETS ONLY -- gated by %s\n' "$AUTH_FILE" >&2
  printf '================================================================\n' >&2
}

# ---- interface detection ----------------------------------------------------
cc_iface() {
  if [ -n "$IFACE" ]; then printf '%s' "$IFACE"; return 0; fi
  local i
  i=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
  [ -z "$i" ] && i=wlan0
  printf '%s' "$i"
}

# ---- BSSID / MAC helpers ----------------------------------------------------
cc_norm()  { printf '%s' "$1" | tr 'a-f' 'A-F' | tr -d ' '; }         # upper, no spaces
cc_valid_mac() { printf '%s' "$1" | grep -qiE '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'; }

# ---- HARD authorization gate ------------------------------------------------
# A BSSID is authorized IFF it appears as an uncommented first field in AUTH_FILE.
cc_is_authorized() {
  local b; b=$(cc_norm "$1")
  [ -f "$AUTH_FILE" ] || return 1
  grep -vE '^[[:space:]]*#' "$AUTH_FILE" 2>/dev/null | awk '{print toupper($1)}' | grep -qx "$b"
}

# Call at the top of EVERY attack module, before touching the air at a target.
# Refuses (exit 2) unless the BSSID is well-formed AND on the allowlist.
cc_auth_gate() {  # $1 = bssid
  local b; b=$(cc_norm "$1")
  if ! cc_valid_mac "$b"; then
    cc_warn "bad BSSID '$1' -- expected AA:BB:CC:DD:EE:FF"
    cc_die "REFUSED_BAD_BSSID input='$1'" 2
  fi
  if [ ! -f "$AUTH_FILE" ]; then
    cc_warn "allowlist $AUTH_FILE is missing -- failing closed."
    cc_warn "deploy authorized-targets.txt to Kali (deploy.sh) and add this BSSID first."
    cc_die "REFUSED_NO_AUTHFILE path=$AUTH_FILE" 2
  fi
  if ! cc_is_authorized "$b"; then
    cc_warn "[REFUSED] $b is NOT in $AUTH_FILE."
    cc_warn "          Only allowlisted BSSIDs may be attacked. If this is YOUR gear or a"
    cc_warn "          sanctioned target, add its BSSID to the allowlist, then retry."
    cc_die "REFUSED_NOT_AUTHORIZED bssid=$b authfile=$AUTH_FILE" 2
  fi
  cc_log "AUTHORIZED $b (found in $AUTH_FILE)"
}

# ---- tool presence ----------------------------------------------------------
cc_need() {  # cc_need tool1 tool2 ... -> dies listing any that are missing
  local miss=() t
  for t in "$@"; do command -v "$t" >/dev/null 2>&1 || miss+=("$t"); done
  if [ "${#miss[@]}" -gt 0 ]; then
    cc_warn "missing tool(s): ${miss[*]}  (run kali-toolkit-install.sh)"
    cc_die "ERROR_MISSING_TOOLS tools=${miss[*]}" 3
  fi
}
cc_have() { command -v "$1" >/dev/null 2>&1; }

# ---- adapter soft-reset (fix-adapter.sh pattern; NEVER reload the driver) ----
cc_soft_reset() {
  local IF mode
  IF=$(cc_iface)
  cc_log "soft-resetting $IF (down -> set monitor -> up; no driver reload)"
  sudo pkill -9 airodump-ng aireplay-ng hcxdumptool mdk4 reaver bully wash 2>/dev/null
  sleep 1
  sudo ip link set "$IF" down 2>/dev/null
  sudo iw dev "$IF" set type monitor 2>/dev/null
  sudo ip link set "$IF" up 2>/dev/null
  sleep 1
  mode=$(iw dev "$IF" info 2>/dev/null | awk '/type/{print $2}')
  if [ "$mode" != "monitor" ]; then
    cc_warn "$IF is not in monitor mode (mode=${mode:-none})."
    cc_warn "If wlan0 is GONE, hard-reset from the Mac:"
    cc_warn "    utmctl usb disconnect $USBID; sleep 3; utmctl usb connect Kali $USBID"
    cc_die "ADAPTER_NOT_MONITOR iface=$IF mode=${mode:-none}" 4
  fi
  cc_log "$IF ready (monitor mode)"
}

# ---- channel locate + lock --------------------------------------------------
# Echoes the channel on success (and leaves the radio locked there); empty + rc1 if not found.
cc_lock_channel() {  # $1 = bssid  [$2 = forced channel]
  local b forced IF ch c
  b=$(cc_norm "$1"); forced="${2:-}"; IF=$(cc_iface)
  if [ -n "$forced" ]; then
    sudo iw dev "$IF" set channel "$forced" 2>/dev/null
    printf '%s' "$forced"; return 0
  fi
  for ch in "${CC_CHANS[@]}"; do
    sudo iw dev "$IF" set channel "$ch" 2>/dev/null
    sudo rm -f /tmp/cc-loc* 2>/dev/null
    sudo timeout 4 airodump-ng -c "$ch" --bssid "$b" "$IF" -w /tmp/cc-loc --output-format csv >/dev/null 2>&1
    # anchor to line start: only the AP row begins with the BSSID (station rows
    # carry it in a later column), so $4 is reliably the AP's channel.
    c=$(grep -i "^$b" /tmp/cc-loc-01.csv 2>/dev/null | awk -F, '{gsub(/ /,"",$4); if($4+0>0){print $4; exit}}')
    sudo rm -f /tmp/cc-loc* 2>/dev/null
    if [ -n "$c" ]; then
      sudo iw dev "$IF" set channel "$c" 2>/dev/null
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

# ---- cleanup ----------------------------------------------------------------
cc_cleanup() { sudo pkill -9 airodump-ng aireplay-ng hcxdumptool mdk4 reaver bully wash 2>/dev/null; }
