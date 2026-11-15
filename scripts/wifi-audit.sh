#!/bin/bash
# wifi-audit.sh (runs on the Mac) — local Wi-Fi audit console.  AUTHORIZED TARGETS ONLY.
#
#   scan (Kali)  ->  numbered table w/ ✅ auth marks  ->  pick #  ->  HARD auth-gate
#                ->  capture (Kali)  ->  crack (Mac GPU)  ->  report
#
# The authorized list (authorized-targets.txt) is the ONLY thing that decides what may be
# attacked. Anything not on it is REFUSED — there is no AI judgment in the loop.
#
# Usage:
#   wifi-audit.sh scan            # scan + show the numbered table (safe; just lists)
#   wifi-audit.sh attack <N>      # attack list row N (refused unless ✅ authorized)
#   wifi-audit.sh                 # interactive: scan, then prompt for a number
set -uo pipefail

KALI="kali@192.168.64.2"
LAB="/Users/macbook/Ai agent /wifi-lab"
AUTH="$LAB/authorized-targets.txt"
CAPDIR="$HOME/wifi-lab-captures"; mkdir -p "$CAPDIR"
SSH="ssh -o ConnectTimeout=8"
PICK=/tmp/wifi-pick.txt

norm(){ printf '%s' "$1" | tr 'a-f' 'A-F' | tr -d ' '; }

# BSSID is authorized iff it appears (uncommented) in authorized-targets.txt
is_authorized(){
  local b; b=$(norm "$1")
  grep -vE '^[[:space:]]*#' "$AUTH" 2>/dev/null | awk '{print toupper($1)}' | grep -qx "$b"
}

scan(){
  echo "[*] scanning nearby Wi-Fi (channel-locked, ~40s)…" >&2
  $SSH "$KALI" 'sudo bash /home/kali/wifi-scan.sh' 2>/dev/null > /tmp/wifi-aps.txt
  if ! [ -s /tmp/wifi-aps.txt ]; then
    echo "[!] no APs found — adapter attached to Kali? in range? (retry, or check: ssh $KALI 'iw dev')" >&2
    return 1
  fi
}

show_table(){
  printf "\n  %-3s %-5s %-18s %-4s %-5s %-8s %s\n" "#" "AUTH" "BSSID" "CH" "PWR" "CLIENTS" "ESSID"
  echo   "  --------------------------------------------------------------------------"
  local n=0 b ch pw cl es mark
  : > "$PICK"
  while IFS='|' read -r b ch pw cl es; do
    [ -z "$b" ] && continue
    n=$((n+1))
    if is_authorized "$b"; then mark="OK"; else mark="--"; fi
    printf "  %-3s %-5s %-18s %-4s %-5s %-8s %s\n" "$n" "$mark" "$b" "$ch" "$pw" "$cl" "$es"
    printf "%s|%s|%s|%s|%s\n" "$n" "$b" "$ch" "$es" "$mark" >> "$PICK"
  done < /tmp/wifi-aps.txt
  echo   "  --------------------------------------------------------------------------"
  echo   "  OK = in authorized-targets.txt (attackable).   -- = NOT authorized (refused)."
}

attack(){   # $1 = row number (uses the last scan's $PICK)
  local n="$1" line b ch es
  [ -s "$PICK" ] || { echo "[!] run a scan first: wifi-audit.sh scan"; return 1; }
  line=$(awk -F'|' -v n="$n" '$1==n{print; exit}' "$PICK")
  [ -z "$line" ] && { echo "[!] no row #$n in the last scan"; return 1; }
  b=$(printf '%s' "$line" | cut -d'|' -f2)
  ch=$(printf '%s' "$line" | cut -d'|' -f3)
  es=$(printf '%s' "$line" | cut -d'|' -f4)

  # ---- HARD AUTHORIZATION GATE ----
  if ! is_authorized "$b"; then
    echo "[REFUSED] #$n  $b  ($es) is NOT in your authorized list."
    echo "          Only BSSIDs in $AUTH may be attacked."
    echo "          If this is YOUR gear or a sanctioned target, add its BSSID there, then rescan."
    return 2
  fi

  echo "[*] AUTHORIZED: #$n  $b  ($es)  ch$ch  — capturing handshake (needs a client connected)…"
  $SSH "$KALI" "sudo bash /home/kali/grab.sh $b $ch" 2>/dev/null | tee /tmp/wifi-grab.out
  if ! grep -q HANDSHAKE_CAPTURED /tmp/wifi-grab.out; then
    echo "[!] no handshake captured — a device must be connected to the target. Reconnect one and retry."
    return 3
  fi

  local safe ts out
  safe=$(printf '%s' "$es" | tr -c 'A-Za-z0-9._-' '_')
  ts=$(date +%Y%m%d-%H%M%S)
  out="$CAPDIR/${safe}-${ts}.cap"
  scp -o ConnectTimeout=8 "$KALI:/tmp/cap-01.cap" "$out" >/dev/null 2>&1
  echo "[*] saved: $out"
  echo "[*] cracking on the Mac GPU…"
  bash "$LAB/crack-mac.sh" "$out"
}

case "${1:-menu}" in
  scan)   scan && show_table ;;
  attack) attack "${2:?usage: wifi-audit.sh attack <row#>}" ;;
  menu|*) scan && show_table && {
            echo
            read -r -p "Pick a # to attack (only OK rows), or q to quit: " pick
            [ "${pick:-q}" = q ] && exit 0
            attack "$pick"
          } ;;
esac
