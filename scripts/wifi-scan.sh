#!/bin/bash
# wifi-scan.sh (runs in Kali) — list nearby 2.4GHz Wi-Fi APs with a CHANNEL-LOCKED sweep.
# This ONLY listens — it attacks nothing. The authorized-targets gate is enforced later,
# before any capture. Designed to be FAST + CHATTY so the Command Center live-log shows it
# working: primary channels (1/6/11) first with a longer dwell, then the rest quickly.
#
# Output contract (parsed by the backend): the FINAL block prints one line per AP as
#   BSSID|CH|PWR|CLIENTS|ESSID
# sorted most-clients then strongest. Every other line is a human "[scan] …" progress line
# that the backend ignores (it only parses lines whose 1st field is a MAC).
IF=wlan0
# Guarantee no airodump/aireplay is ever left orphaned (they can ignore SIGTERM and wedge the
# radio for every later scan). This fires on normal exit AND if our SSH session is dropped.
trap 'sudo pkill -9 airodump-ng aireplay-ng 2>/dev/null' EXIT HUP INT TERM
sudo pkill -9 airodump-ng 2>/dev/null; sleep 1
sudo rm -f /tmp/scan-ch* 2>/dev/null
sudo ip link set "$IF" down 2>/dev/null; sudo iw dev "$IF" set type monitor 2>/dev/null; sudo ip link set "$IF" up 2>/dev/null

# WARM the radio — the rtl8xxxu reports 0 APs on a stone-cold first scan until an injection
# test kicks it awake. A short test is enough once the adapter is already attached.
echo "[scan] warming the radio (injection test)…"
sudo iw dev "$IF" set channel 1 2>/dev/null
sudo timeout -k 2 4 aireplay-ng --test "$IF" >/dev/null 2>&1

# PRIMARY channels first (most 2.4GHz APs live on 1/6/11) — longer dwell so clients are caught.
for ch in 1 6 11; do
  echo "[scan] listening ch $ch (primary)…"
  sudo iw dev "$IF" set channel "$ch" 2>/dev/null
  sudo timeout -k 2 4 airodump-ng -c "$ch" "$IF" -w "/tmp/scan-ch$ch" --output-format csv >/dev/null 2>&1
done
# REMAINING channels — quick pass to catch anything on the edges.
for ch in 2 3 4 5 7 8 9 10 12 13; do
  echo "[scan] listening ch $ch…"
  sudo iw dev "$IF" set channel "$ch" 2>/dev/null
  sudo timeout -k 2 2 airodump-ng -c "$ch" "$IF" -w "/tmp/scan-ch$ch" --output-format csv >/dev/null 2>&1
done

echo "[scan] merging + de-duplicating…"
# merge all per-channel CSVs: dedupe APs (keep strongest), count clients per AP
awk -F, '
  FNR==1 { sec=1 }                                   # each file starts in the AP section
  /Station MAC,/ { sec=2; next }                     # ... then the station section
  sec==1 && $1 ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/ {
    b=toupper($1); gsub(/ /,"",b); c=$4; gsub(/ /,"",c); p=$9+0;
    e=$14; gsub(/^ +| +$/,"",e);
    if(!(b in S) || p>PW[b]) { CHN[b]=c; PW[b]=p; ES[b]=e } ; S[b]=1
  }
  sec==2 && $6 ~ /([0-9A-Fa-f]{2}:){5}/ { ab=toupper($6); gsub(/ /,"",ab); CL[ab]++ }
  END { for (b in S) printf "%s|%s|%s|%d|%s\n", b, CHN[b], PW[b], CL[b]+0, (ES[b]==""?"<hidden>":ES[b]) }
' /tmp/scan-ch*-01.csv 2>/dev/null | sort -t'|' -k4,4nr -k3,3nr
echo "[scan] done."
