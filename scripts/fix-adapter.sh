#!/bin/bash
# Soft-reset a hung monitor-mode USB Wi-Fi adapter on Kali (down -> monitor -> up).
#
# IMPORTANT: NEVER `modprobe -r/-modprobe` a PASSED-THROUGH USB adapter. Reloading the driver
# disconnects the USB device from the guest, and it then needs a Mac-side re-attach to come back
# (verified 2026-11-12: the old modprobe reset made wlan0 vanish; recovery = utmctl usb
# disconnect/connect from the Mac). A soft reset clears most hangs WITHOUT dropping passthrough.
#
# If wlan0 is GONE, re-attach from the Mac:
#     utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
#
# Usage (from the Mac):  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'
set -uo pipefail

IF=$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')
if [ -z "$IF" ]; then
  echo "[!] no wlan interface — the USB adapter dropped from the VM."
  echo "    Re-attach from the Mac:  utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C"
  exit 2
fi

echo "[*] soft-resetting $IF (down -> set monitor -> up; no driver reload)"
sudo ip link set "$IF" down 2>/dev/null
sudo iw dev "$IF" set type monitor 2>/dev/null
sudo ip link set "$IF" up 2>/dev/null
sleep 1

MODE=$(iw dev "$IF" info 2>/dev/null | awk '/type/{print $2}')
echo "[*] $IF is now mode=${MODE:-unknown}"
if [ "$MODE" = "monitor" ]; then
  echo "ADAPTER_RESET_DONE"
else
  echo "[!] still not in monitor mode — HARD RESET from the Mac:"
  echo "    utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C"
  exit 4
fi
