#!/bin/bash
# kali-toolkit-install.sh — install the FULL Wi-Fi security toolkit in Kali (run once, needs internet).
# For authorized learning / sanctioned testing on your own gear. Run:  sudo bash kali-toolkit-install.sh
set -uo pipefail
echo "[*] updating apt…"; sudo apt-get update -y

# --- core apt packages ---
PKGS=(
  aircrack-ng        # capture + crack + deauth (airodump/aireplay/aircrack)
  hashcat            # GPU/CPU cracking (we crack on the Mac GPU, but handy here too)
  hcxtools           # hcxpcapngtool: convert .cap -> hashcat 22000
  hcxdumptool        # PMKID / clientless capture
  reaver             # WPS PIN brute-force
  bully              # WPS PIN brute-force (alternative)
  pixiewps           # WPS Pixie-Dust (offline PIN recovery — instant win when vulnerable)
  wifite             # automated wrapper (handshake/WPS/PMKID) — great for learning the flow
  mdk4               # deauth/beacon/auth floods (DoS family)
  cowpatty           # WPA handshake verify/crack helper
  hostapd            # stand up an AP (evil-twin base)
  dnsmasq            # DHCP/DNS for a rogue AP / MITM lab
  bettercap          # MITM framework: ARP/DNS spoof, sniffing
  asleap             # crack MSCHAPv2 (WPA-Enterprise / PEAP)
  freeradius-utils   # test RADIUS tools (enterprise lab)
  tshark             # CLI Wireshark (frame analysis, probe sniffing)
  macchanger         # MAC spoofing / bypass MAC filters
  iw wireless-tools net-tools   # interface management
  git build-essential python3-pip   # for the from-source tools below
)
echo "[*] installing: ${PKGS[*]}"
sudo apt-get install -y "${PKGS[@]}"

# --- from source / git (not always in apt) ---
mkdir -p /opt/wifi-tools && cd /opt/wifi-tools

# eaphammer — WPA-Enterprise evil-twin / credential (MSCHAPv2) capture for YOUR OWN enterprise lab
if [ ! -d eaphammer ]; then
  echo "[*] cloning eaphammer…"
  git clone https://github.com/s0lst1c3/eaphammer.git 2>/dev/null \
    && (cd eaphammer && yes | sudo ./kali-setup 2>/dev/null) || echo "[!] eaphammer setup needs a manual run: cd /opt/wifi-tools/eaphammer && sudo ./kali-setup"
fi

# hostapd-mana — Karma/MANA rogue AP (answers every probe)
if [ ! -d mana ]; then
  echo "[*] cloning hostapd-mana…"
  git clone https://github.com/sensepost/hostapd-mana.git 2>/dev/null || echo "[!] clone hostapd-mana manually if needed"
fi

echo
echo "=== quick check ==="
for t in airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool reaver bully pixiewps wifite mdk4 hostapd dnsmasq bettercap asleap tshark macchanger; do
  command -v "$t" >/dev/null && echo "  ok   $t" || echo "  MISS $t"
done
echo
echo "[*] done. eaphammer: /opt/wifi-tools/eaphammer   |   hostapd-mana: /opt/wifi-tools/mana"
echo "[*] reminder: authorized targets only. Use these against your own gear / sanctioned labs."
