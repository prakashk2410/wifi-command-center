#!/bin/bash
# =============================================================================
# deploy.sh  (runs on the MAC)  --  push the Kali modules + the allowlist to Kali.
#
#   Usage:  bash deploy.sh
#
#   Copies common.sh + the four modules to /home/kali/, AND copies the
#   authorized-targets.txt allowlist there too -- the modules fail CLOSED if the
#   allowlist is missing, so this keeps the gate wired up. chmods everything +x.
#
#   Override the host with:  KALI=kali@192.168.64.2 bash deploy.sh
# =============================================================================
set -uo pipefail

KALI="${KALI:-kali@192.168.64.2}"
LAB="/Users/macbook/Ai agent /wifi-lab"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCP="scp -o ConnectTimeout=8"
SSH="ssh -o ConnectTimeout=8"

MODULES=(common.sh deauth.sh wps-attack.sh pmkid.sh rogue-ap-detector.sh recon.sh spoof.sh)

echo "[*] deploying modules to $KALI:/home/kali/ ..."
ok=1
for f in "${MODULES[@]}"; do
  if $SCP "$HERE/$f" "$KALI:/home/kali/$f" >/dev/null 2>&1; then
    echo "  ok   $f"
  else
    echo "  FAIL $f"; ok=0
  fi
done

# the allowlist that gates every attack -- must exist on Kali or modules refuse.
if [ -f "$LAB/authorized-targets.txt" ]; then
  if $SCP "$LAB/authorized-targets.txt" "$KALI:/home/kali/authorized-targets.txt" >/dev/null 2>&1; then
    echo "  ok   authorized-targets.txt   (the allowlist -- gates every attack)"
  else
    echo "  FAIL authorized-targets.txt"; ok=0
  fi
else
  echo "  WARN authorized-targets.txt not found in LAB -- modules will refuse until one is present on Kali"
fi

# chmod +x every module we just pushed -- derived from MODULES so it can't drift
CHMOD_PATHS=""
for f in "${MODULES[@]}"; do CHMOD_PATHS="$CHMOD_PATHS /home/kali/$f"; done
$SSH "$KALI" "chmod +x$CHMOD_PATHS 2>/dev/null; echo '  ok   chmod +x (${#MODULES[@]} modules)'" || ok=0

[ "$ok" = 1 ] && echo "RESULT=DEPLOY_DONE host=$KALI" || echo "RESULT=DEPLOY_PARTIAL host=$KALI (see FAIL/WARN lines above)"
