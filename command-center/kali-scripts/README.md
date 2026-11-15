# Command Center — Kali modules

New attack/detect modules for the local Wi-Fi Command Center. They run **on the
Kali VM** (the radio); the Mac stays the controller and does the GPU cracking.
**Authorized targets only** — own gear / sanctioned competition / lab.

## Safety model (read first)
- **Every attack is gated by the allowlist** `/home/kali/authorized-targets.txt`.
  A BSSID that is not (uncommented) in that file is **refused** — there is no
  override in the attack path. Modules **fail closed** if the allowlist is missing.
- **No credential capture.** There is deliberately no fake-login, captive portal,
  or evil-twin AP here. `rogue-ap-detector.sh` is a **detector** that only listens.
- **No `modprobe`.** Every module soft-resets the adapter (`down → monitor → up`)
  via the shared `common.sh`; reloading the driver would drop the USB passthrough.
- **Bounded.** Everything is `timeout`-capped so nothing runs away.

## Deploy
```bash
bash deploy.sh          # pushes common.sh + modules + the allowlist to /home/kali/, chmods +x
```
`common.sh` must sit **next to** the modules — they source it and refuse to run without it.

## Modules
| script | call | does |
|---|---|---|
| `deauth.sh` | `deauth.sh <BSSID> [client_mac\|all] [secs]` | targeted or broadcast deauth (aireplay-ng, mdk4 fallback), 1–120s cap |
| `wps-attack.sh` | `wps-attack.sh <BSSID>` | Pixie-Dust first (reaver `-K 1`), then bounded reaver PIN brute; prints PIN + PSK |
| `pmkid.sh` | `pmkid.sh <BSSID> [chan]` | clientless PMKID → `/tmp/pmkid.pcapng`; single-AP filtered; falls back to a handshake |
| `recon.sh` | `recon.sh <BSSID> [chan]` | **allowlist-gated** focused client/station enumerate of one AP (receive-only airodump) |
| `spoof.sh` | `spoof.sh [random\|restore\|MAC]` | randomize **your own** adapter MAC via macchanger (no target, no gate) |
| `rogue-ap-detector.sh` | `rogue-ap-detector.sh <your_SSID>` | **defensive**: evil-twin, deauth-flood, Karma detection |

Each prints a machine-readable `RESULT=...` line on stdout (human chatter goes to stderr).

## Run (from the Mac controller)
```bash
ssh kali@192.168.64.2 'sudo bash /home/kali/deauth.sh AA:BB:CC:DD:EE:FF all 20'
ssh kali@192.168.64.2 'sudo bash /home/kali/wps-attack.sh AA:BB:CC:DD:EE:FF'
ssh kali@192.168.64.2 'sudo bash /home/kali/pmkid.sh AA:BB:CC:DD:EE:FF'
ssh kali@192.168.64.2 'sudo bash /home/kali/recon.sh AA:BB:CC:DD:EE:FF'
ssh kali@192.168.64.2 'sudo bash /home/kali/spoof.sh random'
ssh kali@192.168.64.2 'sudo bash /home/kali/rogue-ap-detector.sh "MyHomeWiFi"'
```
Crack a captured PMKID/handshake on the Mac GPU: `crack-mac.sh /tmp/pmkid.pcapng`.

## Tunables (env)
`MAXSECS` (deauth cap) · `PIXIE_T` `BRUTE_T` `WASH_T` `FORCE_BRUTE` (wps) ·
`CAP_T` (pmkid) · `SCAN_T` `DEAUTH_THRESH` `KARMA_THRESH` (detector) ·
`IFACE` `AUTH_FILE` (all).
