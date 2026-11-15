# Wordlist Strategy for WiFi (WPA/WPA2-PSK)

> **Scope & authorization.** This reference is for **authorized** work only: your own networks, lab
> gear you control, sanctioned engagements with written scope, CTFs, and OSWP study. WPA cracking is
> an **offline** attack — you capture a handshake/PMKID once, then grind candidate passphrases against
> it on your own hardware. Nothing here touches a third-party network. Every offensive note is paired
> with the **defense** at the end. Keep an allowlist (BSSID/ESSID you are cleared to test) and refuse
> anything not on it.

---

## 1. Concept (brief)

WPA/WPA2-PSK cracking is a **dictionary problem**, not a protocol break. Once you own a valid
4-way-handshake or a PMKID, the PBKDF2-HMAC-SHA1 derivation (`PMK = PBKDF2(psk, essid, 4096, 256)`)
is fixed. You cannot "reverse" it — you can only **guess the passphrase**, hash each guess, and
compare. So the entire engagement hinges on **which guesses you try and in what order**. That is
wordlist strategy.

Two facts drive everything:

1. **The algorithm is deliberately slow.** 4096 PBKDF2 iterations means even a strong GPU does
   *hundreds of thousands* of guesses/sec for WPA, versus *tens of billions*/sec for raw MD5/NTLM.
   A consumer GPU (e.g. an Apple Silicon Mac via Metal, or an RTX card) lands roughly in the
   **100k–1M H/s** band for mode 22000. Aircrack-ng's CPU path is far slower (~50–300 keys/sec).
   **You cannot brute-force the full keyspace.** Candidate quality and ordering are everything.
2. **The PSK is 8–63 characters.** The 802.11i standard mandates an **8-char minimum** and a
   **63-char maximum** (64 hex = a raw PMK, a separate case). This single rule lets you discard a
   huge fraction of generic wordlists before you spend a cycle on them.

**What the real-world key distribution looks like** (PACK analysis of 10,737 *recovered* WPA keys,
from the hashcat WPA-strategy thread — biased toward crackable keys, but directionally gold):

| Pattern | Share | Meaning for strategy |
|---|---|---|
| Length **exactly 8** | **54%** | Shortest legal key is overwhelmingly the most common. Prioritize len-8. |
| **Numeric-only** (`?d…`) | **37%** | Over a third are just digits. |
| **8 digits** `?d?d?d?d?d?d?d?d` | **29%** | The single largest pattern. Cheap mask, run it early. |
| `stringdigit` (word + numbers) | **20%** | Base word padded with dates/sequences → rules territory. |
| 8 lowercase `?l×8` | **9%** | |
| 10 digits `?d×10` | **3%** | Common ISP default style. |
| mixed-case alphanumeric | **2%** | Rare — deprioritize heavy mutation. |

Takeaway: **digits and 8-char keys dominate.** A good WiFi run is *not* "throw rockyou at it" — it
is a short digit mask, then a curated WiFi-length human list, then targeted lists, then (rarely) the
monsters.

---

## 2. The wordlist arsenal — tiered, smallest → largest

Order of attack = **smallest + most-probable first**, because WPA is slow and a hit on a 50MB list
beats a week on a 100GB list. Build the ladder below once and reuse it.

### Tier 0 — Targeted / generated (tiny, highest hit-rate per candidate)
- **ISP/OEM default-key patterns** for the exact router. Many ISPs ship defaults like 8–10 uppercase
  hex, or `<word><digits>`. Identify the vendor from the ESSID/OUI first, then generate only that
  shape with a mask (see §5). xoxox's note from the field: *10-digit hex defaults are common.*
- **OSINT / CUPP / custom** lists built from the target's own data (owner name, pet, street, phone,
  founding year, business name). Small, often decisive. See `osint-password-profiling.md`.
- **ESSID-derived words.** People bake the network name into the key. Extract ESSIDs straight from
  the capture (see §4) and feed them in with rules.

### Tier 1 — rockyou (the baseline, ~134 MB / 14,344,392 lines)
The canonical first dictionary. Ships with Kali at `/usr/share/wordlists/rockyou.txt.gz`. **Must be
8+ filtered for WiFi** (see §4) — ~60% of its lines are < 8 chars and are *illegal* WPA keys.

### Tier 2 — WiFi-specific "probable" lists (curated, already length-aware)
- **SecLists → WiFi/WPA probable lists.** Installed to `/usr/share/seclists` on Kali
  (`sudo apt install seclists`). Pulls in curated WPA-oriented lists.
- **Probable-Wordlists (berzerk0)** → `Real-Passwords/WPA-Length/`. These are **sorted by
  popularity, not alphabetically** — most-seen passwords first, so you crack early or not at all.
  Entries span **8–40 chars**; a password had to appear **≥5 times** across ~1,600 source files
  (~350 GB, ~13 billion raw → ~2 billion deduped) to make the cut. Sources include SecLists,
  weakpass, hashes.org; crackstation/hashkiller credited. **Gotcha:** v1 WPA-Length lists had a
  newline-dup defect that left some 7-char lines in — re-filter to 8+ yourself (§4).
  The widely-cited `Top*Million-probable-WPA.txt` family lives here.
- **Kali's `wifite.txt`** → symlink to `/usr/share/dict/wordlist-probable.txt`; the default wifite
  uses.

### Tier 3 — weakpass (large, ranked, general-purpose)
From weakpass.com / `github.com/zzzteph/weakpass`. Published as ranked merged lists (the
`weakpass_*` / `*.merged` family) that grow from a few GB into tens of GB. Not WiFi-specific, so
**8+ filter** before use. The site also hosts a client-side generator (`passgen`) and a hash→password
range-lookup API (not a WiFi path, but the same ecosystem).

### Tier 4 — crackstation (big general dumps)
- **Human-only** (`crackstation-human-only.txt.gz`, ~258 MB compressed) — real leaked human
  passwords; the high-value one for WPA. CC-BY-SA-3.0 via Academic Torrents.
- **Full dictionary** (~15 GB, ~1.49 billion words) — mostly *not* real passwords (dictionaries,
  concatenations). Low marginal yield for WPA; treat as last-resort. Community wisdom:
  *"bigger wordlist really doesn't translate into more cracks."*

### Tier 5 — the monsters (last resort, days of runtime)
Multi-GB/TB merges (e.g. `Weakpass_4`, `HashMob`/`hashes.org` founds, `kennyn510/wpa2-wordlists`
collections). Run only after Tiers 0–4 + masks + rules have failed and you still have authorization
and time. Diminishing returns rise steeply here.

**Golden rule:** *More list ≠ more cracks.* A focused 50M-line list built from leaked 8+ passwords,
name/word combinations, and permutations (xor's best performer) routinely beats a blind 13GB WPA
list ("useless so far," same thread).

---

## 3. Where the lists live & how to get them (Kali)

```bash
# Kali's wordlist hub (mostly symlinks into tool dirs):
ls -l /usr/share/wordlists/

# rockyou ships gzipped — decompress once (keep a copy with -k):
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz   # -> rockyou.txt (~134 MB, 14,344,392 lines)

# Install the meta-package and SecLists:
sudo apt update
sudo apt install -y wordlists seclists
#   seclists -> /usr/share/seclists
#   wifite.txt -> /usr/share/dict/wordlist-probable.txt

# Probable-Wordlists (WPA-Length lists): clone/pull from berzerk0's repo or its torrents.
# crackstation-human-only + Probable-Wordlists are distributed via Academic Torrents (CC-BY-SA-3.0).
```

Keep your curated WiFi lists in the lab, e.g. `~/wifi-lab/wordlists/`, named by tier so the attack
script can walk them in order:

```
00_targeted_<essid>.txt      # per-engagement, generated fresh
10_rockyou-wifi.txt          # rockyou, 8+ filtered
20_seclists-wpa.txt          # SecLists WPA probable, 8+ filtered, deduped
21_probable-wpa.txt          # Probable-Wordlists WPA-Length, 8+ re-filtered
30_weakpass-wifi.txt         # weakpass, 8+ filtered  (big)
40_crackstation-human.txt    # crackstation human-only, 8+ filtered (big)
90_monster.txt               # last resort
```

---

## 4. Curation — the commands that make lists WiFi-legal and fast

### 4.1 Enforce the 8–63 length window (the single most important filter)
Hashcat **early-rejects** any candidate shorter than 8 for mode 22000 *before rules run* (you'll see
them in the `Rejected` counter). Pre-filtering removes that waste and shrinks the file:

```bash
# Keep only 8..63 character lines (the legal WPA PSK window):
awk 'length>=8 && length<=63' rockyou.txt > rockyou-wifi.txt

# Length-only lower bound (most common shorthand you'll see in guides):
awk 'length>=8' rockyou.txt > rockyou-wifi.txt
```

> **Critical rules caveat.** If you plan to run **rules** (e.g. append digits), do **not** pre-drop
> short base words — a rule could turn `timmy` into `timmy666` (legal), but a pre-filtered list
> already deleted `timmy`. Two correct options:
> 1. Keep the unfiltered list and add **`-S` (slow-candidates mode)**: hashcat applies rules host-side
>    into an in-memory virtual wordlist, so short bases survive to be extended. Costs speed.
> 2. **Pre-apply** the rules to materialize the mutated list, then length-filter the *output*:
>    ```bash
>    hashcat --stdout rockyou.txt -r rules/best64.rule | awk 'length>=8 && length<=63' \
>      | sort -u > rockyou-best64-wifi.txt
>    ```
> `--force` does **not** bypass the length reject — don't try it.

### 4.2 Dedup, sort, and merge tiers without re-testing candidates
```bash
# Dedup a single list (sorted unique):
sort -u 21_probable-wpa.txt -o 21_probable-wpa.txt

# Merge many lists but test each candidate only once across all of them:
cat 10_*.txt 20_*.txt 21_*.txt | awk 'length>=8 && length<=63' | sort -u > merged-wifi.txt

# Remove candidates you've ALREADY tried (set difference) so a re-run skips them:
# (requires both files sorted)
comm -23 <(sort -u big.txt) <(sort -u already_tried.txt) > remaining.txt
```

### 4.3 hashcat-utils / rling for curation at scale
```bash
# splitlen: bucket a list by candidate length (run len-8 first — it's 54% of real keys):
splitlen outdir < merged-wifi.txt      # creates outdir/8, outdir/9, ...
hashcat -m 22000 hash.hc22000 outdir/8   # highest-probability bucket first

# rli / rli2: fast "remove items in list B from list A" (dedup across huge files):
rli merged-wifi.txt remaining.txt already_tried.txt

# combinator: word1+word2 (great for passphrase-style keys like "sunshinebeach"):
combinator names.txt nouns.txt | awk 'length>=8 && length<=63' > combos-wifi.txt
```

### 4.4 Pull ESSIDs out of the capture to seed a targeted list
The network name is a top source of real keys. Extract every ESSID seen in the capture and feed it
in (with rules to append years/digits):

```bash
# hcxpcapngtool can emit an ESSID list while converting (-E):
hcxpcapngtool -o hash.hc22000 -E essids.txt capture.pcapng
awk 'length>=8 && length<=63' essids.txt > 00_essid-seed.txt      # or feed raw + rules via -S
```

---

## 5. Decision order — the sequence pros actually run

This is the heart of the skill: **cheap, targeted, high-probability attacks first; brute monsters
last.** Interleave masks (free, no file) with dictionaries. Everything is mode **22000**, attack
mode **`-a 0`** for dictionaries and **`-a 3`** for masks.

```bash
# --- Step 0: convert the capture once ---
hcxpcapngtool -o hash.hc22000 -E essids.txt capture.pcapng

# --- Step 1: digits first (37% of keys are numeric; 8 digits alone = 29%) ---
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d                 # 8 digits  (~29%)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d             # 10 digits (ISP defaults, ~3%)
hashcat -m 22000 hash.hc22000 -a 3 -1 ?d ?1?1?1?1?1?1?1?1?1          # 9 digits
#   phone-style: country/area prefix + mask, e.g. 10-digit NANP:
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d

# --- Step 2: ISP/OEM default shape (identify vendor from ESSID/OUI first) ---
#   e.g. 8 uppercase hex default keys:
hashcat -m 22000 hash.hc22000 -a 3 -1 ?u?d ?1?1?1?1?1?1?1?1

# --- Step 3: targeted/OSINT/ESSID list (tiny, decisive) ---
hashcat -m 22000 hash.hc22000 00_targeted_<essid>.txt
hashcat -m 22000 hash.hc22000 00_essid-seed.txt -r rules/best64.rule -S

# --- Step 4: rockyou (8+ filtered), plain then with rules ---
hashcat -m 22000 hash.hc22000 10_rockyou-wifi.txt
hashcat -m 22000 hash.hc22000 10_rockyou-wifi.txt -r rules/best64.rule -S

# --- Step 5: WiFi-probable curated lists (SecLists / Probable-Wordlists) ---
hashcat -m 22000 hash.hc22000 20_seclists-wpa.txt
hashcat -m 22000 hash.hc22000 21_probable-wpa.txt            # already popularity-sorted

# --- Step 6: hybrid — dict + appended digits/years (catches "stringdigit", ~20%) ---
hashcat -m 22000 hash.hc22000 -a 6 10_rockyou-wifi.txt ?d?d?d?d      # word + 4 digits
hashcat -m 22000 hash.hc22000 -a 7 ?d?d?d?d 10_rockyou-wifi.txt      # 4 digits + word

# --- Step 7: big general lists (weakpass, crackstation human-only) ---
hashcat -m 22000 hash.hc22000 30_weakpass-wifi.txt
hashcat -m 22000 hash.hc22000 40_crackstation-human.txt

# --- Step 8: last resort — monster list, or broad mask with an estimate first ---
hashcat -m 22000 hash.hc22000 --keyspace -a 3 ?a?a?a?a?a?a?a?a       # size the job BEFORE running
hashcat -m 22000 hash.hc22000 90_monster.txt
```

**Why this order:** cheap digit masks cover ~40% of real keys in minutes; targeted lists exploit what
you know about the owner; rockyou+rules sweeps common human passwords; probable lists are
pre-ranked so you win early or move on; hybrids catch the word+digits pattern; the giants come last
because their *marginal* yield per hour is tiny. Field consensus (epixoip, hawaii): **knowing the
target beats cold cracking** — WPA is too slow to "spray and pray."

---

## 6. Exact hashcat reference (mode 22000)

```bash
# Dictionary (attack mode 0 is the default):
hashcat -m 22000 hash.hc22000 wordlist.txt

# Dictionary + rules (mutations). Use -S so sub-8 base words survive to be extended:
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule -S

# Mask / brute (attack mode 3):
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Hybrid dict+mask (6) and mask+dict (7):
hashcat -m 22000 hash.hc22000 -a 6 wordlist.txt ?d?d?d?d
hashcat -m 22000 hash.hc22000 -a 7 ?d?d?d?d wordlist.txt

# Gzip wordlists feed directly — no need to decompress:
hashcat -m 22000 hash.hc22000 crackstation-human-only.txt.gz

# Useful flags:
#   --keyspace          print candidate count (size the job before committing)
#   --status --status-timer=10   periodic progress
#   --potfile-path FILE keep a per-engagement potfile of cracks
#   --loopback          (with -r) feed newly cracked words back through the rules
#   -O                  optimized kernels (faster; caps candidate length ~31 — fine for WPA)
#   -w 3                workload profile (higher = more GPU, less interactivity)
#   -S                  slow-candidates mode (needed for rules on unfiltered WiFi lists)
#   --show / --left     show cracked / remaining after a run

# 22001 verifies a known PMK (64 hex) — not a passphrase attack path.
```

**hcxpcapngtool conversion notes:** convert the raw capture to `.hc22000` with
`hcxpcapngtool -o hash.hc22000 -E essids.txt capture.pcapng`. Do **not** "clean" captures with
`wpaclean` or merge pcapng files — it corrupts fields hashcat needs. Old `.cap` can be converted;
legacy `.hccapx` (mode 2500) and PMKID mode 16800 are **deprecated** — always target **22000**.

---

## 7. aircrack-ng path (CPU, for quick checks / no-GPU hosts)

```bash
# Dictionary attack against a captured handshake:
aircrack-ng -w rockyou-wifi.txt -b 00:14:6C:7E:40:80 capture*.cap
#   -w  wordlist   (full path if not in cwd)
#   -b  target BSSID
#   capture*.cap   airodump-ng output (wildcard matches split files)
```

- Aircrack-ng is **CPU-only and slow** (~50–300 keys/sec) — fine for a tiny targeted list or a sanity
  check, hopeless for big lists. For anything real, convert and use **hashcat on the GPU**.
- "If the passphrase is not in the dictionary, aircrack-ng cannot find the key." Same truth for every
  tool: **no list contains the key → no crack.** That is a feature of WPA, not a bug in your setup.
- A tiny `password.lst` ships in aircrack-ng's `test/` dir for smoke-testing your pipeline.

---

## 8. Pro tips for speed & yield

- **Run the 8-digit mask first, always.** It's the single largest real pattern (~29%), needs no file,
  and finishes fast. `-a 3 ?d?d?d?d?d?d?d?d`.
- **Bucket by length and do len-8 first** (`splitlen`) — 54% of real keys are exactly 8 chars.
- **Estimate before you commit.** `--keyspace` + your benchmark H/s tells you if a mask/list is a
  10-minute job or a 3-week job. `hashcat -b -m 22000` for your rig's WPA speed.
- **Pre-apply rules and length-filter the output** (§4.1) to get a flat, WiFi-legal list you can
  reuse across many captures without the `-S` speed penalty each time.
- **Dedup across tiers** (`sort -u`, `rli`) so a candidate is never hashed twice; track tried
  candidates and subtract them (`comm -23`) on re-runs.
- **Feed `.gz` directly** — don't waste disk decompressing crackstation/weakpass.
- **`--loopback`** with rules: cracked keys get re-mutated, often catching a second AP using a
  variant of the same base.
- **Potfile hygiene:** per-engagement `--potfile-path` so a lab crack doesn't leak into the next
  client's run, and so `--show` only reports this engagement.
- **Favor curated over colossal.** A 50M list of leaked 8+ passwords + name/word combinations + simple
  permutations out-cracks a blind 13GB "WPA" list. Build quality; don't hoard size.
- **Thermals:** sustained WPA runs peg the GPU for hours — watch temps; a throttled card quietly
  halves your H/s. See `gpu-cracking-optimization.md`.

---

## 9. Pitfalls & gotchas

- **Sub-8 candidates are silently rejected** before rules run (watch the `Rejected` counter). Filter
  to 8+ *or* use `-S` with rules. `--force` will **not** override the length check.
- **Pre-filtering kills rule bases.** If you want `word`→`word1234`, don't delete `word` first — use
  `-S` or pre-apply the rules then filter the *output* (§4.1).
- **Probable-Wordlists v1 WPA-Length defect:** some 7-char lines slipped through via a newline-dup
  bug. Re-run `awk 'length>=8'` yourself.
- **Length window is 8–63**, not just "≥8". A handful of generators emit 64+ char junk — cap at 63 to
  avoid wasted candidates.
- **Don't `wpaclean`/merge pcapng** before `hcxpcapngtool` — it strips fields and your hash won't
  convert or crack.
- **Deprecated modes (2500/16800):** old tutorials still show `.hccapx`/`-m 2500`. Always use 22000.
- **Big ≠ better.** Tiers 4–5 cost hours for small marginal gains. Exhaust targeted + masks + rules
  first.
- **The key may simply not be in any list.** A high-entropy random PSK is *uncrackable* by dictionary.
  Recognize that early and stop burning power — report it as "not recoverable by wordlist," which is
  itself a finding.
- **Charset/encoding:** non-ASCII/UTF-8 passphrases exist; most leaked lists are ASCII-biased. Note it
  as a coverage gap rather than a failure.

---

## 10. DEFENSE — how this whole chapter is defeated

The entire attack collapses against a passphrase that isn't in, or reachable from, any wordlist.
This is the *point* of the exercise: show the owner why the following kills offline cracking.

- **Use a long, high-entropy PSK.** A random 20+ char passphrase, or a 5–6 word diceware phrase
  (e.g. `correct-horse-battery-staple-lamp`), has entropy far beyond any practical wordlist or mask.
  Every attack in §5 fails by construction — the candidate is never generated.
- **No digits-only, no 8-char keys, no `word+1234`.** You just saw that 8-digit and word+digits
  patterns cover the majority of *recovered* keys. Those are exactly what a defender must avoid.
- **Never reuse the ESSID, SSID, phone number, address, or owner's name** in the key — those are the
  first things pulled from the capture and from OSINT.
- **Don't rely on ISP/OEM default keys.** Many are a known shape (8–10 hex/uppercase) that a vendor
  mask cracks in minutes. Change the default on day one.
- **Prefer WPA3-SAE where supported.** SAE (Dragonfly) is resistant to *offline* dictionary attack:
  even with a captured exchange, an attacker can't grind candidates offline the way WPA2-PSK allows.
  (Caveats: transition mode and the Dragonblood-class issues — see `wpa3-sae-dragonblood.md`.)
- **For many users, use 802.1X/EAP (WPA-Enterprise)** with per-user credentials instead of a shared
  PSK, so there is no single handshake to crack. See `wpa-enterprise-eap.md`.
- **Detection/monitoring:** repeated deauth floods (the usual way an attacker *forces* a handshake)
  are observable — 802.11w/PMF (Protected Management Frames) blocks the deauth trick and is the
  defensive control to enable. See `deauth-dos.md` and `handshake-capture.md`.
- **Operational:** rotate the PSK if it may have been exposed; segment guests onto their own
  SSID/VLAN so a cracked guest key yields nothing of value.

**One-line summary for a report:** *WPA2-PSK security is entirely the entropy of the passphrase. A
random 20+ char or 5+ word key makes every wordlist, mask, and rule in this document useless; a short,
numeric, or name/word-based key makes them trivial.*

---

## Sources

- hashcat wiki — Cracking WPA/WPA2 (mode 22000/22001, 8–63 PSK, conversion, dict/mask/rule syntax, deprecations): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- aircrack-ng.org — Cracking WPA (`-w`/`-b` syntax, 8–63 chars, ~50–300 keys/sec, "not in dict → no key"): https://www.aircrack-ng.org/doku.php?id=cracking_wpa
- Kali Linux — wordlists package & paths (`/usr/share/wordlists`, rockyou.txt.gz → 134 MB/14,344,392 lines, seclists, `wifite.txt`→`wordlist-probable.txt`): https://www.kali.org/tools/wordlists/
- berzerk0 Probable-Wordlists — WPA-Length lists, popularity sorting, 8–40 char range, ≥5-occurrence threshold, sources, v1 newline-dup defect: https://github.com/berzerk0/Probable-Wordlists  (README: https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/README.md)
- hashcat forum — "WPA Specific Strategies, Stats and Lists" (PACK stats: 54% len-8, 37% numeric, 29% 8-digit; ISP-default/geo strategy; curated-beats-colossal): https://hashcat.net/forum/thread-4431.html
- hashcat forum — slow-candidates `-S` & sub-8 early-reject behavior for WPA rules: https://hashcat.net/forum/thread-9838.html , https://hashcat.net/forum/post-49399.html
- hashcat docs — slow-candidates mode: https://git.ventilaar.nl/github/hashcat/src/commit/546b94f3d205e92b13bb67ab43acd8878e9dd5b3/docs/slow-candidates-mode.md
- zzzteph/weakpass — weakpass tooling, generator, ranges (tools.weakpass.com): https://github.com/zzzteph/weakpass
- CrackStation dictionary — human-only (~258 MB gz, CC-BY-SA-3.0) vs full ~15 GB/1.49B words; "bigger ≠ more cracks": https://academictorrents.com/details/7ae809ccd7f0778328ab4b357e777040248b8c7f , https://crackstation.net/
- Volkis handbook — generating effective wordlists (length filtering, awk 8+): https://handbook.volkis.com.au/services/generating-effective-wordlists/
- kennyn510/wpa2-wordlists — WPA-oriented wordlist collection & filtering notes: https://github.com/kennyn510/wpa2-wordlists
