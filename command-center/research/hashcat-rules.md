# Hashcat Rules for WPA Cracking (mode 22000)

> **Scope / authorization.** This reference is for recovering pre-shared keys from
> **WPA/WPA2 handshakes you are authorized to test** — your own gear, a sanctioned
> engagement with written scope, a CTF, or OSWP study. Password cracking is a
> local, offline operation against a capture **you already lawfully hold**. Nothing
> here helps you obtain a handshake you are not entitled to. Every offensive note
> is paired with the matching defense (see **§13 Defense**).

---

## 1. Concept (brief)

A **rule** is a one-line program in hashcat's small mutation language. Each rule is
applied to **every word in your wordlist on the fly** (nothing expanded to disk),
turning e.g. `summer` into `Summer2024!`. A **rule file** (`-r file.rule`) is a list
of such programs; hashcat multiplies your wordlist by the rule count, so a 14.3 M
word list × a 52 k-rule file = ~745 **billion** candidates from one pass.

Why rules dominate real WPA cracking:

- Real Wi-Fi passphrases are overwhelmingly **human-chosen**: a base word plus
  predictable mangling (capital, year, `!`, `123`, leet). Rules encode exactly those
  human habits, so a good wordlist + rule set out-performs raw brute force by orders
  of magnitude **on the passwords people actually pick**.
- Mode 22000 is a **slow** hash (PBKDF2-HMAC-SHA1, 4096 iterations). You get far
  fewer guesses/second than with fast hashes, so **every candidate must earn its
  place**. Rules let you spend your limited guess budget on likely passwords instead
  of exhausting a keyspace you'll never finish.

The whole discipline is a **keyspace vs. time tradeoff**: more rules = more coverage
= more hours. Sections 7–9 make that tradeoff concrete.

---

## 2. Mode 22000 facts that shape every rule decision

Mode 22000 = **WPA-PBKDF2-PMKID+EAPOL** (since hashcat 6.0.0, it unifies the old
`2500` EAPOL and `16800` PMKID plugins; both are deprecated). Mode **22001** verifies
a known PMK (64 hex) instead of a passphrase.

Two hard constraints from the WPA spec drive rule/mask choice:

- **PSK length is 8–63 characters.** hashcat **rejects/skips any candidate outside
  8–63** for mode 22000. This is the single most important fact for rules: any rule
  that shortens a base word **below 8 chars** (`]`, `[`, `'N`, over-aggressive delete)
  produces a candidate that **cannot be the key** and is wasted work. Favor rules that
  *append/prepend/substitute*; be wary of truncation rules on short base words.
- **Two hash-line types** (format matters when filtering, not when cracking — both go
  into one `-m 22000` run):
  - PMKID: `WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR`
  - EAPOL: `WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR`

**The ESSID is cracking gold.** The network name is embedded in the hash line. People
bury the SSID, street name, or ISP in the passphrase constantly, so **derive a
targeted wordlist from the ESSID** and run it first (see §9).

---

## 3. End-to-end workflow (capture → convert → crack)

Rules only matter at the last step, but the commands before it set the format.

```bash
# 0) (on Kali, adapter in monitor mode) free the radio first
sudo systemctl stop NetworkManager
sudo airmon-ng check kill            # kills wpa_supplicant/NetworkManager leftovers

# 1) CAPTURE — authorized target only. hcxdumptool writes pcapng.
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
#   (do NOT run hcxdumptool on a virtual interface — hashcat wiki warning)

# 2) CONVERT to hashcat's hc22000 format
hcxpcapngtool -o hash.hc22000 -E essid-wordlist.txt dump.pcapng
#   -E also dumps every seen ESSID to a file you can feed back as a wordlist

# 3a) (optional) FILTER — split/clean before you burn GPU time
hcxhashtool -i hash.hc22000 --type=2 -o eapol-only.hc22000   # 2=EAPOL, 1=PMKID
#   or, by hand:  grep 'WPA\*01' = PMKID,  grep 'WPA\*02' = EAPOL

# 4) CRACK — this is where rules live (next sections)
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule
```

**Version discipline:** keep `hcxdumptool` and `hcxpcapngtool` on the **same hcxtools
version** — mismatches silently corrupt conversions. The converter does **not** filter
junk; use `hcxhashtool` to drop noise so you aren't cracking garbage.

---

## 4. Rule syntax reference (the full language)

`N`/`M` = positions (0-based; `A`–`Z` = positions 10–35). `X`/`Y` = a single character.
Rules operate on **single bytes**, are **not** whitespace-separated, and each line /
combined chain is capped at **31 functions**. Comment lines start with `#`.

### Core transforms (work in a rule file)

| Rule | Does | Example on `p@ssW0rd` |
|---|---|---|
| `:` | no-op (pass word through) | `p@ssW0rd` |
| `l` / `u` | lowercase / uppercase all | `p@ssw0rd` / `P@SSW0RD` |
| `c` / `C` | Capitalize / inverse-capitalize | `P@ssw0rd` / `p@SSW0RD` |
| `t` / `TN` | toggle all / toggle at N | `T3` → `p@sSW0rd` |
| `r` | reverse | `dr0Wss@p` |
| `d` / `pN` | duplicate / append N dup copies | `p@ssW0rdp@ssW0rd` |
| `f` | reflect (append reversed) | `p@ssW0rddr0Wss@p` |
| `{` / `}` | rotate left / right | `@ssW0rdp` / `dp@ssW0r` |
| `$X` / `^X` | append / prepend X | `$1` → `p@ssW0rd1`; `^1` → `1p@ssW0rd` |
| `[` / `]` | delete first / last char | `@ssW0rd` / `p@ssW0r` |
| `DN` | delete char at N | `D3` → `p@sW0rd` |
| `xNM` / `ONM` | extract / omit M chars from N | `x04`→`p@ss`; `O12`→`psW0rd` |
| `iNX` / `oNX` | insert / overwrite X at N | `i4!`→`p@ss!W0rd`; `o3$`→`p@s$W0rd` |
| `'N` | truncate at length N | `'6` → `p@ssW0` |
| `sXY` | replace all X with Y (leet) | `ss$` → `p@$$W0rd` |
| `@X` | purge all X | `@s` → `p@W0rd` |
| `zN` / `ZN` | dup first / last char N times | `z2`→`ppp@ssW0rd`; `Z2`→`p@ssW0rddd` |
| `q` | duplicate every char | `pp@@ssss…` |
| `k` / `K` | swap first two / last two chars | — |
| `*NM` | swap chars at N and M | — |
| `yN` / `YN` | duplicate first / last N chars | — |
| `E` / `eX` | title-case / title-case on separator X | — |
| `+N` `-N` `.N` `,N` `LN` `RN` | inc/dec/replace-by-neighbor/bit-shift at N | — |

### Memory, rejection & positional (`-j` / `-k` only — **not** in a normal `-r` file)

- **Memory:** `M` memorize, `4` append memory, `6` prepend memory, `XNMI` insert from memory.
- **Reject:** `<N` (len > N), `>N` (len < N), `_N` (len != N), `!X`/`/X` (contains / lacks X),
  `(X`/`)X` (starts / ends with X), `=NX` (pos N is X), `%NX` (X appears ≥N), `Q` (equals memory).
- **Positional `p`** records the Nth instance of a char (set by `%`/`/`): e.g. `%2s Dp`
  deletes the second `s`.

> These only run as **single-rule** `-j`/`-k` (applied to the left/right of a combinator
> attack, or once to the wordlist). Putting a reject rule in a `-r` file does **nothing**.

### v7+ character-class and hex forms

- Classes `?l ?u ?d ?h ?H ?s`: `~s?dY` replace all digits with Y, `~@?s` strip all symbols,
  `~!?C` reject if any char in class C (CPU only), etc.
- Hex bytes: `$\x64` appends `d` (useful for non-printable / multibyte).

### Random rules (cheap coverage when you're out of ideas)

```bash
hashcat -m 22000 hash.hc22000 wordlist.txt --generate-rules=10000 \
        --generate-rules-func-min=1 --generate-rules-func-max=4 \
        --generate-rules-func-sel=ioTlcsp
```

### Always test a rule before you trust it

```bash
# See what a rule PRODUCES without cracking (no hash needed):
echo 'summer' | hashcat -r rules/best64.rule --stdout
# Debug WHICH rule cracked WHICH hash during a real run:
hashcat -m 22000 hash.hc22000 wl.txt -r r.rule --debug-mode=1 --debug-file=hits.rule
```

---

## 5. The named rulesets — what they are and what they cost

Ship with hashcat (`/usr/share/hashcat/rules/` on Kali): `best64.rule`,
`best66.rule` (the 7.1 successor to best64 — check which your build ships),
`d3ad0ne.rule`, `dive.rule`, `rockyou-30000.rule`, `toggles[1-5].rule`,
`leetspeak.rule`, `T0XlC*.rule`, `generated2.rule`, `Incisive-leetspeak.rule`, etc.

| Ruleset | ~Rule count | Character | Where it sits in the tradeoff |
|---|---|---|---|
| `best64` | 64 (≈77 unique) | tiny, fastest, hand-picked | **Run first, always.** The quick-win against weak keys. |
| `best66` | ~66 | best64's modern replacement | drop-in for best64 on hashcat 7.1+ |
| `toggles1–5` | small→large | case-toggle only | underrated; stack on top of a base set or big wordlist |
| `leetspeak` | small | char substitution | **only** useful stacked with another set (lowercase-only) |
| `rockyou-30000` | 30,000 | mid, breach-derived | solid general mid-tier |
| `InsidePro` (PasswordsPro / HashManager) | mid | good yield, combinable | strong second pass per TrustedSec |
| `d3ad0ne` | 34,156 | 2013-era, PACK-built | big, still respectable, now mid-pack |
| `dive` | ~99k–120k | huge | high coverage, slow — fast hashes / short lists |
| `generated2` | large | machine-generated | strong but heavy |
| `OneRuleToRuleThemAll` | **51,998** | best-of-many, de-duped | the community default "big single pass" |
| `OneRuleToRuleThemStill` | ~49k | refreshed ORTTA | leaner successor |
| `pantagrule` | up to millions | statistically generated | last-resort mega-coverage, GPU-heavy |

> **OneRuleToRuleThemAll** (stealthsploit) was built by taking the **top 25% of rules
> from many sets, de-duping and concatenating** → 51,998 rules, keyspace **745,808,362,112**
> per wordlist pass. It is **not** a hashcat built-in; download the `.rule` and point `-r` at it.

### Published effectiveness figures (treat as directional, not gospel)

From NotSoSecure's own test (rockyou wordlist vs. unsalted MD5 "Lifeboat" breach):

| Rule | Candidates / word-pass | % cracked |
|---|---|---|
| `best64` | 1,104,433,792 | 32.43% |
| `rockyou-30000` | 430,298,880,000 | 59.05% |
| `d3ad0ne` | 489,063,363,712 | 59.58% |
| `dive` | 1,421,219,827,456 | 65.64% |
| **`OneRuleToRuleThemAll`** | 745,808,362,112 | **68.36%** |

Cyclone's separate set: `d3ad0ne` 41.1% vs `OneRuleToRuleThemAll` 50.8% on one corpus;
75.8% vs 79.6% on another. **Caveats that matter:** these are blog/GitHub benchmarks on
**fast MD5/SHA1 breach corpora**, not WPA. They used different wordlists and loopback
settings, so percentages are **not** directly comparable and **will not transfer 1:1 to
mode 22000**, where the slow hash caps how much of that keyspace you can actually reach.

---

## 6. The keyspace ↔ time math (do this before every big run)

**Total candidates ≈ (wordlist size) × (rule count).** Runtime ≈ total candidates ÷
your mode-22000 hashrate.

```bash
# Ask hashcat the real keyspace for THIS version/wordlist/rule combo:
hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/OneRuleToRuleThemAll.rule --keyspace
```

> Use `--keyspace` — **never** hand-estimate. The hashcat forum documents that reported
> keyspace **changes between hashcat versions**, so your own multiplication can be wrong.

**Mode-22000 hashrates are brutally low** (PBKDF2, 4096 iters). Representative
community benchmarks (vary wildly with driver / `-O` / `-w` / tuning):

| GPU | ~kH/s (mode 22000) |
|---|---|
| RTX 3060 | ~384 kH/s |
| RTX 4090 | ~2,656 kH/s |
| RTX 5090 | ~3,474 kH/s |
| RX 7900 XTX | ~1,466 kH/s |
| Apple-class / laptop iGPU | tens of kH/s (far lower) |

**Worked example — why rules, not brute force.** Take rockyou (14.3 M words):

- `rockyou` alone: 14.3 M candidates. On a 400 kH/s card ≈ **~36 s**. Trivial — run it bare first.
- `rockyou + best64`: ~916 M candidates ≈ **~38 min** @ 400 kH/s.
- `rockyou + OneRuleToRuleThemAll`: ~745 B candidates. @ 400 kH/s ≈ **~21 days**;
  @ 2,656 kH/s (4090) ≈ **~3.2 days**. (A fast-hash blog quotes ~76 min for this same
  combo — that is an **MD5** figure and **does not** apply to WPA. Expect days, not minutes.)
- Pure 8-digit brute (`-a 3 ?d?d?d?d?d?d?d?d`): 10^8 = 100 M candidates ≈ **~4 min** @ 400 kH/s —
  cheap and worth running because of default-router numeric keys. But 8× lowercase
  (`?l^8` = 26^8 ≈ 2.1×10^11) ≈ **~6 days** @ 400 kH/s, and full 8× mixed is infeasible.

**Takeaway:** on mode 22000 you can afford a good wordlist with a **small-to-mid** rule
set, or a mid wordlist with best64, or targeted masks. A 52 k-rule file over a big
wordlist is a **multi-day** commitment — budget it deliberately, use `--keyspace` and
`--runtime`/checkpointing, and prefer a 4090-class card.

---

## 7. Decision order — the order pros actually try things

Spend the cheap, high-yield guesses first; escalate only on failure.

1. **Bare high-quality wordlist, no rules.** Start with a WPA-specific list — the
   wpa-sec cracked corpus (`cracked.txt.gz`; hashcat reads gzip directly) — which is
   *already* real Wi-Fi keys. Seconds to minutes.
   ```bash
   hashcat -m 22000 hash.hc22000 cracked.txt.gz
   ```
2. **ESSID-targeted wordlist** derived from the network name (see §9). Cheap, very high
   hit rate on vanity/SSID-based keys.
3. **Digit masks** (default-router style): 8–10 digit, phone-number, date patterns.
   ```bash
   hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d          # 8-digit, ~minutes
   hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d       # 10-digit (phones)
   hashcat -m 22000 hash.hc22000 -a 3 -1 '19 2' '?1?d?d?d?d?d?d?d'  # years/dates
   ```
4. **Wordlist + `best64`.** The universal quick mangling pass.
5. **Wordlist + mid ruleset** (`rockyou-30000`, InsidePro, `d3ad0ne`).
6. **Wordlist + `OneRuleToRuleThemAll`** (or ORTTS) — the big single-pass. Budget days.
7. **Combinator** for two-word passphrases (`correct-horse` style):
   ```bash
   hashcat -m 22000 hash.hc22000 -a 1 words.txt words.txt
   hashcat -m 22000 hash.hc22000 -a 1 left.txt right.txt -j '$-' -k '$!'  # with -j/-k single rules
   ```
8. **Hybrid wordlist+mask** (base word + appended digits/symbols):
   ```bash
   hashcat -m 22000 hash.hc22000 -a 6 words.txt '?d?d?d?d'     # word + 4 digits
   hashcat -m 22000 hash.hc22000 -a 7 '?d?d?d?d' words.txt     # 4 digits + word
   ```
9. **Stacked / custom rules** and `pantagrule` mega-sets — last, when you have GPU-days.

---

## 8. Custom rules — build them from what you learn

The highest-value rules are the ones that match *your target population*.

**Mine your own hits.** Every time you crack a key, learn the rule that did it, then
promote the winners into a tight custom file:

```bash
# capture the winning rules during a run
hashcat -m 22000 hash.hc22000 wl.txt -r big.rule --debug-mode=1 --debug-file=hits.rule
sort hits.rule | uniq -c | sort -rn | head        # which mutations actually worked
```

**WPA-specific custom rules worth writing** (remember the ≥8-char floor):

```
# append a 4-digit year — cheap, hugely common on Wi-Fi keys
$2$0$2$4
$2$0$2$5
# capitalize + bang (router/consumer habit)
c$!
# leet a base word (stack on a base set, lowercase-only)
sa@ss$se3so0
# prepend the ISP/area code the target uses
^0^2^0
```

**Trim big lists to a high-yield head.** Most public rulesets are sorted by popularity,
so you can keep the best slice cheaply:

```bash
head -n 2000 rules/OneRuleToRuleThemAll.rule > rules/ortta-top2k.rule
```

---

## 9. Turning the ESSID into a wordlist (the WPA edge)

Because the SSID ships inside the hash, build a candidate list around it and run it at
step 2 above.

```bash
# pull the network name(s) you captured
hcxpcapngtool -o hash.hc22000 -E essids.txt dump.pcapng

# generate mutations around the name with a maskprocessor / hcxpsktool
hcxpsktool -i hash.hc22000 --country > essid-candidates.txt   # name/number heuristics
# or classic cupp/CeWL-style personal lists when you have OSINT on the owner (authorized)
```

Combine with digit masks via hybrid attack (`-a 6/7`) so `NETGEAR` becomes
`NETGEAR2024`, `NETGEAR!23`, etc.

---

## 10. Stacking rules (multiply with care)

Multiple `-r` files are **combined as a product**, not run in sequence: every rule in
file A is paired with every rule in file B.

```bash
# best64 (quick mangling) × toggles2 (case variants)  -> 64 × ~small
hashcat -m 22000 hash.hc22000 wl.txt -r rules/best64.rule -r rules/toggles2.rule
# base set × leetspeak (leet only helps when stacked)
hashcat -m 22000 hash.hc22000 wl.txt -r rules/best64.rule -r rules/leetspeak.rule
```

Good stacking pairs (TrustedSec): best64 + toggles2; best64 + a leetspeak set; best64 +
a small `insert_00-99` list. **Danger:** two big files multiply into a keyspace you
cannot finish and can **exhaust host memory** while loading rules. Keep at least one
side small.

---

## 11. Gotchas & pitfalls

- **Sub-8-char candidates are dead on arrival.** Mode 22000 rejects anything <8 or >63
  chars. Truncation/delete-heavy rules on short base words waste your guess budget.
- **Rules are byte-wise, single-char.** No multi-char find/replace in one function
  (John the Ripper's engine is stronger for string-level work). Chain `sXY` calls.
- **Reject/memory rules do nothing in a `-r` file** — they're `-j`/`-k` only.
- **`--keyspace` varies by hashcat version.** Always query it; don't trust old blog numbers.
- **Fast-hash benchmark %s don't transfer to WPA.** A 68% MD5 result ≠ 68% on your
  handshake in the same wall-clock time — PBKDF2 is ~orders slower.
- **`-O` (optimized kernels) caps password length** (often 31). Fine for WPA (max 63 but
  real keys are short) and much faster — but know it silently skips longer candidates.
- **Version-mismatched hcx tools corrupt conversions.** Pin `hcxdumptool`/`hcxpcapngtool`.
- **Potfile skips already-cracked hashes.** Disable (`--potfile-disable`) when
  benchmarking rule effectiveness so prior hits don't skew counts.
- **Don't run hcxdumptool on a virtual interface** (hashcat wiki).
- **31-function cap** per combined rule line — big stacks can silently overflow.

---

## 12. Pro tips for speed

```bash
# optimized kernels + max workload (watch thermals; -w 4 steals the desktop)
hashcat -m 22000 hash.hc22000 wl.txt -r rules/best64.rule -O -w 3

# know the cost before you commit, and bound the run
hashcat ... --keyspace            # true candidate count for this build
hashcat ... --runtime=86400       # stop after 24h
hashcat ... --restore             # resume a checkpointed session

# benchmark YOUR card for mode 22000 so your time math is real
hashcat -b -m 22000
```

- **Right-size the rule set to the hash speed.** Slow hash ⇒ favor best64 / mid sets /
  targeted masks over 52 k-rule monsters unless you have 4090-class GPU-days.
- **Order matters: cheap+likely first** (wpa-sec list, ESSID list, digit masks) before
  any heavy rule pass. Most authorized recoveries fall here.
- **Promote winners** from `--debug-file` into a small custom rule — a 200-line tuned
  file often beats a 50 k generic one on your population, for a fraction of the time.
- **Use `--slow-candidates` (`-S`)** when running huge rule files on slow hashes; it can
  improve candidate generation efficiency for `-m 22000`.
- **Split work across machines/GPUs** with `-s`/`-l` (skip/limit) on the keyspace.

---

## 13. Defense (pair every attack with this)

The entire rule-based attack collapses against two defender choices:

1. **Passphrase strength is the whole game.** Rules only beat *human-predictable* keys.
   A **long, random** passphrase (≥ ~15 chars, or a 5–6 word diceware phrase) pushes the
   keyspace past any wordlist+rule or mask you can finish on PBKDF2. Research on real
   networks found many fall in minutes precisely because of weak, guessable passphrases;
   an 8-digit numeric key can fall in **~minutes**. **Mitigation: generate the PSK
   randomly; never base it on the SSID, address, phone, or a dictionary word + year.**
2. **Kill the offline-capturable material.**
   - **PMKID exposure** is a WPA2-Personal + 802.11r/PMKID-caching condition (Fortinet
     FG-IR-18-199; Cisco). **Mitigation: disable 802.11r / PMKID roaming where it isn't
     needed**, which removes or drastically reduces the PMKID attack surface.
   - **Move to WPA3-SAE (Dragonfly).** SAE is a password-authenticated key exchange that
     **removes the offline-dictionary step** handshake/PMKID capture depends on — an
     attacker can't grind candidates offline against a captured exchange.
   - **Avoid WPA3 transition (mixed) mode** once clients support SAE: an attacker can
     **downgrade to WPA2** and dictionary-attack the fallback (arXiv 2501.13363), so a
     weak passphrase stays exposed even on a "WPA3" SSID.
3. **Defender-side detection & hygiene:** monitor for deauth floods and rogue
   association/PMKID-harvesting behavior; segment IoT onto its own SSID; rotate the PSK
   after any suspected capture; prefer 802.1X/enterprise (per-user creds) over PSK where
   feasible. For evil-twin, **detection only**: watch for duplicate SSIDs / unexpected
   BSSIDs and deauth bursts — do **not** stand up a credential-harvesting portal.

---

## Sources

Primary / official docs:
- hashcat wiki — Rule-based Attack: https://hashcat.net/wiki/doku.php?id=rule_based_attack
- hashcat wiki — Cracking WPA/WPA2 (mode 22000): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- Kali Tools — hcxtools: https://www.kali.org/tools/hcxtools/
- hcxpcapngtool man page: https://manpages.debian.org/testing/hcxtools/hcxpcapngtool.1

Ruleset creation / benchmarks:
- NotSoSecure — One Rule to Rule Them All: https://notsosecure.com/one-rule-to-rule-them-all
- stealthsploit — Optimised-hashcat-Rule (ORTTA / OneRuleToRuleThemStill): https://github.com/stealthsploit/Optimised-hashcat-Rule
- TrustedSec — Better Hacking Through Cracking: Know Your Rules: https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules
- rarecoil/pantagrule: https://github.com/rarecoil/pantagrule
- cyclone-github rules comparison: https://awesome.ecosyste.ms/projects/github.com%2Fcyclone-github%2Frules

Performance / keyspace:
- hashcat forum — mode 22000 hashrates: https://hashcat.net/forum/post-50243.html
- Hashcat GPU benchmark table: https://tutorials.technology/blog/08-Hashcat-GPU-benchmarking-table-Nvidia-and-amd.html
- hashcat advanced techniques (keyspace examples): https://tutorials.technology/tutorials/hashcat-advanced-techniques-2026.html

Defense / CVEs:
- Fortinet FG-IR-18-199 (PMKID/802.11r preconditions & mitigation): https://fortiguard.com/psirt/FG-IR-18-199
- Cisco — WPA2 PMKID attack vector & defense: https://news-blogs.cisco.com/security/shining-a-light-on-a-new-way-to-attack-wpa2-weaknesses
- arXiv 2501.13363 — False Sense of Security on Protected Wi-Fi (weak passphrases, WPA3 transition downgrade): https://arxiv.org/html/2501.13363v1
- CWNP — Revisiting WPA2 / move to WPA3: https://www.cwnp.com/uploads/1660_cwnp-wp_revisiting-wpa-2-understanding-its-security-gaps-and-evaluating-the-move-to-wpa3_ver120224.pdf

> **Note on numbers:** rule-count, keyspace, and crack-% figures above come from
> community/vendor tests on **fast-hash breach corpora**; they indicate *relative* rule
> strength, not literal mode-22000 outcomes. Always run `--keyspace` and `hashcat -b -m
> 22000` on your own hardware for real time estimates.
