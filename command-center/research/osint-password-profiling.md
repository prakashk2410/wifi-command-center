# OSINT-Based Password Profiling for Targeted Wordlists

**Module:** Wi-Fi Command Center / Research
**Scope:** WPA/WPA2-PSK (and WPA3-SAE) offline candidate generation from open-source intelligence
**Last reviewed:** 2026-11-14

---

## 0. Authorization gate (read first, every run)

This technique produces a wordlist tailored to a *specific human or organization*. That is exactly what makes it powerful and exactly what makes it sensitive. Use it **only** against:

- your **own** APs / your own home or lab network;
- a network you have **written** authorization to test (signed scope / rules of engagement);
- a **sanctioned CTF / competition range** or OSWP-style lab you are enrolled in.

Operational rules baked into the toolkit:

- **Allowlist enforcement.** The target BSSID/ESSID must be present in the Command Center allowlist before any capture or crack job runs. Profiling a wordlist for an ESSID that is not on the allowlist should be refused by the orchestration layer.
- **OSINT scope = the target you own/are authorized for.** "OSINT" here means public data about *your* org or *your* identity (or the lab's fictional persona), not surveillance of an uninvolved third party. Do not scrape, profile, or build a dictionary for a real person you have no authorization to test. There is no "just profiling, not cracking" exemption — building the list for an unauthorized target is itself out of scope.
- **Data handling.** Profiles contain PII (names, DOBs, kids' names). Keep generated `.txt` lists inside the lab project dir, treat them as sensitive, and delete them with the engagement. Never commit them.
- **Every attack pairs with its defense.** See §12.

If any of the above is not satisfied, stop and surface it to the operator.

---

## 1. Concept (brief)

WPA2-PSK and WPA3-SAE passphrases are chosen by humans, and humans anchor passwords to memorable, personal facts: their name, a partner/child/pet name, a birth year, a phone number, a street, a favorite team, the company name — very often a capitalized word + a number + maybe a symbol (`Summer2023!`, `Rex2011`, `Linksys0788`). WPA's 8–63 character minimum pushes people toward `word + digits` padding to reach length.

**OSINT-based password profiling** gathers those personal/organizational facts from open sources and mechanically expands them into a *small, high-probability* candidate list — then mangles it with case/leet/append rules. Because WPA key derivation (PBKDF2-HMAC-SHA1, 4096 iterations, salted with the ESSID) is **slow**, you cannot brute-force a large keyspace; a few thousand to a few million *well-aimed* guesses that actually match how the owner thinks is the whole game. A 10-line targeted list that contains the real passphrase beats a 14-billion-line generic list that does not.

Two complementary ideas:
- **Profiling** (CUPP, Mentalist) — build candidates from *known facts* about the owner.
- **Scraping / harvesting** (CeWL) — build candidates from the *language of the target's own web presence* (company site, bio, product names).

---

## 2. Where this sits in the pro decision order

For an authorized WPA2-PSK engagement, the order pros actually try things:

1. **Captured hash in hand.** PMKID or EAPOL M1–M4 → `hash.hc22000` (see `handshake-capture.md`, `pmkid.md`). Nothing below matters until you have a valid hash.
2. **Default-key check FIRST.** If the ESSID/vendor matches a known ISP default-password scheme (see §5), a *mask* attack on that fixed keyspace is far more likely and often faster than any wordlist. Pros always rule this in/out before profiling.
3. **`rockyou.txt` + `best64.rule`.** Cheap, fast, catches lazy human passwords. Run it as a baseline (minutes).
4. **OSINT-targeted list (this doc).** Build with CUPP/CeWL/Mentalist, run *before* you spend hours on big generic lists. This is where engagements are won when the owner picked something personal.
5. **Big curated lists + heavy rules** (`OneRuleToRuleThemAll`, `weakpass`, Hashmob) — long tail.
6. **Pure mask / brute** — last resort, only for small/known keyspaces.

OSINT profiling is step 4, but its *results feed back into* step 5 as high-value seed words for rule mangling.

---

## 3. OSINT collection — what to gather and from where

Build a **facts file** before touching any tool. For an authorized target (yourself / your org / the lab persona), collect:

| Category | Specific items | Typical open sources |
|---|---|---|
| **SSID itself** | The ESSID string, any digits/suffixes in it, the vendor prefix | Your own scan (`airodump-ng`, `wash`, `hcxdumptool`) |
| **Identity** | First/last name, nicknames, maiden names, handles | Company "About" page, LinkedIn, domain WHOIS, social bios |
| **Family / pets** | Partner, kids, pet names + their birth years | Social media, public bios |
| **Dates** | Birth years, anniversary, founding year | Public profiles, "since 20xx" on sites |
| **Location** | Street name/number, city, ZIP, area code, country | Business address, maps, listing sites |
| **Phone** | Local number, area code, country code patterns | Public contact pages |
| **Org context** | Company name, brand/product names, slogans, founding year | The target's own website (→ CeWL) |
| **Interests** | Sports team, band, hobby, favorite word | Social media, bios |

Key SSID-derived signals that massively narrow the list:
- **Vendor from ESSID + BSSID OUI** → do the §5 default-key check. The first 3 bytes of the BSSID (OUI) identify the chipset/vendor; `hcxpcapngtool`/`hcxhashtool` and online OUI lookups map it.
- **Numbers inside the ESSID** (e.g. `HOME-A4F2`, `Linksys0788`) — the owner often reuses those exact digits in the key, or they encode the default-key keyspace.
- **A personal/business name in the ESSID** (`SmithFamily`, `JoesCafe5G`) — strong seed words.

Record the facts verbatim; you will paste them straight into CUPP/Mentalist or echo them into a seed file for CeWL merge.

---

## 4. The human-password model you are exploiting

Keep this mental model; it drives every tool setting:

```
[case variant of a base word] + [separator?] + [number/date] + [special char?]
   Summer        ->  summer, Summer, SUMMER, sUMMER
   + year        ->  Summer2023, Summer23
   + special     ->  Summer2023!
   + leet        ->  Summ3r2023!, $ummer2023
```

- **Base words:** names, pet, company, SSID tokens, scraped site words.
- **Appends dominate:** years (birth, current, founding), `123`, `1`, phone fragments, area/ZIP codes.
- **Specials cluster at the end:** `!` first, then `@#$`, and the `word + ! ` pattern is extremely common because it satisfies "needs a symbol" policies.
- **Leet is partial, not full:** real users do `a->@`, `e->3`, `s->$`, `o->0`, `i->1` on *one or two* letters, rarely all. Favor "one at a time" substitution over "all at once".
- **Length floor = 8 (WPA):** drop every candidate < 8 chars before cracking — they cannot be a valid PSK and waste time.

---

## 5. Default-key reality check (do this before profiling)

Many home networks still run the **ISP/vendor default** WPA2 key. These are not random to you — they are drawn from a *fixed, small keyspace* tied to the ESSID/MAC, so a **mask attack** (`-a 3`) beats any wordlist. Always classify the target first:

- **All-digit defaults.** Some routers ship an all-numeric key (8–10 digits). Keyspace `?d?d?d?d?d?d?d?d` is only 10^8 — minutes-to-hours on a modern GPU for WPA2.
  ```bash
  hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d
  ```
- **Uppercase-hex defaults** (common on several ISP routers): 8–10 uppercase-hex chars.
  ```bash
  # 8 uppercase hex, custom charset 1 = ABCDEF0-9
  hashcat -m 22000 hash.hc22000 -a 3 -1 ?u?d ?1?1?1?1?1?1?1?1   # if letters are A-F only, define -1 charset accordingly
  hashcat -m 22000 hash.hc22000 -a 3 ?H?H?H?H?H?H?H?H           # ?H = uppercase hex 0-9A-F
  ```
- **Lowercase-alpha defaults** (e.g. 10 lowercase letters):
  ```bash
  hashcat -m 22000 hash.hc22000 -a 3 ?l?l?l?l?l?l?l?l?l?l
  ```
- **Word-list default schemes** (ISP picks from a small dictionary of words, sometimes `AdjectiveNoun####`). If the vendor is known to use dictionary-word defaults, build a combinator of its word pool instead of brute.

How to decide: identify the vendor from the **BSSID OUI** + ESSID pattern, then look up that model's documented default-key format (vendor manuals, public teardown writeups, community keyspace notes). On a lab/own device, read the sticker. Estimate run time with `--keyspace` before committing:
```bash
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d --keyspace
hashcat -m 22000 hash.hc22000 -a 3 ?d?d?d?d?d?d?d?d --status --status-timer=10
```
If the default keyspace is small and plausible, it almost always wins over profiling. Profiling (§6–8) is for *user-changed* passphrases.

> Historical note: older generators (e.g. for specific legacy ISP router families) derived the default key deterministically from the MAC/ESSID, making recovery instant. Treat these as design-era vulnerabilities and a defensive lesson (§12), not a push-button for arbitrary targets.

---

## 6. Tool 1 — CUPP (Common User Passwords Profiler)

Profiles an individual from facts you supply, then expands with years, specials, random numbers, and leet. Kali: `cupp` / upstream `python3 cupp.py`.

### 6.1 Flags (exact)

| Flag | Meaning |
|---|---|
| `-i` | **Interactive** — ask questions about the target and build the list |
| `-w <file>` | **Improve** an existing dictionary (profile/expand a wordlist or WyD.pl output) |
| `-l` | **Download** prebuilt wordlists from the configured repo (FUNET) |
| `-a` | Parse default usernames/passwords from the **Alecto DB** (purified Phenoelit + CIRT) |
| `-v` | Version |
| `-h` | Help |
| `-q` | (some forks) quiet |

### 6.2 Interactive session — the exact prompts, in order

`python3 cupp.py -i` asks (literal strings from source):

1. `> First Name:`  (empty → `[-] You must enter a name at least!`)
2. `> Surname:`
3. `> Nickname:`
4. `> Birthdate (DDMMYYYY):`  (bad input → `[-] You must enter 8 digits for birthday!`)
5. `> Partners) name:`
6. `> Partners) nickname:`
7. `> Partners) birthdate (DDMMYYYY):`
8. `> Child's name:`
9. `> Child's nickname:`
10. `> Child's birthdate (DDMMYYYY):`
11. `> Pet's name:`
12. `> Company name:`
13. `> Do you want to add some key words about the victim? Y/[N]:`
    - yes → `> Please enter the words, separated by comma. [i.e. hacker,juice,black], spaces will be removed:`
14. `> Do you want to add special chars at the end of words? Y/[N]:`
15. `> Do you want to add some random numbers at the end of words? Y/[N]:`
16. `> Leet mode? (i.e. leet = 1337) Y/[N]:`

**Output:** writes `<firstname>.txt` (lowercased, stripped). Status lines: `[+] Now making a dictionary...`, `[+] Sorting list and removing duplicates...`, `[+] Saving dictionary to <file>, counting <N> words.`, then `> Hyperspeed Print? (Y/n):` and `[+] Now load your pistolero with <file> and shoot! Good luck!`

For WPA, enter **birth years / anniversaries** consistently — CUPP combines name tokens with the date digits and the `[years]` from `cupp.cfg`.

### 6.3 Tuning `cupp.cfg` (this is where pros win)

Literal defaults you will edit:

```ini
[years]
years = 1990,1991,...,2020,2021,2022      # EXTEND to current year (e.g. ...,2026) and add the target's known years

[leet]
a=4
i=1
e=3
t=7
o=0
s=5
g=9
z=2

[specialchars]
chars=!,@,#,$,%,&,*

[nums]
from = 0
to = 100                                   # digits appended when "random numbers" = yes

[nums] / word length
wcfrom = 5                                  # minimum base-word length kept
wcto   = 12                                 # maximum base-word length kept

threshold = 200                            # dedup/validation threshold

[alecto]
alectourl = https://.../alectodb.csv.gz

[downloader]
dicturl = http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/
```

Pro edits for WPA targets:
- **`years`:** add the current year(s) and the target's specific birth/founding years; remove decades that cannot apply to shorten the list.
- **`wcfrom`/`wcto`:** WPA keys are ≥ 8 chars, but CUPP's `wc*` is the *base word* length before appends — leaving `wcfrom=5` is usually fine because appends push totals past 8; still, prune the final list for <8 (see §9).
- **`chars`:** trim to `!,@,#,$` — the realistic set — to cut combinatorial bloat.
- Keep leet **on only when needed**; it multiplies size fast.

### 6.4 Improve an existing list

```bash
python3 cupp.py -w existing.txt        # append CUPP patterns onto each word (years/specials/nums)
```
Use this to mangle a CeWL scrape (§7) with CUPP's year/number/leet logic.

### 6.5 CUPP gotchas
- Interactive output is **unordered-ish and unfiltered for WPA length** — always post-filter (§9).
- Dates are **DDMMYYYY** (8 digits), not slashed — 8 digits or it rejects.
- Leet + specials + numbers together can explode a 10-fact profile into hundreds of thousands of lines; enable selectively.
- The `-l` downloader URL and Alecto URL can rot; don't depend on them for airgapped labs — pre-seed your own wordlists.

---

## 7. Tool 2 — CeWL (Custom Word List generator)

Spiders a target's **own website** and returns the unique words actually used there — company jargon, product names, staff names, slogans — the vocabulary the owner is most likely to draw a passphrase from. Ruby tool by digi.ninja; in Kali as `cewl`.

### 7.1 Flags (exact, from digi.ninja)

| Option | Meaning |
|---|---|
| `-d, --depth x` | Spider depth. **Default 2.** `-d 0` = single page only |
| `-m, --min_word_length` | Drop words shorter than this. **Default 3** (for WPA, think about `-m 8`? no — keep base words short, pad later) |
| `-o, --offsite` | Allow following links to external sites (can wander onto many domains) |
| `-w, --write <file>` | Write wordlist to file instead of stdout |
| `-u, --ua <string>` | Set User-Agent |
| `-n, --no-words` | Do **not** output the wordlist (use with `--meta`/`--email`) |
| `-a, --meta [file]` | Also extract document **metadata** (author/creator names from Office/PDF) |
| `-e, --email [file]` | Also extract **email addresses** (from mailto links) |
| `--meta_file <file>` | Filename for metadata output |
| `--email_file <file>` | Filename for email output |
| `--meta-temp-dir <dir>` | Temp dir exiftool uses (default `/tmp`) |
| `-c, --count` | Show the occurrence count per word (frequency = likelihood signal) |
| `-v, --verbose` | Verbose |
| `--auth_type` | `digest` or `basic` |
| `--auth_user`, `--auth_pass` | HTTP auth creds |
| `--proxy_host`, `--proxy_port` (def 8080), `--proxy_username`, `--proxy_password` | Proxy |
| `URL` | Site to spider |

Notes: CeWL **keeps original case**, pulls words from `alt`/`title` tags, finds words in JavaScript, follows `location.href` redirects, parses links with Nokogiri. No `--offset`, no `--lowercase` flag exist (case is preserved; lowercase downstream).

### 7.2 Recipes

```bash
# Baseline: spider the org site two deep, write a wordlist
cewl -d 2 -m 5 -w site-words.txt https://example-target.tld

# Frequency-ranked (most-used words first = best seeds) + keep counts
cewl -d 2 -m 5 -c -w site-words.txt https://example-target.tld

# Harvest author/creator names from published PDFs/Office docs (great seed names)
cewl -d 2 -n --meta --meta_file meta-names.txt https://example-target.tld

# Harvest emails (handles → username/name tokens)
cewl -d 2 -n --email --email_file emails.txt https://example-target.tld

# Deeper crawl behind a login (authorized), via proxy for logging
cewl -d 3 --auth_type basic --auth_user u --auth_pass p \
     --proxy_host 127.0.0.1 --proxy_port 8080 \
     -w deep-words.txt https://intranet.example-target.tld
```

### 7.3 Feed the scrape into cracking
CeWL output is **raw base words** — it is not a passphrase list yet. Mangle it:
```bash
# with hashcat rules (preferred for WPA — apply on the fly)
hashcat -m 22000 hash.hc22000 site-words.txt -r rules/best64.rule

# or pre-expand with CUPP's year/number/leet logic
python3 cupp.py -w site-words.txt

# or feed Mentalist (§8) as a Base Words custom file
```

### 7.4 CeWLeR (modern Python alternative)
`cewler` (roys/cewler, `pip install cewler`) re-implements CeWL in Python with better JS handling: `-d` counts **link hops** from the start URL (not path depth), `-d 0` = unlimited; `-m` min length; `-l` lowercase; `-js` for JavaScript; `-r` request rate. Use it when CeWL chokes on a JS-heavy SPA.

### 7.5 CeWL gotchas
- `-d 2` on a large site with `-o` can crawl the whole internet — keep offsite off, bound depth.
- `-m 3` default yields noise; `-m 5` or `6` is a better seed quality for WPA.
- CeWL words are **short base tokens** — do **not** `-m 8` thinking "WPA needs 8"; you need short seeds that you then *pad* to length with rules/appends.
- Metadata extraction needs `exiftool` installed.
- Respect robots/scope — you are hitting the target's live site; only do so when in scope.

---

## 8. Tool 3 — Mentalist (graphical chain-based generator)

GUI tool (sc0tfree, MIT, Python 3.11+) that builds wordlists as a **directed chain of nodes**. Best when you want fine, visual control over the case/leet/append matrix and want to **export hashcat/John rules** instead of a giant flat file. Kali/BlackArch packaged; Windows/mac builds on the releases page. No CLI — all GUI.

### 8.1 Chain model
- A **chain** is an ordered list of **nodes**; the first node is **always Base Words**.
- Each base word flows down the chain; each node may pass it through, modify it, or fan it out into variants.
- Each node **de-duplicates per base word**; only unique results pass to the next node.
- Output is either a **full wordlist** or **rules** that regenerate the same list.

### 8.2 The five node types + their attributes (exact)

**Base Words** — the roots (dictionary file, custom file, or manual entry). Seed this with your CUPP output, CeWL scrape, SSID tokens, and the facts file.

**Case**
- No Case Change
- Lowercase All
- Lowercase First, Upper Rest
- Uppercase All
- Uppercase First, Lower Rest  ← the classic `Summer` pattern
- Toggle Nth (e.g. `TeSt` with N=2 → `TESt`)

**Substitution** (leet)
- No Substitution
- Replace All Instances
- Replace First Instance ⚠ *not compatible with hashcat/John rule export*
- Replace Last Instance ⚠ *not compatible with rule export*
- Modes: **One at a Time** (sub a single char per output — realistic) vs **All at Once**
- Example subs shown: `a→@`, `e→3`, `t→+` (define your full map: `a@ e3 i1 o0 s$ t7`)

**Append / Prepend**
- No Append/Prepend
- Numbers: **User Defined** (From/To, 0-padding), **Small 0–100**, **Basic 0–1000**, **Full 0–10000**, **Years 1950–2025**, **Dates** (From Year, To Year, format e.g. `mmddyy`, leading-0 option)
- Special Characters (one at a time)
- Words: Custom File, Custom String, English Dictionary, Men, Women, Pets, Slang & Expletives, Months & Seasons
- **Area Codes (US)** and **Zip Codes (US)** — by state or city ← excellent for location-anchored phone/ZIP passphrases

### 8.3 A realistic WPA chain
```
Base Words: [facts + CeWL scrape + SSID tokens]
   → Case: {Uppercase First-Lower Rest, Lowercase All}
   → Substitution: One-at-a-Time {a@, e3, s$}  (optional)
   → Append: Years 1990–2026  +  Numbers Small 0–100
   → Append: Special Characters {!, @, #}
Output: Hashcat/John Rules   (NOT a flat file — keeps it small)
```
Export **rules**, then apply them to your compact base list at crack time:
```bash
hashcat -m 22000 hash.hc22000 base.txt -r mentalist.rule
```

### 8.4 Mentalist gotchas
- **Combinatorial explosion:** every expanding node multiplies. `Numbers Small` alone adds 101 outputs per word; stack case × leet × years × specials and a 500-word base becomes tens of millions. Prefer **rule export** over full wordlist, and watch the live count in the GUI.
- **Replace First/Last Instance** can't be exported as hashcat/John rules — use Replace All if you need rule output.
- GUI-only: for headless/lab automation, generate the `.rule`/wordlist once on a workstation, then ship it to the Kali box.
- Save chains as `.mentalist` for reuse across engagements.

---

## 9. Supporting tools (fill the gaps the big three leave)

- **crunch** — generate by pattern/charset for known structures (phone numbers, default keyspaces):
  ```bash
  # all 8-digit numbers (local phone w/o area code) -> stdout piped to hashcat
  crunch 8 8 0123456789 | hashcat -m 22000 hash.hc22000
  # area-code-prefixed 10-digit: fixed prefix 415 + 7 digits
  crunch 10 10 -t 415%%%%%%%        # % = numeric placeholder
  # word + 4 digits pattern
  crunch 11 11 -t pass@@@@,  -o out.txt   # see crunch -t placeholders: @ lower, , upper, % num, ^ special
  ```
- **maskprocessor (`mp64`)** — fast mask expansion for date/phone keyspaces:
  ```bash
  mp64 -1 ?d ?1?1?1?1?1?1?1?1 > eight-digit.txt
  mp64 19?d?d > birthyears-1900s.txt ; mp64 20?d?d > birthyears-2000s.txt
  ```
- **hashcat-utils:**
  - `combinator.bin a.txt b.txt` — concatenate every word in A with every word in B (e.g. names × years).
  - `rli` / `rli2` — subtract already-tried words from a list (dedupe across runs).
  - `expander` — build fragment lists.
  ```bash
  combinator.bin names.txt years.txt > names_years.txt
  ```
- **kwprocessor (`kwp`)** — keyboard-walk candidates (`qwerty`, `1qaz2wsx`, `zaq12wsx`) that humans use as "random" WPA keys:
  ```bash
  kwp basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route > walks.txt
  ```
- **psudohash** — profiling mangler similar to CUPP with transformation levels and year/number/symbol padding; good scriptable alternative.
- **username-anarchy** — turn harvested names/emails (from CeWL `--email`/`--meta`) into name-token permutations to seed Base Words.
- **hashcat native `-a 1` combinator** and **`-a 6/-a 7` hybrid** — append/prepend a mask to each dict word *inside* hashcat (no intermediate file):
  ```bash
  hashcat -m 22000 hash.hc22000 -a 6 words.txt ?d?d?d?d          # word + 4 digits
  hashcat -m 22000 hash.hc22000 -a 7 ?d?d?d?d words.txt          # 4 digits + word
  hashcat -m 22000 hash.hc22000 -a 1 left.txt right.txt          # combinator
  ```

---

## 10. From wordlist to crack — the WPA/WPA2 workflow (hashcat `-m 22000`)

1. **Capture → convert** (full detail in `handshake-capture.md` / `pmkid.md`):
   ```bash
   sudo systemctl stop NetworkManager.service wpa_supplicant.service
   hcxdumptool -i INTERFACE -w dump.pcapng --rds=1 -F      # authorized target only
   sudo systemctl start wpa_supplicant.service NetworkManager.service
   hcxpcapngtool -o hash.hc22000 dump.pcapng               # -> hc22000 (PMKID WPA*01 / EAPOL WPA*02)
   ```
   Isolate if needed:
   ```bash
   grep 'WPA\*01' hash.hc22000 > pmkid.hc22000     # PMKID lines
   grep 'WPA\*02' hash.hc22000 > eapol.hc22000     # EAPOL lines
   grep '2$'      hash.hc22000                       # best EAPOL message-pair bitmask
   ```
   Do **not** `wpaclean` the capture and do **not** merge pcapng files (hashcat wiki).

2. **Default-key mask first** (§5) if the vendor keyspace is known/small.

3. **Run the OSINT list — plain, then with rules:**
   ```bash
   hashcat -m 22000 hash.hc22000 osint.txt                            # straight
   hashcat -m 22000 hash.hc22000 osint.txt -r rules/best64.rule       # +mangling
   hashcat -m 22000 hash.hc22000 osint.txt -r rules/best64.rule -r rules/best64.rule   # stacked
   ```

4. **Hybrid append/prepend for date & phone tails** (no pre-generated file):
   ```bash
   hashcat -m 22000 hash.hc22000 -a 6 names.txt ?d?d?d?d       # Name + year
   hashcat -m 22000 hash.hc22000 -a 7 ?d?d       names.txt     # 2-digit + Name
   ```

5. **Combinator** for name×year, word×word (apply at most one rule per side):
   ```bash
   hashcat -m 22000 hash.hc22000 -a 1 first.txt last.txt -j '$2$0$1$9'   # right rule appends 2019, etc.
   ```
   (The combinator kernel allows only one rule per dictionary; for heavy rules, pipe `combinator.bin` output into a straight `-a 0` run.)

6. **Escalate** to big lists + `OneRuleToRuleThemAll` only after the targeted phase.

Always pre-estimate:
```bash
hashcat -m 22000 hash.hc22000 osint.txt -r rules/best64.rule --keyspace
hashcat ... --status --status-timer=5     # watch speed/ETA; WPA2 is PBKDF2-slow
```

---

## 11. Decision order & pro tips for speed

1. **Filter for WPA length before cracking** — strip anything < 8 chars (can't be a PSK):
   ```bash
   awk 'length>=8 && length<=63' osint.txt | sort -u > osint.wpa.txt
   ```
2. **Rank by likelihood, run best-first.** Put bare base words and `Word+Year`/`Word+123`/`Word!` at the top; leet variants last. Use CeWL `-c` counts to order site words.
3. **Rules > giant flat files.** Apply mangling with `-r` at runtime so the wordlist stays small and GPU-fed; Mentalist rule export and `best64.rule` are the workhorses.
4. **Dedupe across runs** with `rli` so you never re-test a candidate (WPA time is precious).
5. **One capture, many attacks.** Convert once to `hc22000`, keep `--potfile` so cracked keys persist; use `--left` to see what's uncracked.
6. **Keep base lists tiny and aimed.** 10–50 strong seeds × good rules out-performs 10⁷ random lines for WPA.
7. **Merge sources:** `cat cupp.txt cewl.txt ssid_tokens.txt | sort -u` → single Base Words file → Mentalist/rules.
8. **Pipe `crunch`/`mp64` into hashcat** rather than writing huge intermediate files to disk when attacking numeric keyspaces.
9. **Benchmark your GPU** (`hashcat -b -m 22000`) so you can compute whether a keyspace is tractable before you start.

---

## 12. DEFENSE — pair every attack with its countermeasure

OSINT profiling only works because people anchor passphrases to guessable facts and ISPs ship weak defaults. Defenses:

- **Use a long random passphrase.** 5+ random words (diceware) or 20+ random chars defeats targeted *and* generic lists — the PBKDF2 slowness that frustrates attackers is *your* ally when the key isn't in any list. This single control neutralizes CUPP/CeWL/Mentalist entirely.
- **Never base the key on personal facts** that appear anywhere public: name, pet, kids, birth year, phone, address, ZIP, company, SSID tokens, favorite team. If it's on your LinkedIn or your front door, it's in the wordlist.
- **Change ISP default keys immediately.** Default-key schemes (§5) turn a MAC/ESSID into a small keyspace. Replace the sticker key with a random one; this is the #1 fix for home networks.
- **Don't encode info in the SSID.** `SmithFamily5G`, `Apt4B`, or leaving the vendor+digits default (`Linksys0788`) hands attackers both seed words and keyspace hints. Use a neutral SSID (but note hiding the SSID is not real security).
- **Move to WPA3-SAE where possible.** SAE (Dragonfly) replaces the offline-crackable 4-way-handshake/PMKID exchange with a PAKE: an eavesdropper cannot run an *offline* dictionary attack against a captured exchange, so OSINT lists lose their offline leverage. Each guess requires a live interaction with the AP, which is rate-limitable and detectable. (Deploy patched implementations — see `wpa3-sae-dragonblood.md` for the downgrade/side-channel caveats.) Enterprise/802.1X (EAP) removes the shared PSK entirely.
- **Reduce your OSINT surface.** Strip author/creator metadata from published PDFs/Office docs (defeats CeWL `--meta`); minimize personal detail in public bios; use role-based rather than name-based emails where feasible (defeats CeWL `--email` → username seeding).
- **Monitor.** Deauth floods and PMKID/handshake harvesting precede offline cracking — WIDS/alerting on mass deauth and on association scans gives early warning (see `deauth-dos.md`, `evil-twin-detection.md`).
- **Audit yourself the same way.** The honest test of a passphrase is: build the profile with these exact tools against your *own* data and confirm your key is *not* produced. If CUPP/CeWL/Mentalist can generate it, change it.

> Evil-twin / captive-portal note: credential-capture ("phishing") rogue-AP builds are **out of scope** for this toolkit. The relevant coverage is **detection and concept only** — see `evil-twin-detection.md` and `karma-mana.md` for recognizing and defending against rogue APs, not for harvesting credentials.

---

## 13. Sources

Primary tool docs / source (read directly):
- CUPP — upstream repo & README: https://github.com/Mebus/cupp
- CUPP — `cupp.cfg` (literal years/leet/specialchars/nums/wc/threshold values): https://github.com/Mebus/cupp/blob/master/cupp.cfg
- CUPP — `cupp.py` source (exact interactive prompts & output behavior): https://raw.githubusercontent.com/Mebus/cupp/master/cupp.py
- CeWL — author's project page (digi.ninja), full option reference: https://digi.ninja/projects/cewl.php
- CeWL — Debian/Ubuntu man pages: https://dyn.manpages.debian.org/testing/cewl/cewl.1.en.html , https://manpages.ubuntu.com/manpages/jammy/man1/cewl.1.html
- CeWLeR (Python alternative) — repo & PyPI: https://github.com/roys/cewler , https://pypi.org/project/cewler/
- Mentalist — How It Works (chain/node model): https://github.com/sc0tfree/mentalist/wiki/How-It-Works
- Mentalist — Node Attributes (exact Case/Substitution/Append attributes): https://github.com/sc0tfree/mentalist/wiki/Node-Attributes
- Mentalist — repo: https://github.com/sc0tfree/mentalist
- hashcat — WPA/WPA2 cracking wiki (mode 22000 workflow, hcxpcapngtool, rule/mask examples, PMKID/EAPOL filtering): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

Rules / methodology (secondary, cross-checked):
- hashcat combinator-attack forum thread (one-rule-per-dict limit): https://hashcat.net/forum/
- pantagrule rulesets & coverage comparison: https://github.com/rarecoil/pantagrule
- TrustedSec — "Better Hacking Through Cracking: Know Your Rules": https://trustedsec.com/blog/better-hacking-through-cracking-know-your-rules
- Kali tools (mentalist, hashcat-utils entries): https://en.kali.tools/?p=1310 , https://en.kali.tools/?p=1296

Supporting tools referenced: crunch, maskprocessor (`mp64`), hashcat-utils (`combinator`, `rli`, `expander`), kwprocessor (`kwp`), psudohash, username-anarchy — all standard Kali/hashcat ecosystem utilities.

*Note: HackTricks "Pentesting Wifi" was attempted but returned HTTP 402 (paywalled) and could not be read for this pass.*
