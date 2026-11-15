# GPU Cracking Optimization on Apple Silicon (hashcat, mode 22000)

> **Scope & authorization.** This reference is for cracking WPA/WPA2 handshakes/PMKIDs
> **you are authorized to test** — your own APs, sanctioned engagements, CTF/OSWP lab
> targets, or `wpa-sec`-style public research corpora. Offline cracking is passive; the
> legal line was already crossed (or not) at capture time. Every section pairs the attack
> workflow with the **defense** that neutralizes it. Nothing here builds a credential
> harvester or targets third-party networks.

Platform assumed: **macOS on Apple Silicon (M1–M4 family)** + **hashcat 6.2.6 / 7.x**
with the **Metal** backend, cracking **`-m 22000` (WPA-PBKDF2-PMKID+EAPOL)**. Every
number in this document is an *anchor to measure against*, not a promise — on this
workload the only authoritative figure is `hashcat -b -m 22000` on your own chip, OS, and
cooling.

---

## 0. The one-paragraph concept

WPA2-PSK security rests on **PBKDF2-HMAC-SHA1 with 4096 iterations** (hashcat reports
`4095` because it counts from zero), keyed by the passphrase and salted by the ESSID. To
test a candidate passphrase you compute the PMK (`PBKDF2(passphrase, ESSID, 4096)`),
derive the PTK, and check the MIC (EAPOL) or the PMKID (HMAC-SHA1 over PMK + "PMK Name" +
AP MAC + client MAC). That PBKDF2 is **deliberately slow** — ~8192 SHA1 compressions *per
guess* — so WPA cracking is **throughput-bound** on the GPU's compute units, not memory-
or I/O-bound. "Optimization" therefore means two things: (1) make the GPU compute as many
PBKDF2/s as the silicon allows, and (2) **spend those scarce guesses in the smartest
order** so you crack early or not at all. On Apple Silicon both levers matter more than on
a discrete NVIDIA card, because the M-series GPU is modest for this specific hash (an M1
Max benchmarks around a quarter of a million H/s; an RTX 4090 is in the ~2.3 MH/s range —
roughly 10x). You cannot out-hardware the problem on a Mac, so **ordering is where you
win**.

---

## 1. Pipeline recap: capture → hc22000 → crack

```bash
# Capture (authorized AP) — hcxdumptool writes native pcapng
sudo hcxdumptool -i INTERFACE -w dump.pcapng --rds=1 -F

# Convert to the hashcat 22000 line format (also emit an ESSID wordlist with -E)
hcxpcapngtool -o target.hc22000 -E essid-wordlist.txt dump.pcapng

# Inspect what you actually got
hcxhashtool -i target.hc22000 --info=stdout
```

**hc22000 line anatomy** (critical for candidate strategy later):

```
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR            # 01 = PMKID
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL*MESSAGEPAIR # 02 = EAPOL/handshake
```

The **MESSAGEPAIR** nibble encodes which EAPOL messages were paired and whether the AP/
client nonces are trustworthy; `hcxhashtool` can filter on it. Prefer pairs built from
M1+M2 or M2+M3 where the nonce is authentic over "replaycount-guessed" pairs.

Split / filter when you want to work one hash cleanly:

```bash
hcxhashtool -i target.hc22000 --type=1 -o pmkid.hc22000      # PMKID only
hcxhashtool -i target.hc22000 --type=2 -o eapol.hc22000      # EAPOL only
hcxhashtool -i target.hc22000 --essid-list=targets.txt -o scoped.hc22000  # only authorized ESSIDs
hcxhashtool -i target.hc22000 --mac-ap=AABBCCDDEEFF -o one-ap.hc22000      # one AP you own
```

**Gotchas (from hcxtools / hashcat docs):**
- **Do NOT** run `wpaclean`, do NOT merge pcapng files, do NOT set monitor mode with
  third-party tools before capture — all of these corrupt the nonce/replay bookkeeping and
  `hcxpcapngtool` silently drops the pair. Capture clean, convert once.
- **WPA3/SAE is not convertible** — there is no hashcat mode to recover a WPA3-SAE PSK
  offline, so `hcxpcapngtool` produces no 22000 line for it. "No output" on a modern AP
  usually means WPA3-SAE or "FT using PSK" (802.11r fast-transition, also skipped).
- `.hccapx` (old mode 2500) and the PMKID-only mode 16800 are **deprecated → use 22000**,
  which carries both PMKID and EAPOL in one format.
- Put PMKID (`*01*`) and EAPOL (`*02*`) for the **same ESSID in one file**: hashcat reuses
  the PBKDF2(PMK) result across both, saving GPU cycles instead of recomputing the
  expensive part twice.
- Scope hard with `hcxhashtool --essid-list` / `--mac-ap` **before** cracking so a messy
  capture never puts a neighbor's network in front of the GPU. This is an authorization
  control, not just hygiene.

---

## 2. Apple Silicon backend reality: Metal, not OpenCL

Apple froze OpenCL at **1.2** and no longer maintains it; hashcat prints a literal warning
that *"Apple's OpenCL drivers (GPU) are known to be unreliable."* hashcat added a **Metal**
backend in **6.2.5** (labeled experimental but stable in practice), and on 6.2.6 / 7.x
Metal is the supported path on macOS.

The trap: on Apple Silicon hashcat enumerates the **same physical GPU twice** — once under
Metal, once under OpenCL. If you let both run they fight over the one GPU and your *net*
H/s drops. Pick Metal and silence OpenCL.

```bash
# See exactly what backends/devices hashcat detected
hashcat -I                      # --backend-info: lists Metal + OpenCL devices, cores, mem

# Clean way: disable the OpenCL backend entirely so only Metal runs
hashcat -m 22000 target.hc22000 wordlist.txt --backend-ignore-opencl -w 3

# Or pin the device number of the Metal GPU (confirm the number from `hashcat -I` first)
hashcat -m 22000 target.hc22000 wordlist.txt -d 1 -w 3
```

> **Device-number caveat:** Metal-vs-OpenCL numbering is **not stable across machines or
> versions**. On an M1 Max the Metal GPU enumerates as device **#1** and the OpenCL
> duplicate as **#2**; other builds/chips report the reverse, and a Nov-2025 M4 thread
> describes hashcat *skipping device 1 (Metal) and reverting to device 2 (OpenCL)*. Always
> read `hashcat -I` and match the device by its **backend name**, not a hard-coded number.
> Preferring `--backend-ignore-opencl` sidesteps the ambiguity entirely.

**CPU is not worth adding.** On Apple Silicon the GPU is fed *by* the CPU; dedicating cores
to a second compute device usually lowers total throughput and steals the host-side
candidate generator's headroom. Run the **GPU alone**; leave the P/E cores for rule/mask
generation (and for `-S`, §8).

**Metal runtime mismatch.** `Unsupported Apple Metal runtime version 'XYZ' detected!
Falling back to OpenCL...` means your hashcat build predates your macOS Metal version. Fix
by **updating hashcat** (`brew upgrade hashcat`, a beta build, or compile from source)
rather than letting it fall onto the unreliable OpenCL path. On a stubborn M4 where Metal
is skipped, grabbing the latest beta from hashcat.net is the usual fix; `--force` only
masks the problem.

**Not enough allocatable device memory.** Unified memory is shared with the OS and every
other app. If hashcat reports it can't allocate, close GPU/VRAM-hungry apps (browsers with
many tabs, Final Cut, Docker VMs) and retry — you are competing for the *same* RAM the
system is using.

```bash
# One-time environment sanity before a long run
hashcat -V                      # build version — pin your flags/speeds to this
hashcat -I                      # backends + device numbers + memory
sudo powermetrics --samplers smc -i 1000 -n 5   # watch GPU/package temp during a run
```

---

## 3. The `-O` optimized-kernel question for mode 22000

This is the single most common wasted/cargo-culted flag. `-O`
(`--optimized-kernel-enable`) swaps in a length-limited kernel that is genuinely faster
**for fast hashes** (MD5/NTLM, capping candidates at ~31 bytes). **For `-m 22000` there is
no separate optimized kernel.** hashcat uses a **"pure kernel" covering the full legal PSK
range of 8–63 bytes**. Pass `-O` and you get:

```
Optimized kernel requested but not available or not required.
Falling back to pure kernel.
```

A hashcat moderator's explanation: *WPA2 mode 22000 "does not have or need an optimized
kernel as the attack cannot be optimized any differently than the pure kernel."* You will
find one or two blog tutorials claiming `-O` buys ~15% on 22000 — the **forum evidence is
more specific and contradicts them**; treat the 15% claim as unverified and test it
yourself with a `--speed-only` run if you care.

```bash
# A/B the claim on YOUR build in seconds (don't trust a blog number):
hashcat -m 22000 target.hc22000 rockyou.wpa.txt --speed-only -w 3
hashcat -m 22000 target.hc22000 rockyou.wpa.txt --speed-only -w 3 -O
# Watch startup for "Falling back to pure kernel." If you see it, -O did nothing.
```

**Takeaways:**
- `-O` is a **no-op (or no-op-with-noise) for WPA 22000** on current builds. Don't copy it
  from MD5 tutorials; it neither speeds 22000 up nor truncates your candidates there.
- The **8–63 byte range is the kernel's own hard bound**. Any candidate shorter than 8 or
  longer than 63 is *impossible* as a WPA PSK — prune those from wordlists/masks (§5),
  because feeding them only wastes dispatch slots and host I/O.

```bash
# Prune a wordlist to valid PSK length BEFORE cracking (big efficiency win on huge lists)
awk 'length($0) >= 8 && length($0) <= 63' rockyou.txt > rockyou.wpa.txt
wc -l rockyou.txt rockyou.wpa.txt       # see how much dead weight you dropped
```

---

## 4. Workload profile `-w`, autotune, and manual tuning on a laptop

`-w` sets how aggressively hashcat drives the GPU. It seeds the **Accel / Loops / Thr**
values in the status line; the **autotune** engine then fine-tunes within that envelope at
launch (you can watch it in `--status`).

| `-w` | Name | Use on Apple Silicon |
|------|------|----------------------|
| 1 | Low | interactive; you're actively using the Mac for other work |
| 2 | Default | conservative baseline; keeps the UI responsive |
| **3** | **High** | **the sweet spot for a dedicated/headless crack run** |
| 4 | Nightmare | headless only; makes the UI stutter, invites thermal throttling |

```bash
# Dedicated run, Metal only, high workload:
hashcat -m 22000 target.hc22000 wl.txt -r rules/best64.rule --backend-ignore-opencl -w 3

# Benchmark YOUR chip for 22000 — the number that actually matters:
hashcat -b -m 22000 --backend-ignore-opencl
```

**Why not always `-w 4` on a Mac?**
- MacBooks are thermally constrained. `-w 4` raises die temp fast; once you hit the
  thermal ceiling the GPU clocks **down** and sustained H/s can end up *below* `-w 3`.
  Watch the `Temp` field; hashcat aborts at ~90 °C by default
  (`--hwmon-temp-abort=90`). Correlate with `powermetrics` (§2).
- On WPA the per-step kernel is already long (PBKDF2 loops), so `-w 3` usually saturates
  the GPU; `-w 4` mostly costs responsiveness and heat for little gain. **Measure both**
  with `--speed-only` on your exact chip before committing a long run.

**Benchmark vs. real-run mismatch (important nuance).** `hashcat -b` runs with *optimized
kernels enabled by default*, so a mode's benchmark line can read higher than what you see
cracking with the pure kernel. For 22000 there's no optimized kernel so the gap is small,
but don't be surprised if a mixed benchmark sheet looks rosier than your live run. The
honest speed is a `--speed-only` run of your *actual* attack.

**Manual Accel/Loops tuning (`-n` / `-u`) — usually leave it to autotune.** You *can*
override the per-device kernel-accel (`-n`) and kernel-loops (`-u`):

```bash
# ONLY if autotune is clearly leaving the GPU idle; otherwise this hurts.
hashcat -m 22000 target.hc22000 wl.txt -w 3 -n 256 -u 512 --force
```
On slow iterated hashes like PBKDF2, **autotune almost always matches or beats hand values**,
and bad `-n/-u` can tank throughput or trip "invalid kernel" errors. Treat `-n/-u` as a
last resort, measured with `--speed-only`, never a default.

**Pro throughput checklist for a long M-series run:**
1. `--backend-ignore-opencl` (Metal only) · `-w 3`.
2. Plug in power, run **lid-open / on a stand with active cooling** — thermals are your
   real clock governor on a laptop, not the `-w` number.
3. Close GPU/unified-memory-hungry apps (WebGL browser tabs, Final Cut, Docker).
4. `--status --status-timer=60` to log progress without spamming the terminal.
5. If a fast dictionary+rules combo leaves the GPU starved, test `-S` (§8) — sometimes a
   win on slow hashes, sometimes not. Prove it with `--speed-only`.

---

## 5. Candidate ordering — where WPA cracks are actually won

Because every guess is expensive, **order by (hit probability ÷ cost)**: cheap,
high-likelihood keyspaces first; sprawling brute force last (usually never). The pro
sequence:

**Stage 0 — free/near-free structural guesses (minutes).** Many consumer APs ship default
PSKs that are pure patterns, and a huge fraction of home PSKs are phone numbers or dates.

```bash
# 8-digit all-numeric (extremely common default + user pattern)
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d --backend-ignore-opencl -w 3
# 10-digit phone numbers (prefix with the country/area digits you legitimately know)
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d -w 3
# 11-digit mobile pattern (region-dependent)
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d?d -w 3
```

**Stage 1 — target-derived wordlists (seconds–minutes).** The ESSID itself and words from
the capture are disproportionately likely for an authorized target you know context about.

```bash
# The -E wordlist hcxpcapngtool wrote from the capture:
hashcat -m 22000 target.hc22000 essid-wordlist.txt -r rules/best64.rule -w 3
# Hand-built: ESSID + common suffixes, company/venue name, street, SSID variants.
```

**Stage 2 — rockyou plain, length-pruned (minutes).**

```bash
hashcat -m 22000 target.hc22000 rockyou.wpa.txt -w 3            # pruned in §3
```

**Stage 3 — rockyou + rules (tens of minutes).** The standard escalation is *plain →
best64 → heavier rules*. (hashcat 7 reorganized the bundled rules; check your `rules/` dir
— you may see `best64.rule` or newer names.)

```bash
hashcat -m 22000 target.hc22000 rockyou.wpa.txt -r rules/best64.rule -w 3
# rockyou × best64 ≈ 9.2×10^8 candidates — already hours on M-series; see §6 math.
```

**Stage 4 — bigger curated lists + rules (hours).** `weakpass`, `hashesorg`, and
WPA-specific corpora. A standout for WPA is the **wpa-sec cracked corpus** — real PSKs that
real people chose, so very high ROI per candidate.

```bash
# Real cracked PSKs from the public wpa-sec project (authorized research corpus):
curl -L -o wpa-cracked.txt.gz https://wpa-sec.stanev.org/dict/cracked.txt.gz
hashcat -m 22000 target.hc22000 wpa-cracked.txt.gz -w 3
```

**Stage 5 — hybrid word+mask (`-a 6` / `-a 7`).** Catches `word1234`, `2024word!`.

```bash
hashcat -m 22000 target.hc22000 -a 6 rockyou.wpa.txt ?d?d?d?d -w 3   # word then digits
hashcat -m 22000 target.hc22000 -a 7 ?d?d?d?d rockyou.wpa.txt -w 3   # digits then word
```

**Stage 6 — structured brute force, Markov-ordered (days+).** Only for narrow keyspaces
you have a specific reason to believe in. Mask attacks default to **Markov-ordered**
candidates, which front-loads statistically likely character combos.

```bash
# 8-char lowercase is already ~2×10^11 — days on a Mac; keep masks tight and justified.
hashcat -m 22000 target.hc22000 -a 3 ?l?l?l?l?l?l?l?l -w 3
# Markov controls:
#   --markov-hcstat2 FILE   use a custom statistics file (train on target-like passwords)
#   --markov-classic        classic Markov (no per-position stats)
#   --markov-disable        emulate plain brute force, no ordering
#   -t, --markov-threshold  cap chains per position: HIGHER t = SMALLER keyspace = faster,
#                           but you may skip the real password. t=0 ≈ full space, ordered.
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d -t 50 -w 3
```

**Rule of thumb:** if a stage's keyspace ÷ your benchmark H/s exceeds the time you have,
**skip it** and move the saved time into better wordlists. WPA is won by good lists and
good ordering, almost never by brute force. Use `--keyspace` to get the count *before* you
commit:

```bash
hashcat -m 22000 target.hc22000 -a 3 ?d?d?d?d?d?d?d?d?d?d --keyspace   # prints the count
```

---

## 6. Keyspace math — decide *before* you launch

```
time (s) ≈ keyspace / speed(H/s)
```

Benchmark first: `hashcat -b -m 22000 --backend-ignore-opencl`. Apple Silicon is **modest**
for PBKDF2. **Measured anchors** (your mileage varies with chip/cooling/version — these are
real reports, not guarantees):

| Chip (reported) | mode 22000 speed | Notes |
|---|---|---|
| M2 MacBook Air | ~67 kH/s | hashcat 6.2.5, Metal; thermally limited fanless design |
| M1 Max (32-core GPU) | ~248 kH/s | hashcat 6.2.5 benchmark, Metal |
| M1 Ultra / high-core Max | higher (few hundred kH/s) | scales with GPU core count; **measure** |
| RTX 4090 (reference, not a Mac) | ~2.3 MH/s | ~10× an M1 Max — why ordering matters on Mac |

Using an M1 Max ≈ **250 kH/s** as a working anchor:

| Example keyspace | Size | @ ~67 kH/s (M2 Air) | @ ~250 kH/s (M1 Max) |
|---|---|---|---|
| 8-digit `?d`×8 | 10^8 | ~25 min | ~6.7 min |
| 10-digit phone | 10^10 | ~41 days | ~11 days |
| rockyou × best64 | ~9.2×10^8 | ~3.8 h | ~1 h |
| 8-char lower `?l`×8 | 2.1×10^11 | ~36 years | ~9.6 years |
| 8-char full `?a`×8 | 6.6×10^15 | millennia | centuries |

The table is the whole argument for §5's ordering: the cheap structured/dictionary stages
are minutes-to-hours; a 10-digit phone sweep is already *days* on a MacBook; full brute
force is geologic. Spend guesses where the table is green and refuse the red cells.

---

## 7. Potfile & session hygiene (don't recompute what you cracked)

hashcat records every crack in a **potfile** (default `~/.hashcat/hashcat.potfile`) and
**auto-skips** hashes already present there on the next run ("Removed N hashes found in
potfile").

```bash
# Per-project potfile so runs don't cross-contaminate:
hashcat -m 22000 target.hc22000 wl.txt --potfile-path ./proj.potfile -w 3

# Show cracked PSKs for this file (reads from the potfile, no GPU work):
hashcat -m 22000 target.hc22000 --show

# List what's still UNcracked — great for planning the next stage:
hashcat -m 22000 target.hc22000 --left

# Force a re-crack (e.g. to re-verify) WITHOUT reading/writing your main potfile:
hashcat -m 22000 target.hc22000 wl.txt --potfile-disable

# Trim the input file to only-uncracked as you go (long/distributed runs):
hashcat -m 22000 target.hc22000 wl.txt --remove --remove-timer=60
```

**Potfile gotchas:**
- `--potfile-disable` turns off **both** reading and writing — previously cracked hashes
  will be re-cracked. Use it only to re-verify; in normal work you *want* the potfile.
- `--remove` edits your input file in place; users report it can leave **duplicate lines**
  for a cracked entry in some cases, so keep an untouched copy of the original hc22000.
- If your hashes are in `hash:username` form you must pass `--username` to **all** of
  `--show` / `--left` / the crack run, or hashcat won't line them up.

**Session restore** (laptops sleep, runs get interrupted):

```bash
hashcat -m 22000 target.hc22000 big.txt -r rules/best64.rule \
        --session=proj1 --status --status-timer=60 --backend-ignore-opencl -w 3
# Resume exactly where it stopped:
hashcat --session=proj1 --restore
```

**Brain — skip candidate/hash pairs you've already tried, network-wide.** For multi-ESSID
campaigns or repeated iterations against the same handful of hashes, hashcat's **brain**
remembers tried (candidate, hash) pairs so later runs don't repeat work:

```bash
# Terminal 1 — brain server:
hashcat --brain-server --brain-password mypass

# Terminal 2 — client attaches with -z (short for the brain-client set):
hashcat -m 22000 target.hc22000 wl.txt -z --brain-host 127.0.0.1 --brain-password mypass -w 3
```
Note: `-z` (brain client) **auto-enables `-S` slow-candidates mode** (§8), which can lower
raw H/s — brain is a win when *dedup* saves more than slow-candidates costs, i.e. when you
re-run overlapping attacks against the same slow hashes many times. For a single pass it's
usually not worth it.

---

## 8. `-S` / `--slow-candidates` — host-side generation for slow hashes

`-S` moves **password-candidate generation onto the host CPU**: hashcat applies rules
on-host and builds a "virtual wordlist" in memory, then streams finished candidates to the
GPU. The hashcat docs are explicit that candidates still cross the PCIe/host boundary, "this
slows down cracking performance" in the general case — so **`-S` is not a universal
speedup**. It helps specifically when:
- the hash is **very slow** (PBKDF2, bcrypt, WPA) so the GPU spends most of its time
  computing, not waiting for candidates, *and*
- a heavy **rule set** makes on-GPU rule processing the bottleneck.

```bash
# Prove it per-attack rather than assuming — compare the two speed-only numbers:
hashcat -m 22000 target.hc22000 rockyou.wpa.txt -r rules/dive.rule --speed-only -w 3
hashcat -m 22000 target.hc22000 rockyou.wpa.txt -r rules/dive.rule --speed-only -w 3 -S
```
If the `-S` number is higher for *your* list+rules+chip, keep it; otherwise drop it. `-z`
(brain) enables `-S` for you automatically.

---

## 9. Quick-reference: the pro "first 30 minutes" runbook

```bash
# 1. Confirm build, backend & benchmark the chip
hashcat -V
hashcat -I
hashcat -b -m 22000 --backend-ignore-opencl

# 2. Convert + inspect + scope + prune
hcxpcapngtool -o t.hc22000 -E essid.txt dump.pcapng
hcxhashtool -i t.hc22000 --info=stdout
hcxhashtool -i t.hc22000 --essid-list=authorized.txt -o t.hc22000   # stay in scope
awk 'length>=8 && length<=63' rockyou.txt > rockyou.wpa.txt

# 3. Fast structural + target lists first
hashcat -m 22000 t.hc22000 -a 3 ?d?d?d?d?d?d?d?d --backend-ignore-opencl -w 3
hashcat -m 22000 t.hc22000 essid.txt -r rules/best64.rule --backend-ignore-opencl -w 3

# 4. rockyou plain → best64 → big curated list (with a session for restart safety)
hashcat -m 22000 t.hc22000 rockyou.wpa.txt --backend-ignore-opencl -w 3
hashcat -m 22000 t.hc22000 rockyou.wpa.txt -r rules/best64.rule --backend-ignore-opencl -w 3
hashcat -m 22000 t.hc22000 wpa-cracked.txt.gz --backend-ignore-opencl -w 3 --session=proj1

# 5. Harvest results
hashcat -m 22000 t.hc22000 --show
hashcat -m 22000 t.hc22000 --left     # what to attack next
```

**Common failure modes → fix:**
- Empty hc22000 → WPA3-SAE / 802.11r-FT (unsupported offline); re-check the target's mode.
- OpenCL "unreliable" warning / instability → add `--backend-ignore-opencl`.
- "Falling back to pure kernel" on `-O` → expected for 22000; drop the `-O`.
- Metal skipped, reverts to OpenCL (esp. M4) → update hashcat to the latest beta; don't
  paper over it with `--force`.
- "Not enough allocatable device memory" → close GPU/RAM-heavy apps; unified memory is
  shared.
- Speed decays over minutes → thermal throttle; improve cooling or drop `-w 4`→`-w 3`.
- Live speed << benchmark → benchmark used optimized kernels / different attack; judge by a
  `--speed-only` run of your real attack.

---

## 10. DEFENSE — how a network makes every section above fail

The whole offline model dies against a sufficiently strong PSK or WPA3. Harden in this
order (this is the half that matters for an authorized assessment report):

1. **Passphrase entropy is the master control.** PBKDF2's 4096 iterations only buy time;
   §6 shows a random **20+ character** PSK (or a 5–6 word diceware phrase) pushes the
   keyspace past centuries even at datacenter-GPU speeds, let alone an M-series laptop.
   Never use phone numbers, dates, SSID-derived words, or anything in rockyou/weakpass/
   wpa-sec. This single change defeats §5 entirely.
2. **Move to WPA3-SAE (Dragonfly).** SAE replaces the PSK-verifier exchange with a
   password-authenticated key exchange, so **capturing the handshake does not yield an
   offline dictionary oracle** the way a WPA2 4-way handshake or PMKID does — there is no
   `-m 22000` equivalent for SAE. This is the structural fix, not merely a longer password.
3. **Require PMF / 802.11w (management-frame protection).** PMF blocks spoofed deauth/
   disassoc, the usual way an attacker *forces* a client to re-handshake for capture.
   Mandatory PMF (pure WPA3) removes the easy EAPOL-forcing path. PMKID capture needs no
   client at all, so it is **not** stopped by PMF — only by control (1).
4. **Avoid WPA3 "transition mode" where you can.** A mixed WPA2/WPA3 SSID is downgradeable
   back to the WPA2 offline-crackable path (a transition-downgrade attack can trick a
   client into the WPA2 handshake). Prefer **separate SSIDs** — one pure-WPA3, one legacy —
   over a single transition SSID, and retire the legacy SSID as clients allow.
5. **Disable WPS** — a separate attack surface (PIN brute force / Pixie-Dust) that bypasses
   PSK strength entirely, so a strong PSK doesn't save you if WPS is on.
6. **Detection (what a blue team watches for):** bursts of deauth/disassoc frames
   (handshake forcing), unsolicited association requests that elicit PMKIDs, and clients
   probing for your ESSID off-site. These all map to the *capture* step; by the time
   cracking runs it is offline and invisible on your network — which is exactly why (1) and
   (2) are the real controls, not detection.

**Net:** a long random PSK makes a captured handshake pointless; WPA3-SAE + mandatory PMF
makes capture both hard *and* pointless. Everything in §1–§9 is a race against entropy
that you, as the defender, get to set arbitrarily high — and the GPU on a MacBook is slow
enough that even a modest entropy bump ends the race before it starts.

---

## Sources

Verified against the following during this research pass (distinct sources, grouped).

**Primary / authoritative (official docs, man pages, project repos):**
- hashcat wiki — Cracking WPA/WPA2 (mode 22000, hc22000 format, PMKID/EAPOL, PBKDF2 reuse): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hashcat man page (`-w`, `-O`, `-d`, `-n`/`-u`, `--backend-info`, `--session`/`--restore`, `--potfile-*`, `--left`, `--remove`, `--show`, `--markov-*`, `--keyspace`, `--speed-only`, `--status-timer`): https://dyn.manpages.debian.org/trixie/hashcat/hashcat.1
- hashcat docs — slow-candidates mode (`-S`, host-side generation, PCIe tradeoff): https://github.com/hashcat/hashcat/blob/master/docs/slow-candidates-mode.md
- hashcat docs — brain (`--brain-server/-client`, `-z` auto-enables `-S`): https://github.com/hashcat/hashcat/blob/master/docs/hashcat-brain.md
- hashcat changelog (slow-candidates introduction): https://github.com/hashcat/hashcat/blob/master/docs/changes.txt
- Kali Linux — hashcat tool page: https://www.kali.org/tools/hashcat/
- Kali Linux — hcxtools package page: https://www.kali.org/tools/hcxtools/
- hcxpcapngtool man page: https://dyn.manpages.debian.org/trixie/hcxtools/hcxpcapngtool.1
- ZerBea hcxtools (README/filters, hcxhashtool): https://github.com/ZerBea/hcxtools
- ZerBea hcxdumptool (capture, pcapng, M1/M2/M3 pairing): https://github.com/ZerBea/hcxdumptool
- Wikipedia — Hashcat (modes, attack types, `--slow-candidates` note): https://en.wikipedia.org/wiki/Hashcat

**hashcat forum (Apple Silicon, mode 22000, potfile, kernel behavior, benchmarks):**
- "How to get maximum performance from Apple Silicon (M1–M3)?" (Metal vs OpenCL, `-d`, GPU-only): https://hashcat.net/forum/thread-11876.html
- Mode 22000 `-O` "falling back to pure kernel" / PSK length 8–63 / no optimized kernel: https://hashcat.net/forum/thread-10538.html
- Expected hashrates with `-m 22000`: https://hashcat.net/forum/post-50243.html
- Choosing a specific Metal GPU on macOS (device numbering): https://hashcat.net/forum/thread-11081.html
- M1 Ultra benchmark thread: https://hashcat.net/forum/thread-10670.html
- Apple Silicon benchmark thread (Metal device output, mode skips): https://hashcat.net/forum/thread-12411.html
- M4 Metal skipped → reverts to OpenCL device 2 (Nov 2025): https://hashcat.net/forum/thread-13432.html
- "Not enough allocatable device memory on Mac" (unified-memory contention): https://hashcat.net/forum/post-55086.html
- "Only getting 1% of the benchmark hashrate" (backend/feed issues): https://hashcat.net/forum/post-55118.html
- Markov threshold semantics (`-t`, keyspace vs. coverage): https://hashcat.net/forum/thread-1265.html
- Dumping uncracked hashes (`--left` / `--remove` behavior, duplicates): https://hashcat.net/forum/post-55768.html

**Backend / tuning / benchmark write-ups:**
- ecto-1a — hashcat on Apple Silicon (Metal in 6.2.5, `-I`, device #1 Metal / #2 OpenCL, **M1 Max mode 22000 ≈ 247.8 kH/s**, benchmarks use optimized kernels by default, `powermetrics` for temp): https://ecto-1a.github.io/hashcatmac/
- camilyed — hashcat M3 benchmarks: https://camilyed.github.io/en/hashcat-m3-benchmarks
- Chick3nman — hashcat benchmark reference gist: https://gist.github.com/Chick3nman/fdf7f9ddcc0a65f6725aefede99ada4e
- crypt0rr — hashcat cheat sheet / Apple Silicon notes: https://gist.github.com/crypt0rr/a2965aca6cf2a19ffd84867156e73011
- labex — Use the potfile to manage cracked hashes (`--show`/`--left`/`--remove`/`--potfile-disable`): https://labex.io/tutorials/kali-use-the-potfile-to-manage-cracked-hashes-594517
- techearl — hashcat optimization (`-w` profiles, `-O`, `-S` for slow hashes): https://techearl.com/hashcat-optimization
- techearl — hashcat cheat sheet: https://techearl.com/hashcat-cheat-sheet

**Defense (WPA2 vs WPA3 / SAE / PMF / transition-mode downgrade):**
- CWNP — "Revisiting WPA2: understanding its security gaps and evaluating the move to WPA3" (whitepaper): https://www.cwnp.com/uploads/1660_cwnp-wp_revisiting-wpa-2-understanding-its-security-gaps-and-evaluating-the-move-to-wpa3_ver120224.pdf
- WiFi Coops — WPA3-Personal (SAE / Dragonfly) deep dive: https://wificoops.com/2019/07/28/wi-fi-security-enhancements-part-1-wpa3-personal-sae/
- Extreme Networks — WPA3 transition mode & PMF (802.11w) behavior: https://documentation.extremenetworks.com/

_Verify every speed/flag against your installed build: `hashcat -V`, `hashcat -I`,
`hashcat -b -m 22000`, `hashcat --help`. All figures above are measured reports or
order-of-magnitude anchors, not guarantees — your chip, macOS, cooling, and hashcat
version move them._
