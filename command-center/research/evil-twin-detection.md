# Evil-Twin Mechanics & Detection — Command-First Reference

> **Scope / authorization.** This is a DEFENSE + DETECTION reference for a local,
> allowlist-gated Wi-Fi audit toolkit. Everything here is for gear you own, a lab
> you control, or an engagement with written authorization (CTF / OSWP study /
> sanctioned red-team window). The "attack mechanics" sections exist only so the
> detector knows the signatures to hunt — this file deliberately does **not** build
> a rogue AP or a credential-phishing/captive-portal harvester. If you ever need to
> *stand up* an evil twin for an authorized red-team demo, that is a separate,
> scoped, signed-off activity; detection is the product here.

---

## 0. TL;DR decision order (what a pro runs, in order)

1. **Baseline first.** You cannot detect a rogue AP without knowing what "legit"
   looks like. Build an allowlist of `ESSID → {BSSID, channel, enc/cipher/auth, PMF}`
   for every AP you own *before* you hunt.
2. **Passive survey** with `airodump-ng` (both bands). Look for your ESSID appearing
   with a **BSSID not on the allowlist**, or a known BSSID advertising a **different
   channel / weaker crypto / open where it should be WPA2/3**.
3. **Signal/TX anomaly.** Same ESSID, two signal tracks, or a clone BSSID whose PWR
   and TX fingerprint differ from the real one → evil twin, even if BSSID matches.
4. **Deauth-storm watch.** Evil twins are almost always paired with a deauth/disassoc
   flood to peel clients off the real AP. Alert on bursts (`wlan.fc.type_subtype == 0x0c`).
5. **Promote to a standing WIDS** — Kismet (`APSPOOF`, `DEAUTHFLOOD`, `CHANCHANGE`,
   `CRYPTODROP`, `ADVCRYPTCHANGE`) or nzyme (fingerprint + signal-track + disconnection
   monitors) so detection is continuous, not a one-shot scan.
6. **Harden** so the attack fails even if present: 802.11w/PMF, WPA3 + transition
   disable, RADIUS server-cert validation, client config.

---

## 1. Concept (brief) — how an evil twin works, so you know the signatures

An **evil twin** is a rogue AP that impersonates a legitimate network by copying its
**ESSID** (network name), and usually also its **BSSID** (AP MAC), channel, and
advertised security. The goal is to get victim clients to associate to the attacker's
radio instead of the real AP. Detection keys off the seams in that impersonation.

**The usual chain (signatures to hunt, not a build guide):**

- **Clone the beacon.** The rogue broadcasts beacons with the target ESSID. Signature:
  *same ESSID, new/unexpected BSSID* — or a **cloned BSSID** whose RF fingerprint
  (PWR, TX timing, beacon rate, BSS timestamp) differs from the genuine radio.
- **Peel clients off the real AP.** Clients won't roam to a weaker/second copy on
  their own, so the attacker floods **deauthentication (subtype 0x0C)** or
  **disassociation (0x0A)** frames — often to the broadcast address — forcing clients
  to disconnect and re-associate. Signature: *deauth/disassoc storm*. (MITRE DET0379;
  nzyme "disconnection frames"; Wireshark `wlan.fc.type_subtype`.)
- **Variants:**
  - **Classic evil twin** — static ESSID clone on a chosen channel.
  - **KARMA / MANA** — the rogue *listens* for client probe requests ("is `HomeWiFi`
    here?") and answers "yes" for *any* SSID a device asks for, so a device's saved-
    network list becomes the attack surface. Signature: *one radio answering probe
    responses for many different SSIDs* (Kismet `KARMAOUI` catches the predictable
    `00:13:37` OUI used by some Karma / WiFi-Pineapple setups).
  - **Known-beacon** — rogue sprays beacons for common/default SSIDs to trigger auto-join.
  - **Enterprise (802.1X/EAP) evil twin** — rogue stands up a fake RADIUS endpoint to
    capture EAP identities/challenge-response. Defense is *client-side server-cert
    validation*, not RF detection (see §9).
- **Tooling that produces these signatures** (so you recognize them): `mdk4`/`mdk3`
  (deauth & beacon floods), `wifiphisher`, `airgeddon`, `eaphammer`, WiFi Pineapple,
  Pwnagotchi, ESP32 Marauder, Flipper Zero Evil Portal. nzyme fingerprints several of
  these platforms directly.

> **Key pro insight (GDS/Aon method):** an ESSID+BSSID match is *not* proof of
> legitimacy — a competent attacker clones the BSSID too. The durable discriminators
> are **physical-layer**: signal strength / TX values, beacon timing, BSS timestamp
> sequence. "Packets sniffed from the evil twin should have noticeably different TX
> values than packets sniffed from the legitimate access point."

---

## 2. Lab gear setup — monitor mode on the TP-Link RTL8188EUS (2.4 GHz)

Detection is passive sniffing, so you need **monitor mode**. The RTL8188EUS is 2.4 GHz
only — fine for 2.4 GHz hunts, but you are blind to 5 GHz twins with this adapter alone
(plan a second dual-band card for full coverage).

**Driver note (gotcha #1):** modern kernels ship `rtl8xxxu` / `r8188eu` in-tree, which
*can* do monitor mode on some builds. If injection/monitor fails, build the out-of-tree
`rtl8188eus` driver (v5.3.9 is the commonly-cited version) and blacklist the in-kernel
module:

```bash
# Identify the adapter and which driver claimed it
lsusb
sudo airmon-ng            # lists interfaces + driver/chipset

# If you must build the out-of-tree driver:
sudo apt update && sudo apt install -y bc build-essential dkms git linux-headers-$(uname -r)
echo 'blacklist r8188eu' | sudo tee -a /etc/modprobe.d/realtek.conf
git clone https://github.com/aircrack-ng/rtl8188eus   # or a maintained fork
cd rtl8188eus && make && sudo make install
sudo reboot
```

**Enter monitor mode (either method):**

```bash
# Method A — airmon-ng (kills interfering processes first)
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # creates wlan0mon (or renames to monN)

# Method B — manual via iw (more predictable naming)
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iw dev                                # confirm "type monitor"
```

**Verify injection/capture works before trusting a "clean" result:**

```bash
sudo aireplay-ng -9 wlan0mon          # injection self-test (lab only)
```

**Gotcha #2:** an auto driver update can silently break monitor mode after it worked
for days. Re-verify with `iw dev` + `aireplay-ng -9` at the start of each session.

---

## 3. Detection workflow — command-first

### 3.1 Passive survey (the first look)

```bash
# 2.4 GHz + 5 GHz sweep (5 GHz only if the adapter supports it), write everything to CSV
sudo airodump-ng --band abg -w survey --output-format csv,pcap --write-interval 1 wlan0mon
```

Read the AP section columns: `BSSID  PWR  Beacons  #Data  CH  MB  ENC  CIPHER  AUTH  ESSID`.
- **PWR** = signal level (−1 means "seen but out of range / no direct frame").
- **CH** = channel from the beacon; **ENC/CIPHER/AUTH** = advertised security.

**Target an ESSID you own and watch for a second BSSID:**

```bash
# Filter to your network name; several BSSIDs under one ESSID = investigate
sudo airodump-ng --band abg -N "YourCorpSSID" wlan0mon
# -N filters by ESSID (repeatable); -R takes a regex
```

### 3.2 Same-ESSID / different-BSSID + config-drift detection (allowlist diff)

The CSV airodump writes is the pivot. Group by ESSID and flag unknown BSSIDs or drifted
config offline:

```bash
# From the airodump CSV, list "ESSID  BSSID  CH  Privacy" and sort by ESSID to eyeball duplicates
awk -F',' 'NR>1 && $1 ~ /:/ {gsub(/^ +| +$/,"",$14); gsub(/^ +| +$/,"",$1);
  print $14"\t"$1"\t"$6"\t"$7$8$9}' survey-01.csv | sort

# Diff live BSSIDs for your ESSID against your allowlist (allowlist.txt = one BSSID per line)
awk -F',' 'NR>1 && $14 ~ /YourCorpSSID/ {gsub(/ /,"",$1); print $1}' survey-01.csv \
  | sort -u | comm -23 - <(sort -u allowlist.txt)
#   ^ anything printed = an ESSID match from a BSSID NOT on your allowlist → candidate evil twin
```

**What each drift means (Kismet maps these to named alerts too):**
| Observation | Meaning | Kismet alert |
|---|---|---|
| Your ESSID, unknown BSSID | Classic evil twin candidate | `APSPOOF` |
| Known BSSID, new channel | Spoof / CSA abuse | `CHANCHANGE`, `DOT11CSASPOOF` |
| Your ESSID now **open** / weaker cipher | Downgrade to ease capture | `CRYPTODROP`, `ADVCRYPTCHANGE` |
| Beacon rate changed | Attacker software fingerprint | `BEACONRATE` |
| BSS timestamp out of sequence | Two radios claiming one BSSID | `BSSTIMESTAMP` |
| Probe-resp channel ≠ beacon channel | Spoofed response | `PROBECHAN` |

### 3.3 Signal / TX anomaly (catches the BSSID-clone that beats the allowlist)

If the attacker clones the BSSID, name+MAC match — so pivot to the physical layer:

```bash
# Watch PWR for your BSSID over time; a genuine fixed AP is stable, a mobile rogue drifts,
# and TWO simultaneous signal levels for one BSSID = two transmitters.
sudo airodump-ng --bssid AA:BB:CC:DD:EE:FF -w sig --output-format csv wlan0mon
# Then trend PWR, Beacons, and beacon-interval; sudden implausible RSSI jumps / a second
# signal "track" for one BSSID is the evil-twin tell (nzyme calls this the second signal track).
```

Heuristic (academic + GDS/Aon): baseline each known AP's RSSI range from its fixed
location; an **implausible RSSI jump** or a **second concurrent track** for one BSSID
exposes a rogue even when ESSID+BSSID look legitimate. RSSI is noisy (multipath,
interference) so treat it as a *flag to investigate*, not a verdict — corroborate with
beacon timing / BSS timestamp.

### 3.4 Deauth / disassoc storm detection (the companion signature)

Evil twins lean on deauth to move clients. Catch the storm live:

```bash
# Live count of deauth(0x0C) + disassoc(0x0A) with tshark
sudo tshark -i wlan0mon -Y '(wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a)' \
  -T fields -e frame.time -e wlan.sa -e wlan.da -e wlan.fc.type_subtype

# One-line rate alarm: count broadcast deauths per 10s window
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'
```

**Wireshark display filters (keep these handy):**
- Deauth: `wlan.fc.type_subtype == 0x0c`
- Disassoc: `wlan.fc.type_subtype == 0x0a`
- Both (mgmt): `wlan.fc.type==0 && (wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12)`
- Beacons: `wlan.fc.type_subtype == 0x08`
- Deauth reason code: `wlan.fixed.reason_code`

**Rule of thumb:** >~20 deauths to the broadcast address within 60s, or hundreds–
thousands/min on a normally-quiet network, is a storm. Baseline your own quiet-network
rate first — a handful of deauths is normal.

### 3.5 Promote to a standing WIDS — Kismet

Kismet turns the one-shot survey into continuous, named alerting. The high-value alert
is **APSPOOF**: you declare the valid MACs for an SSID, and Kismet fires when that SSID
is beaconed from a MAC not on the list.

```bash
sudo kismet -c wlan0mon          # or add the source in the web UI (:2501)
```

`kismet_site.conf` (preferred override location — do **not** edit `kismet_alerts.conf`):

```conf
# --- Evil-twin: valid MACs for your SSID (exact, regex, or OUI-masked) ---
apspoof=Corp1:ssid="YourCorpSSID",validmacs="00:11:22:33:44:55,AA:BB:CC:DD:EE:FF"
# regex form:   apspoof=Corp2:ssidregex="(?:YourCorp.*)",validmacs=00:11:22:33:44:55
# OUI mask:     apspoof=Corp3:ssid="YourCorpSSID",validmacs="00:11:22:00:00:00/FF:FF:FF:00:00:00"

# De-dup can hide flood/spoof frames from APSPOOF/DEAUTHFLOOD — disable it for full coverage:
packets_dedup_size=0

# --- Rate limits: alert=NAME,<max>/min,<max>/sec  (0/min,0/sec disables) ---
alert=APSPOOF,5/min,1/sec
alert=DEAUTHFLOOD,5/min,1/sec
alert=BCASTDISCON,5/min,1/sec
alert=CHANCHANGE,5/min,1/sec
alert=CRYPTODROP,5/min,1/sec
alert=ADVCRYPTCHANGE,5/min,1/sec
alert=BSSTIMESTAMP,5/min,1/sec
alert=KARMAOUI,5/min,1/sec
```

**Kismet alerts most relevant to evil-twin hunting:**
`APSPOOF` (SSID from unlisted MAC), `ADVCRYPTCHANGE`/`CRYPTODROP` (crypto downgrade),
`CHANCHANGE` (channel moved), `BEACONRATE` (beacon-rate change), `BSSTIMESTAMP`
(spoofed/duplicate radio), `PROBECHAN` (probe-resp channel mismatch), `KARMAOUI`
(Karma/Pineapple OUI), `DEAUTHFLOOD`/`BCASTDISCON` (deauth/disassoc flood),
`DISCONCODEINVALID` (bad reason code), `NOCLIENTMFP` (client without PMF on an
MFP-capable net — your hardening gap).

### 3.6 Alternative standing WIDS — nzyme

nzyme is a purpose-built, sensor-based WiFi defense system. It:
- inventories every AP/SSID seen, you approve the legit ones, it alerts on the rest;
- **correlates over-the-air vs on-the-wire** to separate real intrusions from neighbors;
- **fingerprints** APs from how they advertise themselves ("hardware-defined, hard to
  fake") and flags **impossible-location** (one AP in two places at once);
- compares against **expected BSSID/channel/security** (e.g. corp SSID appearing open);
- **signal-track** detection (a second track for one AP = another transmitter);
- flags **look-alike SSIDs**;
- recognizes attack platforms (WiFi Pineapple, Pwnagotchi, Wifiphisher, ESP32 Marauder,
  Flipper Evil Portal, O.MG);
- **disconnection-frame monitors** — counts deauth/disassoc vs a per-network threshold;
- **probe-request monitoring** — alerts when your SSIDs are probed in unexpected places.

Needs monitor-mode adapters ("sensors"); designed to be **stationary**, not wardriving.

---

## 4. Gotchas & pitfalls

- **ESSID+BSSID match ≠ legit.** A good attacker clones the BSSID. Always have a
  physical-layer check (signal/timing/BSS timestamp) behind the allowlist.
- **Same-name neighbor ≠ attack.** A coffee shop next door with the same default SSID is
  a false positive. Dwell-time filtering (nzyme) and wired-side correlation cut these.
- **RSSI is noisy.** Multipath, interference, and a moving sensor all move RSSI.
  Keep the sensor **stationary** and baseline per-AP ranges; use RSSI to *flag*, not convict.
- **Packet de-dup hides floods.** Kismet's de-dup can suppress the very frames APSPOOF /
  DEAUTHFLOOD need — set `packets_dedup_size=0` when running as a detector.
- **Channel hopping = missed frames.** A hopping single radio misses fast floods on other
  channels. Lock to the target channel (`airodump-ng -c N`) when confirming, or run
  multiple radios/sensors pinned to different channels.
- **2.4 GHz-only blindness.** The RTL8188EUS can't see 5 GHz/6 GHz twins. Add a dual-band
  sensor for real coverage.
- **Monitor mode silently dies** after driver updates — re-verify each session (§2).
- **Public Wi-Fi has no WIDS.** Enterprise detection only works where you've deployed
  sensors; a twin at a hotel/airport is a client-side problem (HTTPS, VPN, cert checks,
  turn off auto-join).
- **Modern clients may ignore the twin.** Some phones won't roam to a weaker duplicate —
  absence of victims doesn't mean absence of the rogue; keep hunting the beacon.

---

## 5. Pro tips for speed

- **Baseline once, diff forever.** A static `allowlist.txt` of `ESSID,BSSID,CH,ENC` turns
  detection into a `comm`/`diff` one-liner (§3.2). This is the single biggest time-saver.
- **CSV > eyeballing.** Always `-w` to CSV and group by ESSID with `awk`/`sort`; the terminal
  view scrolls and you miss the second BSSID.
- **Pin the channel to confirm.** Survey wide, then `-c <chan>` + `--bssid` to lock on and
  trend PWR/beacons without hop gaps.
- **Two signals = done.** The fastest high-confidence tell is a **second signal track for
  one BSSID** — you don't need to decrypt anything.
- **Let the WIDS page you.** Don't babysit `airodump`; put Kismet/nzyme on it with APSPOOF +
  deauth thresholds and alert to Slack/Graylog. nzyme can forward frames to Graylog for forensics.
- **Correlate wire + air.** If a sensor sees the SSID over the air but it's not on your
  switch/controller, that's a strong rogue signal (nzyme AP-correlation).
- **Hunt KARMA by the OUI.** `KARMAOUI` / a single radio answering many SSID probe-responses
  is a cheap, specific catch for Pineapple/Karma-style twins.

---

## 6. Defense (the pairing — make the attack fail even if present)

- **802.11w / Protected Management Frames (PMF).** Integrity-protects management frames so
  **forged deauth/disassoc are rejected** by both AP and client — kills the "peel clients
  off" step. Set **Required** mode (default-on under WPA3-Personal-only and WPA3-Enterprise
  192-bit). Plan for legacy clients that lack PMF and will fail to associate. PMF does *not*
  stop the twin from being visible (clients still see rogue beacons) — it stops the deauth DoS.
- **WPA3 + Transition Disable.** WPA3-SAE resists offline PSK cracking; **Transition Disable
  (802.11-2020)** tells a client that has authenticated via WPA3 once to **stop connecting to
  the WPA2 variant** of that SSID — closes the downgrade path a twin relies on.
- **Enterprise: validate the RADIUS server certificate.** The real defense against an
  **enterprise evil twin** is client-side **server-cert validation** (pin the CA + server
  name) so a client never sends EAP creds to a fake RADIUS. PMF alone doesn't solve this.
- **Monitor `NOCLIENTMFP`.** Clients associating without PMF on an MFP-capable network are your
  remaining exposure — track and remediate.
- **Client hygiene.** Disable auto-join to open/known SSIDs, prune saved networks (shrinks the
  KARMA surface), prefer HTTPS/VPN on untrusted Wi-Fi, heed captive-portal/cert warnings.
- **Operational.** Keep a current AP allowlist, run a stationary WIDS (Kismet/nzyme), alert on
  deauth storms + APSPOOF, and physically locate confirmed rogues (trilateration / signal
  walk-down) rather than only logging them.

---

## 7. Copy-paste quick kit

```bash
# 1) Monitor mode + verify
sudo airmon-ng check kill && sudo airmon-ng start wlan0 && iw dev

# 2) Wide passive survey to CSV/pcap
sudo airodump-ng --band abg -w survey --output-format csv,pcap --write-interval 1 wlan0mon

# 3) Evil-twin diff: your ESSID from a BSSID not on the allowlist
awk -F',' 'NR>1 && $14 ~ /YourCorpSSID/ {gsub(/ /,"",$1); print $1}' survey-01.csv \
  | sort -u | comm -23 - <(sort -u allowlist.txt)

# 4) Deauth-storm watch
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'

# 5) Lock on a suspect to trend its signal
sudo airodump-ng --bssid <SUSPECT_BSSID> -c <CHAN> -w sig --output-format csv wlan0mon

# 6) Standing WIDS
sudo kismet -c wlan0mon     # with apspoof=/alert= set in kismet_site.conf
```

---

## 8. Sources

Official tool/standards docs and primary references actually used:

- Kismet — Wi-Fi alerts reference (APSPOOF, DEAUTHFLOOD, CHANCHANGE, etc. + `apspoof=`/`alert=` syntax): https://www.kismetwireless.net/docs/readme/alerts/alerts/
- Kismet — Kali tools page: https://www.kali.org/tools/kismet/
- nzyme — Wireless capabilities (rogue AP, evil-twin fingerprint, signal track, disconnection monitors): https://www.nzyme.org/capabilities/wireless
- nzyme — GitHub (architecture, monitor-mode sensors, Graylog): https://github.com/Offensive-Wireless/nzyme
- nzyme — Deauthentication frames explained: https://www.nzyme.org/knowledge/wifi/deauthentication-frames-explained
- MITRE ATT&CK — Detection Strategy DET0379 "Detect Evil Twin Wi-Fi Access Points": https://attack.mitre.org/detectionstrategies/DET0379/
- Wi-Fi Alliance — Protected Management Frames (802.11w / PMF): https://www.wi-fi.org/node/36713
- aircrack-ng — airodump-ng man page (columns, `-N`/`-R`/`-b`/`-w` flags): https://man.archlinux.org/man/airodump-ng.8.en
- Black Hills InfoSec — Hunting with airodump-ng (dual-band survey practice): https://www.blackhillsinfosec.com/hunt-for-weak-spots-in-your-wireless-network-with-airodump-ng/
- HackTricks — Pentesting Wi-Fi (attack signatures, mdk4 deauth, tooling): https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi
- Kali Tools — Wireless IDS (deauth burst + similar-SSID detection): https://en.kali.tools/?p=83
- GDS Security — "Slaying Rogue Access Points…" (whitelist + TX-value/signal method): https://blog.gdssecurity.com/labs/2016/8/26/slaying-rogue-access-points-with-python-and-cheap-hardware.html
- Aon Cyber Labs — Identifying rogue AP attacks via probe-response patterns & signal strength: https://www.aon.com/cyber-solutions/aon_cyber_labs/whitepaper-identifying-rogue-access-point-attacks-using-probe-response-patterns-and-signal-strength
- Tripwire — Detect & attack evil-twin Wi-Fi access points: https://www.tripwire.com/state-of-security/detect-attack-evil-twin-wifi-access-points
- arXiv 2406.01927 — Liu & Papadimitratos, Position-based Rogue AP Detection (RSSI/CSI limits): https://arxiv.org/pdf/2406.01927
- Purple.ai — Rogue access point detection / RF fingerprinting (power, channel, timing, location): https://www.purple.ai/en-us/blogs/rogue-access-point-detection
- mrncciew — 802.11 mgmt deauth/disassociation frames (subtypes 0x0A/0x0C): https://mrncciew.com/2014/10/11/802-11-mgmt-deauth-disassociation-frames/
- Wireshark Q&A — Detect deauthentication attack (filters): https://ask.wireshark.org/question/30282/detect-de-authentication-attack-on-wifi/
- LabEx — Detect a Fluxion deauth attack with Wireshark (`wlan.fc.type_subtype==0x0c`): https://labex.io/tutorials/kali-detect-a-fluxion-deauthentication-attack-using-wireshark-594462
- rtl8188eus driver (monitor-mode build/blacklist recipe for the TP-Link RTL8188EUS): https://github.com/aircrack-ng/rtl8188eus

*Framing: authorized / own-gear only. Evil-twin coverage here is detection + concept for
defense; no credential-harvesting or captive-portal build is included by design.*
