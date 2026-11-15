# Blue-Team / Wi-Fi Defense — The Hardening Checklist (Command-First Reference)

> **Scope / authorization.** This file is for *authorized* work only: your own gear, a lab
> you control, sanctioned CTFs/competitions, or OSWP study. This is the **defensive** half of
> the knowledge base — the controls that make every attack documented elsewhere in `research/`
> fail or get caught. Every item below is written so a learner can **turn it on, verify it's
> on, and detect when someone attacks it.** For evil-twin we cover **detection and concept
> only** — never a credential-harvesting portal.
>
> **The one-line thesis:** *WPA3-only + PMF required + a long random passphrase (or 802.1X
> with real cert validation) + WPS off + segmentation + a monitor-mode sensor running Kismet
> = the attacker's entire offline/downgrade/deauth toolkit stops working.* Everything in this
> file builds that sentence out with exact commands.
>
> **Research note (this run):** the shared web-search budget for the workflow was exhausted
> before this file's searches ran, so this reference was compiled from deep expert knowledge
> of the primary docs (hostapd/`w1.fi`, Wi-Fi Alliance, Kismet, nzyme, aircrack-ng, IETF/IEEE,
> NIST, vendor WIPS docs, CVE advisories). The **Sources** list points to those authoritative
> references by their canonical URLs; they were **not re-fetched this run** — verify any exact
> flag against the installed man page / running version before you rely on it in production.

---

## 1. Concept — the defender's threat model → control map

Wi-Fi security is five problems. Map each attack class to the control that kills it, and the
whole checklist writes itself:

| Attack class (see sibling file) | Primary control | Secondary / detection |
|---|---|---|
| **Offline PSK crack** (4-way handshake → `hashcat -m 22000`; `pmkid.md`, `handshake-capture.md`) | **WPA3-SAE** (no offline guess) OR a **≥20-char random WPA2 PSK** (infeasible offline) | Rotate PSK; passphrase policy |
| **PMKID roaming-cache attack** (`pmkid.md`) | Disable PMKID caching / WPA3-SAE | AP firmware that doesn't emit PMKID |
| **Deauth / disassoc flood & DoS** (`deauth-dos.md`) | **802.11w PMF** (signs mgmt frames) | Kismet `DEAUTHFLOOD`; frame-count WIDS |
| **KRACK** key-reinstallation (`krack.md`) | **Patch client + AP**; EAPOL retransmit hardening | Firmware/driver version audit |
| **Kr00k / FragAttacks** (`kr00k-fragattacks.md`) | **Patch firmware/driver**; WPA3; per-packet checks | Version audit; anomalous frag detection |
| **Evil-twin / rogue AP / KARMA-MANA** (`evil-twin-detection.md`, `karma-mana.md`) | **WPA3-only + PMF** (defeats transition downgrade); **802.1X server-cert validation** | **Rogue-AP WIDS** (Kismet APSPOOF, nzyme) |
| **WPS PIN / Pixie-Dust** (`wps-*.md`) | **Disable WPS entirely** | AP that has no WPS; firmware without ECC-nonce bug |
| **Transition/version downgrade** (`wpa3-sae-dragonblood.md`) | **Drop transition mode → WPA3-only** | Baseline AKM/RSN per BSSID; alert on change |
| **Enterprise EAP relay / rogue RADIUS** (`wpa-enterprise-eap.md`, `mschapv2-cracking.md`) | **EAP-TLS** or validated PEAP/TTLS with **pinned CA + server name**; **PWD/strong creds** | RADIUS logs; WIDS |

**Defensive priority order (do them in this order):**

1. **WPA3-only + PMF required** (or, where WPA3 isn't possible, WPA2 + a long random PSK + PMF).
2. **Kill WPS.**
3. **Strong passphrase / 802.1X with real cert validation.**
4. **Patch everything** (KRACK/Kr00k/FragAttacks/Dragonblood are all patch-closed).
5. **Segment** (guest VLAN, client isolation, management-plane isolation).
6. **Monitor** (a standing monitor-mode sensor + baseline + alerts).

---

## 2. WPA3 / SAE deployment — the single biggest win

**Why first:** WPA3-Personal replaces the offline-crackable 4-way-handshake-only model with
**SAE (Dragonfly PAKE)**. A captured SAE exchange yields *nothing* testable offline — there is
no hashcat mode for a WPA3-SAE PSK. Guessing becomes **online-only** and rate-limited. PMF is
**mandatory** in WPA3, so deauth-forced re-handshakes stop working too. (Full attack-side
detail: `wpa3-sae-dragonblood.md`.)

### 2.1 hostapd (the reference implementation — exact config)

```ini
# /etc/hostapd/hostapd.conf  — WPA3-Personal (SAE), hardened, NO transition mode
interface=wlan0
ssid=LAB-SECURE
country_code=US                 # sets regulatory domain / channels / TX power
hw_mode=g
channel=6
wpa=2                           # RSN
wpa_key_mgmt=SAE                # SAE ONLY — not "WPA-PSK SAE" (that is transition mode)
rsn_pairwise=CCMP               # AES-CCMP; NEVER TKIP
ieee80211w=2                    # PMF REQUIRED (2=required, 1=optional/capable, 0=off)
sae_pwe=1                       # 1 = Hash-to-Element (H2E) ONLY — constant-time, Dragonblood-safe
                                # (2 = H2E + Hunting-and-Pecking for compat; 0 = H&P only = AVOID)
sae_require_mfp=1               # refuse SAE clients that won't do PMF
wpa_passphrase=CHANGE-ME-TO-A-LONG-RANDOM-STRING
# Optional anti-flood on SAE commit (rate-limit online guessing / DoS):
sae_anti_clogging_threshold=5   # older name; newer hostapd: anti_clogging_threshold / sae_sync
```

**Transition mode (WPA2+WPA3 on one SSID) — understand the trade:**

```ini
# Transition mode advertises BOTH WPA2-PSK and SAE. A downgrade/evil-twin can strip the SAE
# side and attack WPA2. Use ONLY if you must support legacy clients, and if so:
wpa_key_mgmt=WPA-PSK SAE
ieee80211w=1                    # PMF "optional" is forced here — WPA2 clients can't do required PMF
# Harden it with SAE-PK or, better, split SSIDs: legacy on its own VLAN'd SSID, kill it ASAP.
```

**SAE-PK** (public-key-authenticated SAE, for networks where clients know a fingerprint — kills
evil-twin on *known* public SSIDs): set `sae_password=<pw>|pk=<fingerprint>:<key>` per the
hostapd docs; the AP proves it holds the private key so a clone can't impersonate it.

**Start & sanity-check:**

```bash
sudo hostapd -dd /etc/hostapd/hostapd.conf     # -dd = verbose; watch for "SAE" and "MFP"
# In another shell, confirm the BSS advertises what you think:
sudo iw dev wlan0 info
```

### 2.2 OpenWrt / consumer AP (UCI)

```bash
uci set wireless.@wifi-iface[0].encryption='sae'          # WPA3-Personal only
# transition: 'sae-mixed'  |  WPA2 only: 'psk2'  |  enterprise: 'wpa3'/'wpa3-mixed'
uci set wireless.@wifi-iface[0].ieee80211w='2'            # PMF required
uci set wireless.@wifi-iface[0].key='LONG-RANDOM-PASSPHRASE'
uci set wireless.@wifi-iface[0].sae_pwe='1'               # H2E only where supported
uci commit wireless && wifi reload
```

### 2.3 Vendor equivalents (names only — exact UI varies)

- **Cisco (IOS-XE / Catalyst / Meraki):** WLAN security → "WPA3" (SAE) or "WPA2+WPA3",
  **PMF = Required**, disable "WPA2 Policy" when going WPA3-only.
- **Aruba/HPE:** opmode `wpa3-sae-aes`; `mfp-capable`/`mfp-required`; set H2E.
- **Ubiquiti UniFi:** Security = "WPA3" (or "WPA2/WPA3"), PMF = Required when WPA3-only.

**Verification (prove SAE+PMF is actually on the air):**

```bash
# From a monitor-mode sensor, read the RSN/AKM & RSN capabilities of your own BSS:
sudo airodump-ng wlan0mon --essid "LAB-SECURE"   # AUTH column should show SAE, not PSK
# Deeper: tshark decodes AKM suite (00-0f-ac:8 = SAE, :2 = PSK) and the MFPC/MFPR bits:
sudo tshark -i wlan0mon -Y 'wlan.ssid=="LAB-SECURE" && wlan.fc.type_subtype==0x08' \
  -T fields -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr
# MFPR=1 ⇒ PMF required.  AKM=8 ⇒ SAE.  If you see AKM=2 as well, you're in transition mode.
```

---

## 3. 802.11w / PMF (Protected Management Frames) — the deauth killer

**What it does:** Without PMF, management frames (deauth, disassoc, some action frames) are
**unauthenticated** — any attacker can spoof a deauth and kick clients (the basis of
`deauth-dos.md` and of forcing handshake re-captures). PMF (IEEE 802.11w) adds:

- **SA Query** + **BIP (Broadcast/Integrity Protection, BIP-CMAC-128)** so unicast and
  broadcast mgmt frames are integrity-protected/encrypted.
- Forged deauth/disassoc are **dropped**. An attacker's `aireplay-ng --deauth` becomes a no-op
  against PMF-required clients.

**Three modes — know the exact meaning:**

| `ieee80211w` | Meaning | When |
|---|---|---|
| `0` | Disabled | legacy only — avoid |
| `1` | Capable / optional | transition; protects PMF-capable clients only |
| `2` | **Required** | WPA3 (mandatory) and recommended for any WPA2 where all clients support it |

**Config:** already shown in §2 (`ieee80211w=2`, `sae_require_mfp=1`). For **WPA2 + PMF**
(protects legacy nets that can't move to WPA3 yet):

```ini
wpa=2
wpa_key_mgmt=WPA-PSK-SHA256     # SHA256 KeyMgmt is required for full PMF on WPA2-PSK
ieee80211w=2
rsn_pairwise=CCMP
```

**Caveat / gotcha:** forcing `ieee80211w=2` on a WPA2 net **kicks off clients that don't
support 802.11w** (old IoT, some printers). Stage it: set `1` (optional), watch logs for
non-capable clients, then move to `2`.

**Verify PMF is live and working:**

```bash
# 1) Confirm MFPR bit in beacons (see §2.3 tshark one-liner; mfpr=1).
# 2) PROVE it defeats deauth — on YOUR OWN net only: send a deauth and confirm the client
#    stays associated (frame rejected). This is a control TEST, not an attack:
sudo aireplay-ng --deauth 5 -a <YOUR_BSSID> -c <YOUR_CLIENT_MAC> wlan0mon
#    On a PMF-required link the client does NOT drop → control verified.
# 3) Watch for SA Query exchanges (PMF recovery) in tshark:
sudo tshark -i wlan0mon -Y 'wlan.fixed.category_code==8'   # SA Query action frames
```

---

## 4. Strong passphrases — the entropy that makes offline moot

Even without WPA3, a **long random PSK** makes the offline attack in `hashcat-masks.md` /
`wordlist-strategy.md` economically hopeless. The crack cost is set by **entropy**, not by
"complexity rules."

**The math (why length beats symbols):**

- A passphrase's guess-space is `charset_size ^ length`. A GPU rig doing, say, ~1–3 M WPA2
  guesses/sec (realistic for `-m 22000` on consumer GPUs; see `gpu-cracking-optimization.md`)
  needs, on average, half the space.
- **Rule of thumb:** a WPA2 PSK should carry **≥ 60–70 bits** of entropy to be safe for years;
  WPA3 needs less (online-only) but still use real entropy.

**Entropy by scheme (per unit):**

| Scheme | Bits per unit | Units for ~70 bits |
|---|---|---|
| lowercase a–z | 4.7 /char | ~15 chars |
| mixed alnum+sym (~94) | 6.55 /char | ~11 chars |
| **Diceware words** (7776 list) | **12.9 /word** | **~6 words** |

**Generate a genuinely random PSK (don't invent one by hand):**

```bash
# 20 URL-safe random chars (~119 bits):
openssl rand -base64 18 | tr -d '/+=' | cut -c1-20
# or 24 hex chars (~96 bits):
head -c 12 /dev/urandom | xxd -p
# Diceware (6 words, memorable, ~77 bits) — needs the EFF large wordlist:
for i in $(seq 6); do shuf -n1 /path/eff_large_wordlist.txt | cut -f2; done | paste -sd'-'
```

**Policy, not just a string:**

- **Never** reuse a PSK across SSIDs/sites. A shared PSK means one capture compromises all.
- Rotate on staff/tenant change (PSK is a *shared* secret — WPA2 has no per-user revocation;
  that's an argument for 802.1X, §6).
- **Minimum 8 chars is the WPA2 *protocol* floor, not a security target** — treat ≥20 random
  (or 6 Diceware words) as the real minimum.
- Consider **per-device PSKs** (iPSK / "Private PSK" / MPSK on enterprise APs) so each client
  has its own key and can be revoked individually.

---

## 5. Disable WPS — non-negotiable

**Why:** WPS PIN is **offline-brute-forceable** via the Reaver/Pixie-Dust path
(`wps-pin-reaver.md`, `wps-pixiedust.md`). Pixie-Dust recovers the PIN in **seconds** on APs
with weak E-S1/E-S2 nonce generation, bypassing the PSK entirely. There is **no safe WPS** —
even "PIN disabled, push-button only" firmware has repeatedly shipped bugs. **Turn it off.**

```bash
# hostapd: WPS off = simply DO NOT include any wps_* / eap_server lines.
# If a config has them, remove: wps_state, eap_server=1, ap_setup_locked, config_methods...
grep -iE 'wps|eap_server' /etc/hostapd/hostapd.conf    # should return NOTHING for a hardened AP

# OpenWrt:
uci set wireless.@wifi-iface[0].wps_pushbutton='0'
uci -q delete wireless.@wifi-iface[0].wps_label
uci commit wireless && wifi reload

# Consumer AP: web UI → Wireless/Advanced → WPS → OFF (disable both PIN and PBC).
```

**Verify WPS is truly off (don't trust the checkbox):**

```bash
# wash (reaver suite) lists APs ADVERTISING WPS. Your own BSSID must NOT appear.
sudo wash -i wlan0mon
# Or tshark: a WPS IE in beacons (OUI 00-50-f2, type 4) means WPS is still advertised:
sudo tshark -i wlan0mon -Y 'wlan.ssid=="LAB-SECURE" && wps.version2' -T fields -e wlan.bssid
# Empty output = WPS not advertised. If wash shows it with "Lck" No, it's attackable.
```

**Gotcha:** some firmwares re-enable WPS after a factory reset or firmware upgrade — re-verify
with `wash` after any maintenance.

---

## 6. WPA3-Enterprise / 802.1X / RADIUS — for anything beyond a home net

A PSK is a *shared* secret: no per-user identity, no revocation, one leak compromises all.
**802.1X/EAP** gives per-user credentials, central logging, and revocation. But EAP's security
lives or dies on **client-side server-certificate validation** — this is the #1 misconfig the
rogue-RADIUS / evil-twin-enterprise attacks in `wpa-enterprise-eap.md` and `mschapv2-cracking.md`
exploit.

### 6.1 Choose the EAP method (strongest first)

- **EAP-TLS** — mutual certs, **no password to steal/relay**. Best. Requires client-cert PKI.
- **EAP-TTLS / PEAP-MSCHAPv2** — password inside a TLS tunnel. **Only safe if the client pins
  the CA and server name.** Otherwise a rogue AP + `hostapd-wpe`/`eaphammer` captures the
  MSCHAPv2 challenge/response → offline crack (`mschapv2-cracking.md`). MSCHAPv2 is weak (DES →
  effectively a single DES keyspace); treat any leaked challenge/response as crackable.
- **EAP-PWD** — password-based PAKE, no cert needed, resists offline — but less widely supported.

### 6.2 The control that actually matters: client validation

```
On EVERY client profile, set:
  - CA certificate = your issuing CA (pinned), "Do NOT prompt / do NOT allow new CAs"
  - Server name / domain = radius.yourdomain  (exact match or suffix)
  - EAP method + inner method locked
Windows GPO: "Validate server certificate" = ON + specify Trusted Root CA + server names.
Apple/Android: deploy a CONFIG PROFILE / MDM payload — do not let users "trust" at the prompt.
```

Without this, a rogue RADIUS impersonates your server and harvests inner credentials — the
cert prompt is the whole attack surface.

### 6.3 WPA3-Enterprise 192-bit mode (high-security)

```ini
# hostapd — WPA3-Enterprise 192-bit (CNSA suite): GCMP-256 + SHA-384 + Suite-B key mgmt
wpa=2
wpa_key_mgmt=WPA-EAP-SUITE-B-192
rsn_pairwise=GCMP-256
group_mgmt_cipher=BIP-GMAC-256
ieee80211w=2                     # PMF required (mandatory in WPA3-Enterprise)
ieee8021x=1
auth_server_addr=127.0.0.1
auth_server_port=1812
auth_server_shared_secret=LONG-RANDOM-RADIUS-SECRET
```

**RADIUS hygiene:** long random shared secret per NAS; RADIUS over IPsec/RadSec if it crosses
untrusted links; log every Access-Reject and watch for a spike (credential stuffing / rogue
client probing).

---

## 7. Segmentation — contain what you can't prevent

Even a perfectly hardened Wi-Fi link shouldn't put a guest phone on the same L2 as your NAS.
Segmentation turns "one compromised client" into "one contained client."

### 7.1 Controls & exact knobs

```ini
# hostapd — client (station) isolation: clients on this BSS can't talk to EACH OTHER:
ap_isolate=1
# Per-SSID VLAN tagging (multi-SSID AP): tag guest onto its own VLAN:
# (dynamic VLAN via RADIUS, or static per-BSS in a bss= block with vlan_id)
```

```bash
# OpenWrt: isolate clients + put guest SSID on its own network/VLAN/firewall zone:
uci set wireless.@wifi-iface[0].isolate='1'          # client isolation
uci set wireless.@wifi-iface[0].network='guest'      # separate L3 network
uci commit wireless && wifi reload
# Then a firewall zone 'guest' with: input REJECT, forward REJECT, only forward→wan ACCEPT,
# and an explicit rule DROPPING guest→lan.
```

### 7.2 The segmentation checklist

- **Guest VLAN** with **internet-only** egress (drop guest→LAN, guest→mgmt).
- **IoT VLAN** — cameras/TVs/plugs isolated from trusted hosts; allow only the cloud/hub flows
  they need; **client isolation ON**.
- **Management plane isolated:** AP/switch/RADIUS admin on a dedicated VLAN, not reachable from
  guest/IoT/user VLANs; no Wi-Fi management of infra from the guest SSID.
- **Client isolation (`ap_isolate`)** on guest + IoT so a rogue client can't pivot laterally.
- **DHCP snooping / ARP inspection / port security** on the wired side to blunt an attacker who
  plugs a rogue AP into your LAN (the wired-side rogue-AP problem).
- **Disable inter-SSID bridging** on the AP.

---

## 8. WIDS / WIPS & rogue-AP detection — the standing sensor

Prevention fails silently; **detection** tells you when someone is trying. On the Mac+Kali+
RTL8188EUS lab, the practical build is a **monitor-mode sensor running Kismet**, optionally
**nzyme** for a longer-term rogue/evil-twin watch. (Full detection detail: `evil-twin-detection.md`.)

### 8.1 Kismet — the workhorse WIDS

```bash
# Put the adapter in monitor mode (RTL8188EUS recipe lives in adapters-drivers-monitor.md):
sudo airmon-ng check kill
sudo airmon-ng start wlan0            # → wlan0mon

# Run Kismet on the monitor interface (web UI on http://localhost:2501):
sudo kismet -c wlan0mon
```

**Kismet alerts that matter (set in `/etc/kismet/kismet_site.conf`):**

```ini
# Alert on a BSSID advertising one of YOUR SSIDs that isn't a known-good BSSID (evil twin):
apspoof=LAB-RULE:ssid="LAB-SECURE",validmacs="aa:bb:cc:dd:ee:ff"
# Deauth/disassoc flood (the deauth-dos.md signature):
alert=DEAUTHFLOOD,5/min,1/sec
alert=BCASTDISCON,5/min,1/sec
# AP changing channel unexpectedly (possible spoof):
alert=CHANCHANGE,5/min,1/sec
# New AP / probe anomalies:
alert=APSPOOF,10/min,1/sec
alert=NEWAP,0/min,0/sec
```

- **APSPOOF** → an AP claiming your SSID from a MAC not in `validmacs` = candidate evil twin.
- **DEAUTHFLOOD / BCASTDISCON** → someone running the `deauth-dos.md` attack.
- **CHANCHANGE** → a legit AP's clone trying to pull clients.

### 8.2 nzyme — longer-term rogue/evil-twin fingerprinting

nzyme (Offensive-Wireless) runs monitor-mode **sensors** feeding a central node; it does
rogue-AP detection, **evil-twin fingerprinting** (tracks beacon fingerprints, not just BSSID),
signal-strength tracking (a clone usually sits at a different RSSI), and disconnection monitors
(deauth storms). Good when you want a persistent, queryable record rather than a live terminal.

### 8.3 Lightweight home-grown WIDS (no extra software)

```bash
# A) Baseline: record every BSSID advertising your SSID, with AKM + PMF, as "known good":
sudo airodump-ng wlan0mon --essid "LAB-SECURE" -w baseline --output-format csv
#    >1 BSSID for your SSID, or a weaker AKM/PMF than baseline = investigate.

# B) Deauth-storm watch (counts type/subtype 0x0c = deauth per 10s window):
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'

# C) Rogue-SSID sweep across bands (survey both 2.4 and 5 if the adapter supports it):
sudo airodump-ng wlan0mon --band abg

# D) Diff live BSSID/AKM/PMF set against the baseline; alert on ANY new BSSID or weaker pairing.
```

### 8.4 Commercial WIPS (name-only, for context)

Cisco (CleanAir/aWIPS + DNA Center), Aruba (RFProtect), and Ekahau/AirMagnet do containment
(auto-deauth of classified rogues — note: *using* containment deauth is itself regulated; many
orgs run detect-only). For a lab, Kismet + nzyme cover the detection surface.

---

## 9. Monitoring & operations — make detection continuous

```bash
# 1) Standing capture to disk for forensics (rotate files, cap size):
sudo dumpcap -i wlan0mon -b filesize:102400 -b files:20 -w /var/log/wifi/cap.pcapng

# 2) Periodic control audit (cron): re-verify SAE+PMF+no-WPS on your own BSS daily.
#    Fail the check if AKM shows PSK on a WPA3-only net, MFPR=0, or wash lists your BSSID.

# 3) Log sources to watch:
#    - hostapd log: AP-STA-CONNECTED/DISCONNECTED bursts (deauth churn), SAE commit failures
#      (online guessing), MFP SA-Query timeouts.
#    - RADIUS log: Access-Reject spikes (credential stuffing / rogue supplicant).
#    - Kismet/nzyme alert stream → forward to your SIEM/Graylog.

# 4) RF survey / rogue sweep on a schedule (walk the space, log all BSSIDs, diff to baseline).
```

**What "normal" looks like (baseline these so anomalies pop):** one BSSID per SSID per band,
stable channel, stable RSSI band, AKM=SAE (or your intended set), MFPR=1, near-zero broadcast
deauth. Any deviation is your alert.

---

## 10. Attack → defense cross-reference (the whole toolkit, closed)

| Attack (sibling file) | What closes it | Verify |
|---|---|---|
| 4-way handshake offline crack | WPA3-SAE / ≥20-char random PSK | AKM=SAE; passphrase entropy audit |
| PMKID attack (`pmkid.md`) | WPA3-SAE / disable PMKID caching / patched AP | `hcxdumptool` against own AP yields no PMKID |
| Deauth/disassoc DoS (`deauth-dos.md`) | **PMF required** (`ieee80211w=2`) | deauth test leaves client associated |
| KRACK (`krack.md`) | **Patch client & AP**; EAPOL retransmit fix | driver/firmware version ≥ fixed |
| Kr00k (`kr00k-fragattacks.md`) | **Patch** Broadcom/Cypress/etc. firmware | chipset firmware ≥ CVE-2019-15126 fix |
| FragAttacks (`kr00k-fragattacks.md`) | **Patch**; WPA3; discard mixed-key frags | driver ≥ 2021 FragAttacks fixes |
| Dragonblood (`wpa3-sae-dragonblood.md`) | **H2E** (`sae_pwe=1`), patched hostapd ≥2.8/2.11, avoid weak groups | `sae_pwe=1`; version check |
| Evil-twin / downgrade (`evil-twin-detection.md`) | **WPA3-only + PMF**; SAE-PK; 802.1X cert pinning | Kismet APSPOOF; baseline diff |
| KARMA/MANA (`karma-mana.md`) | Disable auto-join to open nets; 802.1X cert validation; PMF | client probe policy; WIDS |
| WPS PIN / Pixie-Dust (`wps-*.md`) | **Disable WPS** | `wash` shows nothing for your BSSID |
| Enterprise EAP relay (`wpa-enterprise-eap.md`, `mschapv2-cracking.md`) | **EAP-TLS** or pinned-CA PEAP/TTLS; strong creds; EAP-PWD | client profile locks CA + server name |

---

## 11. Decision order — the hardening runbook (do it top to bottom)

1. **Inventory & baseline.** `airodump-ng --essid` + `wash` to record your BSSIDs, AKM, PMF,
   WPS state, channels, RSSI. This is both your hardening to-do list and your WIDS baseline.
2. **Patch everything.** AP firmware + every client driver/OS. This alone closes KRACK, Kr00k,
   FragAttacks, and the Dragonblood side-channels. Record fixed versions.
3. **Go WPA3-only + PMF required** (`wpa_key_mgmt=SAE`, `ieee80211w=2`, `sae_pwe=1`). If legacy
   clients block this, move them to their own soon-to-die VLAN'd SSID, not your main one.
4. **Kill WPS.** Re-verify with `wash` after.
5. **Set a real passphrase** (≥20 random / 6 Diceware) or deploy **802.1X with pinned-CA client
   profiles**. Consider per-device PSKs.
6. **Segment:** guest/IoT VLANs, client isolation, management-plane isolation, wired-side DHCP
   snooping / DAI.
7. **Stand up the sensor:** Kismet (+ nzyme) with APSPOOF/DEAUTHFLOOD/CHANCHANGE alerts, feeding
   a log store.
8. **Automate the audit:** daily re-check of steps 3–4 against the baseline; alert on drift.
9. **Re-test from the attacker side** (authorized): run the sibling-file attacks against your
   own hardened net and confirm each one now **fails or alerts**. That's your proof the controls
   work.

---

## 12. Gotchas & pitfalls (where hardening silently fails)

- **"WPA3 enabled" but still in transition mode.** If beacons show *both* AKM=SAE and AKM=PSK,
  a downgrade/evil-twin attacks the WPA2 side. Check with tshark; go WPA3-**only**.
- **PMF "optional" ≠ protected.** `ieee80211w=1` protects only PMF-capable clients; a legacy
  client is still deauth-able. Required (`=2`) is the control; optional is a stepping stone.
- **`ieee80211w=2` kicks non-capable devices.** Old IoT/printers may drop. Stage via `=1`, find
  the stragglers in hostapd logs, replace/segment them, then enforce `=2`.
- **WPS checkbox lies / returns after reset.** Always confirm with `wash`, and re-check after
  firmware upgrades and factory resets.
- **Strong PSK, shared everywhere.** Reuse across SSIDs/sites means one capture breaks all.
  Per-device PSK or 802.1X fixes the revocation problem a shared PSK can't.
- **802.1X without client cert validation.** The single most common enterprise hole — the whole
  point of the TLS tunnel is lost if the client trusts any cert. Lock it via MDM/GPO, not the
  user prompt.
- **TKIP anywhere.** `rsn_pairwise=CCMP` only. TKIP is broken and also forces slower rates.
- **H&P left on (`sae_pwe=0`).** Re-opens the Dragonblood timing/cache side-channel. Use `=1`
  (H2E) where all clients support it; `=2` only for mixed fleets.
- **Monitor-mode adapter can't do PMF test both bands.** The RTL8188EUS is **2.4 GHz only** —
  your 5/6 GHz BSS needs a dual-band monitor adapter to baseline/WIDS properly
  (`adapters-drivers-monitor.md`).
- **Containment deauth is regulated.** Active WIPS "rogue containment" transmits deauth; in many
  jurisdictions that's restricted even on your own premises for non-owned devices. Prefer
  detect-only unless you know the rules apply to you.
- **6 GHz forces H2E and PMF.** That's good — but legacy configs copied from 2.4 GHz may be
  invalid on 6 GHz; let the band enforce the modern defaults rather than fighting them.

---

## 13. Pro tips (speed & signal)

- **Baseline once, diff forever.** The cheapest WIDS is a known-good `airodump` CSV of your
  BSSIDs/AKM/PMF; a cron job that diffs live-vs-baseline and alerts on any new BSSID or weaker
  pairing catches evil-twin, downgrade, and rogue-AP in one check.
- **Prove, don't assume.** For every control, there's a one-liner that proves it on the air
  (tshark AKM/MFPR bits; `wash` for WPS; a deauth-test for PMF). Put those in the daily audit.
- **Use the attacker's own tools as your verifier.** `hcxdumptool` that yields no PMKID,
  `aireplay-ng --deauth` that doesn't drop the client, `wash` that shows nothing — each is a
  green check that a control holds.
- **Segment first, then you can afford to be wrong.** Good VLAN/isolation design means a missed
  patch on one IoT device doesn't become a network compromise.
- **Watch the logs, not just the live screen.** Online SAE guessing, deauth churn, and RADIUS
  rejects all show up as log patterns long before anything "breaks."
- **WPA3-only + PMF is ~80% of the value for ~20% of the effort** — do it first, verify it, then
  layer segmentation and monitoring.

---

## 14. Quick reference — verification one-liners

```bash
# AKM + PMF of your own BSS (SAE? required?):
sudo tshark -i wlan0mon -Y 'wlan.ssid=="LAB-SECURE" && wlan.fc.type_subtype==0x08' \
  -T fields -e wlan.rsn.akms.type -e wlan.rsn.capabilities.mfpr   # akm 8=SAE, mfpr 1=required

# WPS advertised? (must be empty for your BSSID):
sudo wash -i wlan0mon | grep -i <YOUR_BSSID>

# PMF actually defeats deauth (own net control test — client should stay up):
sudo aireplay-ng --deauth 5 -a <YOUR_BSSID> -c <YOUR_CLIENT> wlan0mon

# More than one BSSID for your SSID? (evil-twin / rogue):
sudo airodump-ng wlan0mon --essid "LAB-SECURE"

# Deauth-flood rate on the air:
sudo tshark -i wlan0mon -q -z io,stat,10,'COUNT(frame)wlan.fc.type_subtype==0x0c'

# TKIP anywhere? (should be CCMP/GCMP only):
sudo tshark -i wlan0mon -Y 'wlan.ssid=="LAB-SECURE"' -T fields -e wlan.rsn.pcs.type
```

---

## Sources

Authoritative references this file is built on (canonical URLs; **not re-fetched this run** —
the workflow's shared web-search budget was exhausted before these searches executed, so
`web_used=false`. Verify exact flags against the installed version):

**Standards / alliance (primary):**
- Wi-Fi Alliance — Protected Management Frames (802.11w / PMF): https://www.wi-fi.org/node/36713
- Wi-Fi Alliance — WPA3 specification / security enhancements: https://www.wi-fi.org/discover-wi-fi/security
- IEEE 802.11-2020 — §12 (RSNA, SAE, 802.11w/MFP, BIP): https://standards.ieee.org/ieee/802.11/7028/
- IETF RFC 7664 — Dragonfly (SAE) PAKE: https://www.rfc-editor.org/rfc/rfc7664
- NIST SP 800-153 — Guidelines for Securing WLANs: https://csrc.nist.gov/pubs/sp/800/153/final
- NSA CNSA / WPA3-Enterprise 192-bit (Suite-B) guidance: https://media.defense.gov/2021/Sep/01/2002846597/-1/-1/0/CTR_SECURING_WIRELESS_DEVICES_IN_PUBLIC.PDF

**Reference implementation / config:**
- hostapd — `hostapd.conf` sample (SAE, `ieee80211w`, `sae_pwe`, `sae_require_mfp`, WPA-EAP-SUITE-B-192): https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf
- w1.fi 2019-1 — SAE side-channel advisory (H2E vs H&P, constant-time fix ≥2.8): https://w1.fi/security/2019-1/sae-side-channel-attacks.txt
- OpenWrt — Wireless encryption / `sae`, `sae-mixed`, `ieee80211w`: https://openwrt.org/docs/guide-user/network/wifi/basic
- OpenWrt — WPA3 / 802.11w notes: https://openwrt.org/docs/guide-user/network/wifi/encryption

**WIDS / WIPS / detection tooling:**
- Kismet — Wi-Fi alerts reference (APSPOOF, DEAUTHFLOOD, BCASTDISCON, CHANCHANGE, `apspoof=`/`alert=`): https://www.kismetwireless.net/docs/readme/alerts/alerts/
- Kismet — Kali tools page: https://www.kali.org/tools/kismet/
- nzyme — wireless capabilities (rogue AP, evil-twin fingerprint, deauth monitors): https://www.nzyme.org/capabilities/wireless
- nzyme — GitHub (monitor-mode sensors, architecture): https://github.com/Offensive-Wireless/nzyme
- aircrack-ng — airodump-ng man page (survey columns, `--essid`, `--band`): https://man.archlinux.org/man/airodump-ng.8.en
- reaver/wash — WPS scanner (verify WPS off): https://github.com/t6x/reaver-wps-fork-t6x
- MITRE ATT&CK — DET0379 "Detect Evil Twin Wi-Fi Access Points": https://attack.mitre.org/detectionstrategies/DET0379/

**Attack background (so the defense is grounded) + vendor hardening:**
- KRACK — official site (patch = the defense): https://www.krackattacks.com/
- Kr00k (CVE-2019-15126), ESET research: https://www.welivesecurity.com/2020/02/26/kr00k-serious-vulnerability-affected-encryption-billion-wifi-devices/
- FragAttacks — official site (Vanhoef): https://www.fragattacks.com/
- Dragonblood — official site (H2E as the defense): https://wpa3.mathyvanhoef.com/
- HackTricks — Pentesting Wi-Fi (recon/AKM/PMF/WPS signatures, defense framing): https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi
- Cisco — WPA3 deployment guide (PMF required, transition-mode caveats): https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9100ax-access-points/wpa3-dep-guide-og.html
- Aruba/HPE — WPA3-Personal design/deploy (transition-off, `sae_pwe`, H2E, 6 GHz): https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/modes/wpa3-personal/

*Framing: authorized / own-gear only. This is the defensive counterpart to the attack files in
`research/`; evil-twin coverage is detection + concept for hardening, never a credential
harvester. Compiled 2026-11-14 for the Wi-Fi Command Center knowledge base.*
