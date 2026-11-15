# KRACK — Key Reinstallation Attack (WPA/WPA2 handshakes)

> **Scope / authorization.** AUTHORIZED testing only — your own gear, a sanctioned
> CTF/lab, or OSWP study. KRACK is a **client-side protocol attack** on the 802.11
> handshakes. In this toolkit it is primarily an **interview-depth knowledge module +
> a defensive/auditing capability**: you test whether *your own* clients and APs
> reinstall keys, and you detect KRACK on a network you own. There is **no "crack the
> neighbour's Wi-Fi" use here** — KRACK does **not** recover the PSK/password and does
> **not** recover the session key. Every attack note below is paired with its DEFENSE.

---

## 0. TL;DR decision order (what a pro actually does)

1. **Frame it correctly.** KRACK is not a password attack. It answers: *"is my fleet
   patched, and could an on-path attacker decrypt/replay client traffic even with a
   strong password?"* If the goal is the PSK, that is handshake-capture + hashcat — a
   different module.
2. **Patch-state check, not an attack.** Use Vanhoef's **official test scripts**
   (`vanhoefm/krackattacks-scripts`) to get a yes/no per device. They are explicitly
   *test* tools, not turnkey decrypt tools, and require your own network credentials.
3. **Client test first** (`krack-test-client.py`) — the 4-way-handshake reinstall is
   the headline case and the one most likely to be "catastrophic" (all-zero key on
   Linux/Android). **AP/FT test** (`krack-ft-test.py`) second — the 802.11r case is
   AP-side and the *easiest* to reproduce because it needs no MitM.
4. **Confirm on-air** with an independent monitor-mode capture (IV/PN reuse in
   Wireshark), because packet loss makes the scripts' verdicts flaky.
5. **Remediate on BOTH ends**, patch the client (the important side), enable PMF,
   plan WPA3, and treat the L2 as hostile (TLS/VPN everywhere).
6. **Re-test after patching** — the 2018 follow-up bypassed several first-round
   patches. Trust the behaviour, not the version string.

---

## 1. Concept (brief)

KRACK (Vanhoef & Piessens, **CCS 2017**, "Key Reinstallation Attacks: Forcing Nonce
Reuse in WPA2") breaks WPA1/WPA2 by abusing the **4-way handshake** and several
related handshakes. The flaw is in the **802.11 standard itself**, so *every* correct
WPA2 implementation was affected to some degree.

The one-sentence core:

> **An attacker tricks a victim into reinstalling an already-in-use key. Reinstalling a
> key resets the associated nonce (TX packet number / IV) and the receive replay
> counter to their initial values, so the victim reuses keystream.**

WPA2's data ciphers (CCMP/AES, TKIP, GCMP) are stream-cipher-like: they XOR plaintext
with a keystream derived from `key || nonce`. The nonce **must never repeat** under the
same key. KRACK forces exactly that nonce reuse. From krackattacks.com: *"when the
victim reinstalls the key, associated parameters such as the incremental transmit packet
number (nonce) and receive replay counter are reset to their initial value."* Result:
the attacker recovers keystream → **decrypt, replay, and (depending on cipher) forge**.

Critically, the key *material* is never broken. The site is explicit: *"our attacks do
not recover the password of the Wi-Fi network. They also do not recover (any parts of)
the fresh encryption key that is negotiated during the 4-way handshake."*

---

## 2. Mechanism — how the 4-way handshake is abused

### 2.1 Normal 4-way handshake (recap)

Both sides already share the **PMK** (from the PSK, or from 802.1X/EAP). The handshake
proves mutual possession of the PMK and installs the session keys.

```
AP (authenticator)                         Client (supplicant)
  --- Msg1: ANonce --------------------->          (client picks SNonce,
                                                    derives PTK = PRF(PMK, ANonce, SNonce, MACs))
  <-- Msg2: SNonce + MIC ----------------
  --- Msg3: GTK + MIC -------------------->        install PTK (TK) + GTK here, send Msg4
  <-- Msg4: ACK + MIC -------------------          AP installs PTK
```

- **PTK** = Pairwise Transient Key → its **TK** (Temporal Key) encrypts unicast.
- **GTK** = Group Temporal Key → encrypts broadcast/multicast, delivered inside Msg3.
- The client **installs the TK after receiving Msg3** and then sends Msg4.

### 2.2 The reinstallation trigger

Msg4 can be lost on a real network, so the AP **retransmits Msg3** if it does not
receive Msg4 (krackattacks.com: *"the access point will retransmit message 3 if it did
not receive an appropriate response as acknowledgment… an attacker can thus force nonce
reuse by collecting and replaying retransmissions of message 3 of the 4-way
handshake"*). The standard requires the client to accept a retransmitted Msg3 and
re-send Msg4. **The bug:** on each Msg3 it accepts, the client **re-installs the same
TK**, which **resets the outgoing nonce (TX PN) and the RX replay counter**.

Attack sequence (attacker sits in a **channel-based MitM** position, see 2.4):

1. Let the client complete the handshake and **install the TK** (now using some nonce
   counter value).
2. **Block / withhold Msg4** from reaching the AP so the AP retransmits Msg3.
3. Forward the **retransmitted Msg3** to the client (in later variants it is encrypted
   under the just-installed key; see 2.5).
4. The client **reinstalls the same TK** → **nonce + replay counter reset**.
5. The client now **re-encrypts future frames with nonce values it already used** →
   **keystream reuse**. The attacker who captured the earlier ciphertext at those
   nonces XORs to recover keystream/plaintext, and can **replay** old frames (replay
   counter was reset, so they are accepted again).

The suggested protocol fix (krackattacks.com): *"not reinstall an already-in-use key…
should only be installed and used once"* — i.e. still reply with a new Msg4, but do not
reset key state on a retransmitted Msg3.

### 2.3 The all-zero-key variant (Linux / Android — the severe one)

`wpa_supplicant` (the Linux/Android Wi-Fi client) has an extra implementation bug. To
comply with the standard it **clears the TK from memory** after installing it. If it
then receives a **retransmitted Msg3**, it reinstalls the key — but the key in memory is
now **all-zeros**. From krackattacks.com: *"the client will install an all-zero
encryption key instead of reinstalling the real key."* The attacker then **trivially
decrypts everything and can inject/forge arbitrary frames** (the key is known zeros).

- **Affected:** `wpa_supplicant` **2.4 and 2.5** "end up configuring an all-zero TK"
  (per the maintainer's oss-security advisory). **2.6** is *also* vulnerable via a
  *different* 4-way-handshake message sequence (a forged/retransmitted Msg1 reusing the
  original ANonce) that likewise installs an all-zero TK — this is the `--tptk` path.
- **Platform reach:** Android **6.0+** ships affected `wpa_supplicant`; krackattacks.com
  cited **~50%** of Android devices as vulnerable at disclosure (the CCS paper's measured
  figure was ~31% — different snapshots/wording). This is why KRACK was reported as
  "especially catastrophic" against Linux and Android. macOS and OpenBSD were also
  affected and "significantly easier" to attack than the paper described.

### 2.4 Getting the MitM position (prerequisite for the 4-way case)

KRACK against the 4-way/group handshakes needs a **channel-based man-in-the-middle**
between the real client and real AP — a plain rogue AP on the same channel is **not**
enough, because the attacker must see and selectively **block/forward/replay the real
encrypted frames**. krackattacks.com: *"this MitM position does **not** enable the
attacker to decrypt packets"* — it only lets them *"reliably delay, block, or replay
encrypted packets,"* which is what triggers the reinstall.

Standard technique (SemFio/Vanhoef): run a fake AP with **two radios** — *"one radio
interface to talk to the AP on channel x"* and *"one radio interface to talk to the
client on channel y"* — spoofing the real AP's MAC toward the client, placed close to
the victim. In practice the client is herded to the rogue channel with a **Channel
Switch Announcement (CSA)** so the attacker relays frames between channels and can drop
Msg4 at will.

> **DEFENSE note (MitM):** 802.11w/PMF makes the mgmt-frame side of the setup
> (deauth-based herding, forged mgmt frames) harder, but CSA-based channel MitM and the
> data-plane reinstall are **not** fully stopped by PMF alone. See §8.

### 2.5 The follow-up attack (2018) — why "disable retransmission" wasn't enough

Vanhoef's follow-up (`krackattacks.com/followup.html`; the "generalized" KU Leuven
paper) showed:

- Abuse **802.11 power-save**: send a power-save frame so the AP **buffers** the
  retransmitted Msg3 and sends it later — **encrypted under the new session key** —
  removing the hard race condition of the original attack.
- **Unpatched Android, macOS, and OpenBSD** accepted the **encrypted** retransmitted
  Msg3 and reinstalled the key.
- The **official 802.11 countermeasure could be bypassed**; *"preventing key
  reinstallations is harder than expected."* Several first-round vendor patches were
  incomplete. **Lesson: audit the patch behaviour, don't trust the version string.**

---

## 3. Cipher impact — what nonce reuse actually buys

| Cipher | On nonce reuse | Forge direction |
|---|---|---|
| **AES-CCMP** (standard WPA2) | **Decrypt + replay**. Paper does **not** demo practical arbitrary forgery. | (limited) |
| **TKIP** (legacy WPA) | Decrypt + replay; recovering the **Michael MIC key** enables **forgery** | one direction |
| **GCMP** (WPA2/802.11ad "WiGig") | Worst case: nonce reuse leaks the **GHASH authentication key** → forge | **both directions** |
| **wpa_supplicant 2.4–2.6 all-zero key** | Full decrypt **and** inject (key is known zeros) | both directions |

Direction of the two main cases (krackattacks.com): attacking the **4-way handshake**
lets you decrypt/forge packets **sent by the client**; attacking the **FT handshake**
affects packets **sent toward the client**.

What KRACK lets an attacker do once keystream/plaintext is recovered:
- **Decrypt** frames (read cleartext HTTP, DNS, unencrypted app traffic).
- **Replay** frames the client/AP already sent (replay counter was reset).
- **Forge/inject** in TKIP/GCMP/all-zero cases → e.g. inject into a TCP stream (the site
  notes decrypting a TCP SYN exposes sequence numbers for hijacking), poison DNS, or
  attempt an SSLstrip-style downgrade **if** the upper layer is weak.

What KRACK **cannot** do:
- **Recover the Wi-Fi password / PSK.** (That is handshake-capture + hashcat — a
  separate module. Changing the Wi-Fi password does **not** mitigate KRACK.)
- Recover the freshly-negotiated **PTK/PMK** key material.
- Break properly-deployed **end-to-end TLS/HTTPS/VPN** — only the Wi-Fi layer.

---

## 4. The CVE family (CVE-2017-13077 … 13088)

One attack, many handshakes. Memorize the mapping — classic OSWP/interview fodder. This
clean per-CVE table follows **krackattacks.com** and **CERT-EU 2017-021 / CERT-CC**:

| CVE | Reinstalled key | Handshake | Side |
|---|---|---|---|
| **CVE-2017-13077** | **PTK-TK** (pairwise) | 4-way handshake | client |
| **CVE-2017-13078** | **GTK** (group) | 4-way handshake | client |
| **CVE-2017-13079** | **IGTK** (integrity group) | 4-way handshake | client |
| **CVE-2017-13080** | **GTK** | Group Key handshake | client |
| **CVE-2017-13081** | **IGTK** | Group Key handshake | client |
| **CVE-2017-13082** | **PTK-TK** | **FT / 802.11r** Reassociation | **AP** (no MitM, no Msg4 race) |
| CVE-2017-13084 | STK | PeerKey handshake | (marked **N/A** by maintainer — PeerKey install "does not work") |
| CVE-2017-13086 | TK | TDLS PeerKey handshake | client |
| CVE-2017-13087 | GTK | WNM Sleep Mode response | client |
| CVE-2017-13088 | IGTK | WNM Sleep Mode response | client |

(13083 and 13085 are not assigned/used.)

> **Nuance for interviews:** the clean one-CVE-per-subcase table above is the
> *CERT-EU/krackattacks.com* presentation. The **wpa_supplicant/hostapd maintainer's own
> oss-security advisory (Jouni Malinen)** does **not** map each CVE individually — it
> **groups** 13078/13079/13080/13081/13087/13088 under *"wpa_supplicant and GTK/IGTK
> rekeying"* (all affecting **all wpa_supplicant versions**), ties 13077 to older
> (≤ 2.3) pairwise-key reinstallation, and calls out **13082 as the hostapd/AP FT**
> case (*"hostapd v0.7.2 and newer with FT enabled"*). If someone pushes back on your
> table, that grouping is why.

**CVE-2017-13082 (FT / 802.11r) is special** and the lab favourite: the **AP** reinstalls
the PTK when it accepts a **retransmitted FT Reassociation Request**. It is **AP-side**,
needs **no man-in-the-middle and no blocked Msg4** — the attacker just **replays** the
Reassociation Request (the AP can't distinguish a replay from legit traffic). This is
exactly what `krack-ft-test.py` exercises.

**Bonus AP-side issue (no CVE):** the maintainer also fixed an **hostapd PTK-rekeying
bug** where *"the ANonce value does not get updated"* on rekey — applies to **all
hostapd versions**; fix commit "**Fix PTK rekeying to generate a new ANonce**."

---

## 5. COMMAND-FIRST — testing your own gear (official Vanhoef scripts)

These are **test/detection** tools (they confirm whether a device reinstalls keys), not
turnkey decrypt tools. The README states plainly they are *"not attack scripts"* and
require valid credentials for the test network. Run only against **devices you own**.

### 5.1 Build the toolkit (Kali)

```bash
# Dependencies (from the README, tested on Kali)
sudo apt update
sudo apt install -y libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev \
    net-tools git sysfsutils python3-venv iw

# Clone + build the modified hostapd and the python venv
git clone https://github.com/vanhoefm/krackattacks-scripts.git
cd krackattacks-scripts/krackattack
./build.sh            # builds the patched hostapd used as the test AP
./pysetup.sh          # creates ./venv (scapy etc., per requirements.txt)
```

### 5.2 Disable hardware crypto (critical gotcha)

The test AP must see raw EAPOL/data frames. If the card does crypto in hardware, the
test silently misbehaves.

```bash
cd krackattack
sudo ./disable-hwcrypto.sh    # writes /etc/modprobe.d/nohwcrypt.conf
sudo reboot                   # reboot so the driver reloads without hwcrypto
# verify:  systool -vm <module>      (README example module: ath9k_htc)
# undo:    sudo ./reenable-hwcrypto.sh   (or delete /etc/modprobe.d/nohwcrypt.conf)
```

### 5.3 Per-session setup

```bash
# Turn OFF Wi-Fi in the network manager first, then:
sudo rfkill unblock wifi
cd krackattacks-scripts/krackattack
sudo su
source venv/bin/activate
# Edit hostapd/hostapd.conf -> set  interface=<your-wifi-iface>  (e.g. wlan0)
```

The **client under test** connects to SSID **`testnetwork`**, password **`abcdefgh`**,
and must pull a **DHCP** lease (some tests wait for it). Optionally ping
`192.168.100.254` to generate unicast traffic so IV reuse is observable.

> **Tested adapters (README):** Intel Dual Band Wireless-AC **7260** and TP-Link
> **TL-WN722N v1**. In this toolkit the **RTL8188EUS (2.4 GHz)** serves as the test-AP
> radio for client tests. **5 GHz is not officially supported** (injection/beaconing
> restrictions); check `iw list` for allowed channels. If a client has multiple radios,
> test with several NICs; a spare NIC in monitor mode confirms IVs independently.

### 5.4 Client tests — run in this ORDER (decision order)

```bash
# 1) Baseline: does the client wrongly accept replayed broadcast frames?
#    MUST be addressed first, or the --group result is a false positive.
./krack-test-client.py --replay-broadcast

# 2) Group-key install in the group-key handshake (RSC check; see paper sec 6.4)
./krack-test-client.py --group --gtkinit

# 3) Group-key REINSTALL in the group-key handshake  (CVE-2017-13080)
./krack-test-client.py --group

# 4) THE MAIN TEST: 4-way-handshake PTK/TK reinstall (CVE-2017-13077 / 13078)
./krack-test-client.py
#    In another shell generate unicast traffic:  ping 192.168.100.254

# 5) Variant: inject a forged Msg1 first (hits the 2.6 all-zero-key / TPTK path)
./krack-test-client.py --tptk
# 6) Same, but the forged Msg1 uses a RANDOM ANonce
./krack-test-client.py --tptk-rand
# 7) Retransmit Msg3/4 with new group keys + high replay counters
./krack-test-client.py --gtkinit

#  --debug for verbose output; unknown flags (e.g. -dd -K) pass through to hostapd
```

**Reading client output:**
- A **"vulnerable"** verdict on test 4 (or `--group`) = the device reinstalled the key.
  **Test 4 is the single most important check.**
- Tests 1 and 3 can mislead if the client accepts replayed broadcasts — resolve test 1
  first.
- Test 7 prints something like **"received a new message 4"** → the client *does* accept
  a retransmitted Msg3/4, so the test is valid for that device; it is then vulnerable if
  it afterwards accepts broadcast frames with a **lower replay counter**. (A **Dec 2024**
  README fix made test 7's output trustworthy when you follow the updated steps.) Some
  clients never accept a retransmitted Msg3 and simply **cannot be tested** this way
  (not the same as "patched").
- **Run several times** in a **low-noise RF environment**; packet loss ⇒ unreliable
  verdicts.

### 5.5 AP test — FT / 802.11r (CVE-2017-13082)

Tests an **access point**; needs an AP that supports **802.11r fast roaming** and a
**second AP** of the same ESS to roam to.

```bash
# network.conf
cat > network.conf <<'EOF'
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="testnet"
    key_mgmt=FT-PSK
    psk="password"
}
EOF

# (optional) confirm the AP actually supports FT; if this fails the AP likely isn't affected
sudo wpa_supplicant -D nl80211 -i wlan0 -c network.conf

# Run the test wrapper (it replays the FT Reassociation Request)
sudo su; source venv/bin/activate
./krack-ft-test.py wpa_supplicant -D nl80211 -i wlan0 -c network.conf

# In wpa_cli, associate then ROAM to the 2nd AP to trigger the FT handshake
wpa_cli -i wlan0
> status
> scan_results
> roam <bssid-of-second-AP>

# Generate traffic so IV reuse is visible
arping -I wlan0 192.168.1.10
```

**Reading AP output:**
- **VULNERABLE:** `IV reuse detected (IV=X, seq=Y). AP is vulnerable!` — the same IV
  repeats after each replayed Reassociation Request.
- **PATCHED:** IVs keep **incrementing** and are never reused despite the replays.
- Confirm with an independent **monitor-mode capture** (see §5.6). The README itself
  recommends checking traces to confirm the replay/IV reuse manually.

### 5.6 Independent confirmation in monitor mode

```bash
sudo airmon-ng start wlan1
sudo airodump-ng -c <chan> --bssid <AP-MAC> -w krack_verify wlan1mon
# Then inspect in Wireshark.
```

Wireshark display filters that help:
- `eapol` — isolate the 4-way handshake; look for **duplicate Msg3**.
- `wlan.rsn.ie` / `wlan.ccmp.extiv` — watch the CCMP IV/PN; a **reset or repeat** after a
  retransmitted Msg3 is the KRACK signature.
- `wlan.fc.type_subtype==0x28` (QoS data) — spot repeated CCMP PN values after the
  handshake = nonce reuse.

---

## 6. Detection / blue-team tooling (defensive, run on your own net)

There are **no clean, unique frame-level signatures** for KRACK — the honest position
(SemFio, Vanhoef). The two observable hallmarks are a **retransmitted EAPOL Msg3** and
**IV/PN reuse** on the monitored channel, both of which also occur benignly. So
detection is "investigate," not "confirmed."

**KRACK Detector** (`securingsam/krackdetector`) — a WIDS-style script for a Raspberry
Pi / Linux box in monitor mode near your AP:

- **Detects:** a **duplicate / retransmitted Message 3** of the 4-way handshake on the
  monitored channel.
- **Responds:** on detection it **deauthenticates/disassociates** the targeted client to
  break the attack before the key reinstalls.
- **Typical invocation** (confirm flags with `--help` on your checkout):
  ```bash
  sudo python krackdetector.py -i wlan0mon
  #   -d  deauth the client   -z  disassociate   -n <ssid> / -c <channel>  scope
  ```
- **Known limitation:** Msg3 **is legitimately retransmitted** when Msg4 is lost on a
  noisy network → **false positives**. Patch clients; don't rely on this as a control.

Other blue-team signals: **CSA frames** herding clients to odd channels, a **cloned
BSSID on a second channel**, unexpected **deauth/CSA bursts**. SemFio's bottom line is
the general one — *"use WIPS (Wireless Intrusion Prevention System) to detect the MiTM
attacks."* Treat WIDS/WIPS as an **alerting layer, not a fix**.

---

## 7. Gotchas & pitfalls (field notes)

- **It does NOT get the password.** Wrong tool for the PSK — that's handshake capture +
  hashcat. Don't conflate modules. Changing the Wi-Fi password does **not** mitigate it.
- **Hardware crypto must be OFF** for the test AP, or results are silently wrong
  (`disable-hwcrypto.sh` + reboot; verify with `systool -vm <module>`).
- **`--replay-broadcast` must be clean before trusting `--group`.** A client that always
  accepts replayed broadcasts makes the group-key test report a false "vulnerable."
- **Some clients can't be tested** — if a device never accepts a retransmitted Msg3,
  `krack-test-client.py` can't exercise the path.
- **Packet loss ruins verdicts.** Low-noise RF, close range, repeat runs.
- **Patched ≠ immune (2018).** First-round patches were bypassable; the power-save
  follow-up beat several. **Re-test after patching.**
- **FT test needs real 802.11r** + a **second AP** to roam to, or it just fails.
- **MitM is the hard part.** The scripts give a verdict without a full MitM; reproducing
  the *actual decrypt* needs the channel-based CSA MitM — easy to get wrong, lab-only on
  your own kit.
- **Legality:** CSA MitM, deauth, and rogue-AP herding are **active** techniques — only
  for allowlisted, owned/authorized gear. Gate them behind the toolkit's allowlist.

---

## 8. DEFENSE (pair every attack note with this)

KRACK is fixed by **implementation patches on BOTH ends**, not by one AP setting.
krackattacks.com: *"both the client and AP must be patched to defend against all
attacks"* — and patches are *"backwards-compatible."*

1. **Patch the client AND the AP.** The client fix is the important one (KRACK is
   client-centric): don't reset nonce/replay state on reinstall, and install each
   freshly-negotiated key **exactly once**. Maintainer fixes (w1.fi/security/2017-1/):
   - `wpa_supplicant`: **"Prevent reinstallation of an already in-use group key,"**
     **"Prevent installation of an all-zero TK"** (2.6+ snapshot), plus WNM/TDLS/FT
     hardening (*"Reject TPK-TK reconfiguration,"* *"FT: Do not allow multiple
     Reassociation Response frames"*).
   - `hostapd`: **"Avoid key reinstallation in FT handshake"** (CVE-2017-13082) and
     **"Fix PTK rekeying to generate a new ANonce."**
   - **Long term: update to hostapd/wpa_supplicant 2.7+.**
   - OS patch levels: Android 2017-11-06 security patch, iOS 11.1, macOS 10.13.1,
     Windows Oct 2017 KBs, ChromeOS 62, OpenBSD/FreeBSD updates.
2. **AP-side interim mitigations** (krackattacks.com, for when clients are unpatched) —
   **mitigations, not cures:**
   - **Disable retransmission of the EAPOL handshake messages** (hostapd/Cisco support
     this). **Caveat:** can break if **TDLS** is used, and flaky links may fail to
     (re)connect; SemFio suggests deauth-to-force-reconnect to limit false positives.
   - **Disable client/repeater functionality** on the AP.
   - **Disable 802.11r (FT)** in runtime config to remove the CVE-2017-13082 path.
3. **802.11w / PMF (Protected Management Frames):** raises the bar for the mgmt-frame
   side of the MitM setup and protects mgmt/group handshakes, but **does not by itself
   stop** the data-plane 4-way reinstall (some PMF-related frames stay unprotected, e.g.
   pre-auth). Enable `capable`/`required` where clients support it, **but patch anyway**.
   PMF is **mandatory** under WPA3/Enhanced-Open and not user-configurable there.
4. **Move to WPA3-SAE.** WPA3 **mandates PMF** and SAE is not vulnerable to the 4-way
   reinstallation. **But WPA3 *transition mode* makes PMF optional and allows WPA2
   fallback → downgrade risk.** Prefer **WPA3-only / PMF-required** where feasible.
5. **Defense-in-depth above L2:** enforce **HTTPS/HSTS**, VPN, SSH — KRACK can't break
   properly-deployed TLS. Assume the Wi-Fi layer is hostile.
6. **Unpatchable IoT:** **segment** onto an isolated VLAN/SSID, restrict east-west
   traffic, monitor.
7. **Monitor** for the on-air signatures (duplicate Msg3, rogue CSA, cloned BSSID on a
   second channel) with a WIDS / KRACK Detector — alerting layer, not a fix.

---

## 9. Where KRACK sits in the pro workflow

- **Audit / interview topic first.** For a Wi-Fi assessment the usual chain is
  recon → handshake capture → offline hashcat (for the PSK). KRACK is the answer to
  *"is my fleet patched, and can an on-path attacker decrypt client traffic even with a
  good password?"*
- **Use it to:** (a) prove a specific client/AP reinstalls keys with the official test
  scripts; (b) demonstrate the risk of legacy `wpa_supplicant`/Android; (c) justify
  WPA3/PMF rollout and client patching; (d) stand up KRACK Detector as a monitoring
  control.
- **Don't use it to:** "break into" Wi-Fi — it yields no password and only works from a
  live on-path MitM against an **unpatched** client.

---

## Sources (URLs actually read/used for this reference)

- KRACK official site — mechanism, cipher impact, affected platforms, mitigations,
  "does not recover password/key": https://www.krackattacks.com/
- Follow-up attack (power-save buffering; official defense bypassed): https://www.krackattacks.com/followup.html
- Official test scripts + README (build.sh, `krack-test-client.py`, `krack-ft-test.py`,
  disable-hwcrypto, tested adapters, test-7 Dec-2024 fix): https://github.com/vanhoefm/krackattacks-scripts
- Maintainer advisory (Jouni Malinen, oss-security) — CVE grouping, all-zero TK on
  2.4/2.5/2.6, FT/hostapd case, exact patch titles: https://www.openwall.com/lists/oss-security/2017/10/16/2
- Upstream patches (w1.fi security advisory 2017-1): https://w1.fi/security/2017-1/
- Vanhoef & Piessens, "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2," CCS
  2017 (paper PDF): https://papers.mathyvanhoef.com/ccs2017.pdf
- 34C3 talk slides, "Kracking WPA2 by Forcing Nonce Reuse": https://bork.cs.fau.de/CCC/34C3/slides-pdf/34c3-9273-kracking_wpa2_by_forcing_nonce_reuse.pdf
- CERT-EU Security Advisory 2017-021 (CVE list, affected handshakes): https://cert.europa.eu/publications/security-advisories/2017-021/pdf
- CERT/CC Vulnerability Note (vendor status; KRACK multi-CVE): https://www.kb.cert.org/vuls/id/CHEU-AQNMWZ
- Cisco Meraki 802.11r / CVE-2017-13082 FAQ (AP-side FT, safe-to-use-after-patch): https://documentation.meraki.com/General_Administration/Support/802.11r_Vulnerability_(CVE%3A_2017-13082)_FAQ
- Kudelski Security advisory (impact summary, CVE breakdown): https://research.kudelskisecurity.com/2017/10/16/key-reinstallation-attacks-krack-affecting-wpa-protocol-advisory/
- SemFio Networks, "KRACK — Is it the end of WPA2?" (channel MitM setup, patch/WIPS
  guidance): https://semfionetworks.com/blog/krack-is-it-the-end-of-wpa2
- HPE Aruba — Protected Management Frames (PMF) docs (PMF behaviour, WPA3 mandatory
  PMF): https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/features/pmf/
- SecurityWeek, "Researchers KRACK Wi-Fi Again, More Efficiently" (2018 follow-up
  coverage): https://www.securityweek.com/researchers-krack-wi-fi-again-more-efficiently-time/
