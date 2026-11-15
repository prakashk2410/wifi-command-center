# Adapters, Chipsets & Monitor-Mode Drivers

> **Command Center knowledge base — Topic: Adapters, chipsets & monitor-mode drivers**
> Scope: **AUTHORIZED** Wi-Fi security testing only — your own gear, sanctioned competitions, CTF ranges, OSWP study. Every capture/injection action is gated by the project allowlist (your own BSSIDs/SSIDs). Reconnaissance that is passive (monitor-mode capture of frames in the air you are authorized to test) is low-risk; anything that *transmits* (injection, deauth, probe floods) touches other people's RF and is only run against targets you own or are contracted to test. **Evil-twin material in this KB is detection + concept only — never build a credential harvester.**
>
> Platform assumption: **Mac host + Kali Linux (VM or bare metal) + TP-Link RTL8188EUS (2.4 GHz) adapter**, with other adapters (Alfa AR9271 / MT7612U / RTL8812AU) covered because adapter choice is the single biggest determinant of whether the rest of the toolkit works at all.

---

## 0. TL;DR — the one-screen version

```
# 1. Identify the chipset BEFORE trusting any label
lsusb                         # bus list + VID:PID
lsusb -vv -d 0bda:            # full descriptor for a Realtek device (example)
sudo dmesg | grep -iE 'usb|rtl|ath|mt7|80211'   # which driver bound, firmware load, errors

# 2. Confirm the kernel bound a driver and the netdev exists
iw dev                        # lists wireless interfaces (wlan0, wlan1...)
iw list | grep -A8 'Supported interface modes'   # does it advertise "monitor"?

# 3. Clear interferers, go monitor
sudo airmon-ng check kill     # kill NetworkManager/wpa_supplicant that steal the card
sudo airmon-ng start wlan0    # creates wlan0mon (or renames)
iw dev                        # verify type monitor

# 4. PROVE injection works (this is the gate, not an afterthought)
sudo aireplay-ng -9 wlan0mon  # -9 == --test
```

If `aireplay-ng -9` reports the card injecting and sees APs responding, the adapter + driver + antenna chain is good. If it does not, **stop and fix the adapter layer** — no capture/crack tool downstream will work reliably until this passes.

---

## 1. Concept (brief)

Three independent things must all be true before any WPA2/WPA3 capture or attack works:

1. **Chipset supports monitor mode** — the radio can be put into RFMON so it hands the OS *every* 802.11 frame on a channel (management, control, data) instead of only frames addressed to it after association. This is what lets you sniff beacons, probe requests, and the EAPOL 4-way handshake.
2. **Chipset + driver support injection** — the radio will *transmit* arbitrary raw 802.11 frames (deauth, (re)association, ARP replay). Monitor mode and injection are **separate capabilities**: plenty of cards sniff but cannot inject, and some drivers support injection in one mode and corrupt frames in another.
3. **A driver on your kernel actually exposes both** — the *same* chipset can be excellent or useless depending on which driver binds it (mainline `mac80211` vs vendor "staging" vs out-of-tree DKMS fork). The aircrack-ng project groups Linux drivers into: **vendor** (never supports monitor), **peer-modified vendor** (may, with caveats), **staging** (quality unknown), and **kernel/mac80211** (monitor likely; injection may or may not). ([aircrack-ng.org](https://www.aircrack-ng.org/doku.php?id=compatibility_drivers))

The practical consequence: **buy the chipset, not the product name.** Vendors silently change the chipset inside a product between hardware revisions (the TP-Link WN722N is the canonical cautionary tale — see §2). Always verify the actual chipset with `lsusb` after purchase.

---

## 2. Chipset decision matrix — the pro buy/try order

This is the order experienced operators reach for hardware, best-supported first. The theme across every community list (StationX, CellStream, aircrack-ng forum, Parrot forum): **Atheros for rock-solid 2.4 GHz injection; MediaTek mt76 for the cleanest modern dual-band; Realtek 88xxAU for cheap dual-band if you accept out-of-tree driver pain.**

| Chipset | Driver (best) | Typical adapter | Bands | Monitor | Injection | Notes |
|---|---|---|---|---|---|---|
| **Atheros AR9271** | `ath9k_htc` (in-kernel, mac80211) | Alfa **AWUS036NHA**, TP-Link WN722N **v1 only** | 2.4 only | Excellent | Excellent | The reference injection chipset. In mainline for years; needs only the `ath9k_htc` firmware blob. Most-documented, "just works" for OSWP study. |
| **Atheros AR9170** | `carl9170` (in-kernel) | older Alfa AWUS036NHR | 2.4 only | Good | Good | Mature mac80211 driver, needs `carl9170-fw` firmware. Older/slower but reliable. |
| **MediaTek MT7612U** | `mt76x2u` / `mt76` (in-kernel) | Alfa **AWUS036ACM**, AWUS036ACHM | 2.4 + 5 | Excellent | Excellent | The modern dual-band sweet spot: injection + monitor in mainline, no out-of-tree driver. Widely recommended as the cleanest dual-band option in recent Kali guides. |
| **MediaTek MT7921AU** | `mt7921u` (in-kernel, recent) | Alfa **AWUS036AXML** | 2.4 + 5 (Wi-Fi 6) | Good* | Good* | Wi-Fi 6 / 802.11ax. Needs a recent kernel (6.x). Monitor/injection support improved steadily; verify on *your* kernel. |
| **Realtek RTL8812AU / 8821AU** | aircrack-ng `rtl8812au` **or** `morrownr/8812au-20210629` DKMS; Kali pkg `realtek-rtl88xxau-dkms`; in-kernel `rtl8xxxu` on newer kernels | Alfa **AWUS036ACH** (0bda:8812), AWUS036AC | 2.4 + 5 | Good (driver-dependent) | Good (driver-dependent) | Cheap, popular, powerful — but **out-of-tree driver that breaks on kernel updates**. Pick the *right* fork (see §4.3). aircrack-ng's maintainer points users to the aircrack-ng GitHub driver for 8812AU/8814AU. |
| **Realtek RTL8814AU** | aircrack-ng `rtl8812au` / `8814au` DKMS | AWUS1900, AWUS036ACHM clones | 2.4 + 5 | Good | Good | 4x4 high-power version of the 8812AU story; same DKMS caveats. |
| **Realtek RTL8188EUS** *(your TP-Link)* | out-of-tree `aircrack-ng/rtl8188eus` DKMS **or** in-kernel `rtl8xxxu` / `r8188eu` | small TP-Link TL-WN722N **v2/v3**, Nano USB | 2.4 only | Yes, driver-dependent | Yes, with the right driver | See §4.2. The in-kernel `r8188eu`/`rtl8xxxu` monitor+injection story is inconsistent; the out-of-tree DKMS fork is the usual fix. |
| **Ralink RT3070 / RT5370 / RT5572** | `rt2800usb` (in-kernel) | older Alfa AWUS036NH, many nano dongles | 2.4 (5 on 5572) | Good | Good | Old but genuinely mac80211-native and reliable; listed across community adapter threads. |

\* = version/kernel-sensitive; **always confirm with `aireplay-ng -9` on your exact kernel.**

### The WN722N trap (memorize this)
- **WN722N v1** = Atheros **AR9271** → `ath9k_htc` → gold standard, injects out of the box.
- **WN722N v2/v3** = Realtek **RTL8188EUS** → needs the out-of-tree driver dance and historically fought monitor mode.
Two products, same name and box art, completely different chipset and workflow. This is *why* §3 (identify the silicon) comes before everything.

### Chipsets to avoid for RF testing
- **Broadcom** (most) — commonly reported as lacking both monitor mode and injection on Linux.
- **Intel PRO/Wireless / most internal Intel** — monitor mode often works for *sniffing* but injection is unreliable/absent; driver issues frequently reported. Fine for passive survey, not for an injection lab.
- **RTL8723 / RTL8188CUS / RTL8192CU** — weak/absent injection, poor monitor support.

---

## 3. Identify the actual hardware (do this first, every time)

```bash
# What is physically plugged in + its VID:PID
lsusb
# e.g.  Bus 001 Device 004: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU
#       Bus 001 Device 005: ID 0bda:f179 Realtek ... (8188EUS-family)
#       Bus 001 Device 006: ID 0cf3:9271 Qualcomm Atheros AR9271

# Full descriptor incl. the kernel module currently bound to it
lsusb -vv -d 0bda:8812 | grep -iE 'idVendor|idProduct|iProduct|Driver'

# PCIe/internal card equivalent
lspci -vv | grep -iA8 -E 'network|wireless'

# Which driver actually bound + firmware load success/failure + errors
sudo dmesg --ctime | grep -iE 'usb|rtl8|rtw|ath9k|carl9170|mt76|mt79|ieee80211|firmware'

# Does the chip advertise monitor mode AT THE DRIVER LEVEL?
iw list | sed -n '/Supported interface modes/,/Supported commands/p'
#   look for a line:  * monitor
iw dev                    # the netdev name the driver created (wlan0, wlan1, wlanx)
```

**Interpreting VID:PID (common ones):**
- `0cf3:9271` / `0bda:9271` → AR9271 → `ath9k_htc` (ideal)
- `0bda:8812`, `0bda:881a` → RTL8812AU → out-of-tree 88XXau
- `0bda:8813` → RTL8814AU
- `0bda:f179` → RTL8188EUS/FTV family
- `148f:5370`, `148f:3070` → Ralink → `rt2800usb`
- `0e8d:7612` → MediaTek MT7612U → `mt76x2u`
- `0e8d:7961` → MediaTek MT7921AU → `mt7921u`

Cross-reference unknown IDs against **WikiDevi / the Wireless Adapter Chipset Directory / linux-wireless driver list** (the resources aircrack-ng itself points to) before buying or debugging.

---

## 4. Driver install workflows (command-first)

### 4.0 Golden rule: try the in-kernel driver first
Modern kernels bind many of these chips automatically (`ath9k_htc`, `mt76x2u`, `rt2800usb`, increasingly `rtl8xxxu` for some Realtek parts). If `iw list` already shows `* monitor` and `aireplay-ng -9` passes, **install nothing** — you avoid the entire DKMS-breaks-on-kernel-update treadmill. Only reach for out-of-tree drivers when the in-kernel one is missing or fails the injection test.

Prereqs for *any* DKMS build on Kali:
```bash
sudo apt update
sudo apt install -y build-essential bc dkms git \
  linux-headers-$(uname -r) libelf-dev
# If 'linux-headers-$(uname -r)' is not found in a VM, update first:
sudo apt full-upgrade -y && sudo reboot   # then re-check uname -r matches an installed headers pkg
```
Header/kernel mismatch is the #1 cause of "`make` fails" — the headers package **must** match `uname -r` exactly.

---

### 4.1 Atheros AR9271 / AR9170 — the easy path
Usually zero install. If firmware is missing you'll see a `firmware ... failed` line in `dmesg`:
```bash
sudo apt install -y firmware-atheros        # provides htc_9271.fw / carl9170 fw
sudo modprobe -r ath9k_htc && sudo modprobe ath9k_htc
# carl9170 (AR9170):
sudo apt install -y firmware-linux-free      # carl9170 firmware
```
Then straight to §5. This is why AR9271 is the recommended starting adapter for OSWP/CTF study — the driver layer is a non-event.

---

### 4.2 RTL8188EUS (your TP-Link, 2.4 GHz)

**Step A — see what bound.** Newer kernels may bind `r8188eu` (mainline) or `rtl8xxxu`. Some setups report `rtl8xxxu` giving working monitor+injection on an 8188EUS; others fight it. Test before installing anything:
```bash
sudo dmesg | grep -iE 'r8188eu|rtl8xxxu|rtl8188'
iw list | grep -i monitor      # if present, try §5 + aireplay-ng -9 first
```

**Step B — if in-kernel fails, install the out-of-tree DKMS driver** (`aircrack-ng/rtl8188eus`, widely mirrored):
```bash
cd ~/src
git clone https://github.com/aircrack-ng/rtl8188eus.git
cd rtl8188eus
# Build + install
make
sudo make install          # installs 8188eu.ko
# OR register with DKMS so it rebuilds on kernel upgrades:
sudo dkms add .
sudo dkms build rtl8188eus/<version>
sudo dkms install rtl8188eus/<version>
```

**Step C — CRITICAL: blacklist the conflicting in-kernel module** so the old `r8188eu`/`r8188eus` does not grab the device first:
```bash
echo 'blacklist r8188eu'  | sudo tee /etc/modprobe.d/rtl8188-blacklist.conf
echo 'blacklist r8188eus' | sudo tee -a /etc/modprobe.d/rtl8188-blacklist.conf
sudo update-initramfs -u    # (Debian/Kali) rebuild initramfs so blacklist takes at boot
sudo reboot
```
Community install guides flag this blacklist step explicitly: *"Prevent loading old driver r8188eu."* Skipping it is why the wrong driver keeps binding after a reboot.

**Step D — deprecation note / long-term option.** A mirror of the aircrack-ng driver repo carries a notice that the out-of-tree **DRIVERS ARE DEPRECATED**, pointing instead to the **mac80211 `rtw88` tree (`lwfinger/rtw88`)**. For the 8188EUS specifically that mostly matters as a signal: prefer a working in-kernel/mac80211 driver when one exists, and treat the out-of-tree fork as the fallback, not the default. (Verify current repo status before relying on either — these forks and their kernel compatibility change frequently.)

---

### 4.3 RTL8812AU / 8821AU / 8814AU (Alfa AWUS036ACH, dual-band)

**Pick ONE of these — do not stack them:**

**Option 1 — Kali package (simplest, DKMS-managed):**
```bash
sudo apt update
sudo apt install -y realtek-rtl88xxau-dkms
# reboot or re-plug; check:
iw dev ; iw list | grep -i monitor
```

**Option 2 — aircrack-ng driver (maintainer's recommendation for 8812AU/8814AU):**
```bash
cd ~/src
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install        # registers with DKMS
```

**Option 3 — morrownr DKMS, but choose the RIGHT fork:**
```bash
# USE 20210629 (lists monitor mode + aircrack-ng compat + injection):
git clone https://github.com/morrownr/8812au-20210629.git
cd 8812au-20210629
sudo ./install-driver.sh      # builds via DKMS, writes /etc/modprobe.d config
# DO NOT use 8812au-20210820 for monitor work — its README states monitor mode is NOT supported.
```

**Version pinning when a new kernel breaks the build.** A frequently-cited working recipe pins an older tag known to compile on the current kernel:
```bash
git clone -b v5.6.4.2 https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au && sudo make dkms_install
```
(Reported working as recently as mid-2024 on some kernels; the "right" tag drifts with the kernel, so if `dkms build` errors, try the next older tag.)

**Monitor-mode toggle specific to these drivers.** The 88XXau DKMS drivers ship a module parameter to force monitor behavior and a `/etc/modprobe.d/` file written by the installer. If monitor mode is flaky:
```bash
cat /etc/modprobe.d/*8812*       # see what the installer set
# e.g. options 88XXau rtw_... ; some forks: options 8812au rtw_monitor_...=1
sudo modprobe -r 88XXau && sudo modprobe 88XXau
```

---

### 4.4 MediaTek MT7612U / MT7921AU — prefer in-kernel
```bash
sudo apt install -y firmware-misc-nonfree   # mt76 firmware blobs
sudo dmesg | grep -i mt76
iw list | grep -i monitor
```
The `mt76` family is mainline and generally needs no out-of-tree driver — this is precisely why it's the recommended modern dual-band choice. If firmware is missing you'll see `mt76x2u ... direct firmware load for mediatek/... failed`; install `firmware-misc-nonfree` (or pull the blobs into `/lib/firmware/mediatek/`) and re-plug.

---

## 5. Enable monitor mode — the canonical sequence

Two interchangeable paths. **Path A (airmon-ng)** is the standard; **Path B (iw)** is the manual fallback when airmon-ng misbehaves or you want full control of the netdev name.

### Path A — airmon-ng (recommended)
```bash
# 1. Kill processes that will fight you for the radio (NetworkManager, wpa_supplicant, dhclient)
sudo airmon-ng check            # lists interfering PIDs
sudo airmon-ng check kill       # kills them  <-- skipping this is the #1 monitor-mode failure

# 2. Start monitor mode (creates wlan0mon, or renames in place on newer versions)
sudo airmon-ng start wlan0

# 3. Verify
iw dev                          # expect: type monitor, name wlan0mon
airmon-ng                       # shows the mon interface + driver + chipset
```
Restore normal networking afterward:
```bash
sudo airmon-ng stop wlan0mon
sudo systemctl restart NetworkManager
```

### Path B — iw / ip (manual, no airmon-ng)
```bash
sudo airmon-ng check kill                      # still clear interferers first
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor             # or: set monitor control
sudo ip link set wlan0 up
iw dev wlan0 info                              # verify "type monitor"

# Park on a specific channel (monitor mode does NOT auto-hop)
sudo iw dev wlan0 set channel 6
# 5 GHz / HT40 example:
sudo iw dev wlan0 set channel 36 HT40+
```

### Path C — create a dedicated monitor vif without destroying the managed one
```bash
sudo iw dev wlan0 interface add mon0 type monitor
sudo ip link set mon0 up
# capture on mon0, keep wlan0 for normal connectivity
```

**Channel control matters:** in monitor mode the card sits on whatever channel you set. For wide sweeps use `airodump-ng wlan0mon` (hops automatically); to lock onto a target BSSID's handshake you *must* pin the exact channel (`airodump-ng -c 6 --bssid <AP> -w cap wlan0mon`), because capturing on the wrong channel yields zero frames even though the card "works."

---

## 6. Injection test — the gate (`aireplay-ng -9` / `--test`)

**This is the single most important verification step and belongs immediately after monitor mode — not after you've wasted an hour wondering why a deauth did nothing.**

```bash
# -9 is the short form of --test ; run against the MONITOR interface
sudo aireplay-ng -9 wlan0mon
```

**What it does:** sends broadcast probe requests and listens; it lists nearby APs that respond and, for each, performs ~30 frame tests to measure injection quality (reported as a success percentage and ping-style timing). Good output looks like:
```
Injection is working!
Found N APs
<AP MAC> - channel: 6 - 'SSID'
Ping (min/avg/max): ... ms   30/30: 100%
```

**Card-to-card test (the 100%-sure variant).** Because some drivers/firmware silently *modify* frames on the way out, a one-card test can pass while real injection is subtly broken. With a second adapter in monitor mode on the same channel, use it as the receiver:
```bash
# wlan1mon is a second card listening on the same channel
sudo aireplay-ng -9 -i wlan1mon wlan0mon
```
This guarantees frames leave card A and arrive intact at card B.

**Failure interpretation (`No Answer... Found 0 APs`):**
Treat it as a *hint*, not proof the card can't inject. Rule out, in order:
1. **Wrong/idle channel** — nothing to probe. Pin a channel with a known AP (`iw dev wlan0mon set channel 6`) and retry.
2. **Not actually in monitor mode** — `iw dev` says managed → redo §5.
3. **check kill not run** — NetworkManager flipped the card back. Re-run `airmon-ng check kill`.
4. **Driver doesn't support injection in this mode** — e.g. wrong RTL fork (morrownr 20210820), vendor driver bound instead of out-of-tree → §4.
5. **TX power / regulatory limiting you to listen-only on that band** — see §7/§8.
6. **No APs in range** — move, or do the card-to-card test which needs no external AP.

ASCII-hyphen gotcha: some web pages render `--test` with an en-dash (`—test`), which the shell rejects. Always type two plain hyphens.

---

## 7. Decision order / troubleshooting flowchart

```
Plug adapter
   │
   ├─ lsusb → identify VID:PID → confirm CHIPSET (not product name)   [§3]
   │
   ├─ iw list shows "* monitor"?
   │      NO → is a driver even bound? (dmesg)                        [§3/§4]
   │             NO  → install/firmware → in-kernel first             [§4.0-4.4]
   │             YES → wrong driver bound → blacklist + out-of-tree   [§4.2/4.3]
   │      YES → continue
   │
   ├─ airmon-ng check kill → airmon-ng start wlanX → iw dev == monitor? [§5]
   │      NO → Path B (iw manual) / re-run check kill / fix driver
   │      YES → continue
   │
   ├─ aireplay-ng -9 wlanXmon  →  injection working?                  [§6]
   │      NO → channel? mode? fork? power? (§6 failure list)
   │      YES → ADAPTER LAYER GOOD ✓  → proceed to capture/recon
   │
   └─ On every kernel upgrade: re-verify (DKMS may have silently failed) [§8]
```

Pro buy order when acquiring hardware for an authorized lab:
1. **AR9271 (AWUS036NHA)** — guaranteed 2.4 GHz injection, zero driver drama → learn here.
2. **MT7612U (AWUS036ACM)** — add dual-band without out-of-tree pain.
3. **RTL8812AU (AWUS036ACH)** — only if you need cheap dual-band power and accept DKMS maintenance.
4. Keep the **RTL8188EUS** as the cheap/travel 2.4 GHz backup once its driver is pinned.

---

## 8. Gotchas & pitfalls (field-earned)

- **Kernel update silently breaks DKMS.** After `apt upgrade`, an out-of-tree driver may fail to rebuild. Symptoms: adapter gone from `iw dev`, or monitor mode disappears. Fix:
  ```bash
  dkms status                        # look for "broken"/missing for current kernel
  sudo apt install -y linux-headers-$(uname -r)
  sudo dkms autoinstall
  # still broken → re-clone the driver at a tag that compiles on the new kernel (§4.3)
  ```
  Latest kernels have repeatedly knocked out monitor-mode support for whole batches of USB adapters until the forks catch up — **pin your working kernel on a lab box and hold off blind upgrades before an engagement.**
- **`airmon-ng check kill` not run** → NetworkManager/wpa_supplicant yank the card back to managed mid-capture. Most common monitor-mode "failure."
- **Power management drops the radio.** USB autosuspend or Wi-Fi power save stalls capture:
  ```bash
  sudo iw dev wlan0 set power_save off
  echo on | sudo tee /sys/bus/usb/devices/*/power/control
  ```
- **USB 2.0 vs 3.0 / hubs.** High-throughput dual-band (8812AU/mt76) can brown-out or drop frames on an unpowered hub or a weak VM-passthrough path. Prefer a direct USB 3.0 port or a powered hub. USB 3.0 radio noise can also desense 2.4 GHz — move the dongle on an extension cable away from the port.
- **Regulatory domain caps channels and TX power.** If 5 GHz channels or higher TX are missing:
  ```bash
  iw reg get
  sudo iw reg set US         # set to YOUR legally-correct country
  # TX power (driver permitting):
  sudo iw dev wlan0 set txpower fixed 2000   # mBm (=20 dBm); do not exceed legal limits
  ```
  **Never set a region you are not in to unlock power/channels — that is an RF-compliance violation.** Stay within your jurisdiction's limits even in a lab.
- **Realtek monitor quirks.** 88xxAU forks sometimes need a module option or a down/up cycle before injection is clean; frames may be rate-limited. The card-to-card test (§6) exposes silent frame mangling that `-9` single-card misses.
- **en-dash in copy-pasted commands** (`—test`, `—bssid`) → shell error. Retype hyphens.
- **Interface renamed to mon by newer airmon-ng** — some versions set monitor *in place* keeping the `wlan0` name rather than creating `wlan0mon`. Always re-read `iw dev` for the real name instead of assuming `wlan0mon`.
- **Multiple drivers fighting.** Both an in-kernel module and an out-of-tree module present → race at boot. Blacklist the one you don't want (§4.2) and `update-initramfs -u`.

### VM / macOS host specific (your setup)
- **USB passthrough is the gatekeeper on a Mac.** The adapter must be claimed by the Kali VM, not macOS. In UTM/QEMU, VirtualBox, or VMware Fusion, attach the specific USB device (by VID:PID) to the VM and make sure macOS isn't holding it.
  ```bash
  # inside Kali, confirm the VM actually sees it:
  lsusb        # the dongle's VID:PID must appear
  dmesg | tail # should show enumeration + driver bind
  ```
- Prefer **USB 2.0 emulation for AR9271** (it's a USB2 device; forcing USB3 controllers sometimes breaks enumeration). For MT7612U/8812AU use the **USB 3.0** controller for throughput.
- If the device appears in macOS `System Information` but never in the VM's `lsusb`, the passthrough filter is wrong or macOS grabbed it — detach in the host, re-attach to the guest. (This dovetails with the KB's `vm-usb-passthrough-troubleshoot.md`.)
- Apple Silicon: ARM Kali VMs need an ARM-built DKMS driver; the build must match the VM's `uname -r` just like on x86.

---

## 9. Pro tips for speed

- **Keep a "known-good" adapter + pinned kernel** on the lab box so you always have a reference that passes `aireplay-ng -9`. When a new adapter misbehaves, swap to the reference to isolate adapter-vs-environment.
- **Script the bring-up** so monitor + channel + injection-test is one command (allowlist-gated):
  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  IFACE="${1:?usage: labup <iface> [channel]}"; CH="${2:-6}"
  sudo airmon-ng check kill
  sudo airmon-ng start "$IFACE"
  MON="$(iw dev | awk '/Interface/{print $2}' | grep -m1 mon || echo "${IFACE}mon")"
  sudo iw dev "$MON" set channel "$CH"
  sudo aireplay-ng -9 "$MON"       # prove injection before doing anything else
  echo "monitor+injection ready on $MON (ch $CH)"
  ```
- **`iw` over `iwconfig`.** `iwconfig` is deprecated; `iw` is the mac80211-native tool and reports capabilities honestly (`iw list`).
- **Check `iw list` capabilities before buying time debugging** — if `Supported interface modes` has no `* monitor`, the *driver* won't do it no matter what you try; change driver, not config.
- **Two cards beat one:** one locked on the target channel capturing, one free for the injection/recon role — and it enables the authoritative card-to-card injection test.
- **Label your dongles physically** with chipset + known-good kernel; the WN722N-style name collisions waste real time otherwise.
- **`airmon-ng` version differences**: on a strange box, run `airmon-ng` with no args to see how it names/handles the mon interface before scripting around it.

---

## 10. DEFENSE (pair every capability with its countermeasure)

Monitor mode and injection are the *attacker's* enabling layer; defenders neutralize them at the protocol and detection layers:

- **Monitor-mode sniffing is passive and undetectable over the air** — you cannot stop someone capturing your beacons/EAPOL. Therefore defend the *secret*, not the capture: **long, high-entropy WPA2/WPA3 passphrases** (≥ 20 random chars) make a captured handshake computationally useless offline. This is the real control, since §6-grade injection makes handshake capture trivial.
- **WPA3-SAE / 802.11w (Management Frame Protection)** defeats the injection-era bread-and-butter: PMF makes **deauth/disassoc injection ineffective** (frames are authenticated), so an attacker can't forcibly knock clients off to speed up handshake capture. Enable MFP "required" where client support allows; WPA3 mandates it.
- **WIDS/WIPS detection of injection & rogue RF.** Injection and deauth floods are *loud*: a Wireless IDS (Kismet, or commercial WIPS) flags abnormal deauth rates, spoofed BSSIDs, probe floods, and new monitor-mode-driven anomalies. For the lab, running **Kismet** alongside your tests teaches you exactly what your own injection looks like on the defender's console — the best way to understand detection is to watch your own traffic trip it.
- **Detect rogue APs / evil twins (detection only).** Baseline your authorized BSSIDs and channels; alert on an SSID advertised from an unexpected BSSID, OUI, channel, or signal profile. (Full evil-twin detection lives in `evil-twin-detection.md` — and this KB builds **detection + concept only, never a credential harvester.**)
- **Reduce RF exposure / blast radius:** lower AP TX power to the needed coverage, disable WPS (kills the reaver/pixie-dust path entirely), segment IoT, and use 802.1X/EAP-TLS (certificate auth) for enterprise so there is no PSK to crack.
- **Operational discipline:** every injection/deauth test here runs only against allowlisted, owned/authorized BSSIDs, on your own channel, with logging — because those same frames hitting a bystander's network are both detectable and unlawful.

---

## 11. Sources

Primary / official tool docs:
- aircrack-ng — Compatibility drivers (driver taxonomy: vendor / peer-modified / staging / mac80211): https://www.aircrack-ng.org/doku.php?id=compatibility_drivers
- aircrack-ng project blog — "On drivers: rtl8812au, WN722N, monitor mode": https://aircrack-ng.blogspot.com/2017/08/on-drivers-rtl8812au-wn722n-monitor.html
- aircrack-ng forum — 8812AU/8814AU driver recommendation thread: https://forum.aircrack-ng.org/index.php/topic,1186.msg4116.html
- aireplay-ng(8) man page (injection test `-9`/`--test`, `-i`): https://manpages.org/aireplay-ng/8 and https://www.mankier.com/8/aireplay-ng

Driver repositories:
- aircrack-ng/rtl8812au (maintainer-recommended 88XXau driver): https://github.com/aircrack-ng/rtl8812au
- aircrack-ng/rtl8188eus (out-of-tree 8188EUS DKMS): https://github.com/aircrack-ng/rtl8188eus (mirror/README: https://git.sim1222.com/sim1222/rtl8188eus)
- morrownr/8812au-20210629 (monitor mode supported): https://github.com/morrownr/8812au-20210629
- morrownr/8812au-20210820 (monitor mode NOT supported — avoid for RF work): https://github.com/morrownr/8812au-20210820
- rtl8812au v5.6.4.2 tag README (version-pin recipe): https://git.axenov.dev/anthony/rtl8812au/raw/branch/v5.6.4.2/README.md
- lwfinger/rtw88 (mac80211 replacement the deprecated forks point to): https://github.com/lwfinger/rtw88
- git.abonnel rtl8188eu README (blacklist r8188eu guidance): https://git.abonnel.fr/cedricAbonnel/rtl8188eu

Adapter/chipset compatibility references & guides:
- StationX — Best Wi-Fi Adapters for Kali Linux: https://app.stationx.net/articles/best-wifi-adapters-for-kali-linux
- CellStream — USB Wi-Fi adapters that support monitor mode: https://www.cellstream.com/?p=9110
- hashcat forum — adapter/chipset monitor+injection discussion (Broadcom/Intel caveats): https://hashcat.net/forum/thread-11245.html
- Parrot community — wireless USB adapters (Ralink RT3070/5370/5572): https://community.parrotsec.org/t/wireless-usb-adapters/292/2
- gengstah — Monitor Mode and Packet Injection concepts: https://gengstah.github.io/wiki/concepts/monitor-mode-injection/
- Rokland store — ALFA AWUS036ACH/AC/EAC driver install (Linux/Kali): https://store.rokland.com/pages/alfa-awus036ach-awus036ac-awus036eac-driver-install-linux-kali
- tutorials.technology — RTL8812AU on Kali 2026, monitor mode & injection (kernel 6.14 / realtek-rtl88xxau-dkms): https://tutorials.technology/tutorials/rtl8812au-kali-linux-2026-monitor-mode.html
- tutorials.technology — Best Wi-Fi adapters Kali 2026 (mt76 / MT7612U / MT7921AU): https://tutorials.technology/tutorials/best-wifi-adapters-kali-linux-2026.html
- patrickmccanna.net — AWUS036ACH troubleshooting (Raspberry Pi OS, DKMS): https://patrickmccanna.net/?p=911
- itsfoss — Monitor mode on TP-Link WN722N (v1 vs v2/v3 chipset trap): https://itsfoss.com/monitor-mode-fun/
- Secure Ideas — Introduction to wireless security with aircrack-ng: https://www.secureideas.com/blog/2018/09/introduction-to-wireless-security-with-aircrack-ng.html
- HackingTutorials — Wi-Fi adapter packet injection: https://www.hackingtutorials.org/wifi-hacking-tutorials/wifi-adapter-packet-injection/

> **Research note:** 4 WebSearch queries + 1 direct fetch of aircrack-ng.org completed before this workflow turn hit its shared 200-call web-search budget; the second planned batch (ath9k_htc/AR9271 deep-dive, mt76 deep-dive, airmon-ng step-by-step) was written from the above sources plus established domain knowledge. The exact `aireplay-ng -9` output format, `iw`/`airmon-ng` sequences, DKMS/blacklist mechanics, and VM-passthrough notes should be re-verified against the current repo READMEs and your *exact* kernel before an engagement, since out-of-tree driver/kernel compatibility drifts constantly. For a follow-up pass, re-run with queries on: `ath9k_htc AR9271 firmware htc_9271`, `mt76x2u injection kernel`, `iw dev set type monitor control`, and the aircrack-ng tutorial pages.
