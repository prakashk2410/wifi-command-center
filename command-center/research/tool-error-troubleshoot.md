# aircrack-ng / hashcat / hcxdumptool — Error → Fix Troubleshooting

> **Scope & authorization.** This reference supports an **AUTHORIZED** local Wi-Fi
> lab: your own hardware, sanctioned CTF/competition gear, or OSWP study on a
> network you own or have written permission to test. Everything here is about
> making *your own tooling* run — getting a radio into monitor mode, getting a
> clean capture, converting it, and feeding a GPU. It attacks nothing. The
> **Defense / blue-team** section at the end is the paired hardening view: how the
> same symptoms look from the defender's side and how to make these failures
> *expected* on networks you run.
>
> Rig assumed by this doc: **macOS host → UTM/QEMU → Kali guest → TP-Link
> RTL8188EUS (2.4 GHz) USB adapter**, with a Mac GPU doing hashcat work (Apple
> Metal/OpenCL). Allowlist-gated: every capture/crack is scoped to BSSIDs on your
> approved list.

This is the "it won't work" playbook. The 90% of a Wi-Fi lab that is *fighting
your own tools* lives here. It is organized as **error → cause → fix pairs**, in
the **order a pro actually triages them**, stage by stage down the pipeline.

---

## 0. The concept (brief): the pipeline, and where each error lives

```
 CAPTURE                      CONVERT                 CRACK
 ┌───────────────────────┐    ┌───────────────┐       ┌────────────────────────┐
 airodump-ng / hcxdumptool ──▶ hcxpcapngtool   ──▶     hashcat (-m 22000)
 (monitor mode, injection)     (.pcapng→.hc22000)      aircrack-ng (-w wordlist)
 └───────────────────────┘    └───────────────┘       └────────────────────────┘
   § 2,3,4                        § 5                      § 6,7,8
   "0 APs / Aborted /             "0 EAPOL /               "No devices /
    fixed channel -1 /             0 PMKID /                Token length /
    no handshake"                  no hashes written"       mode 2500 dead"
```

**The single most useful triage habit:** decide *which stage* failed before you
touch a flag. A hashcat "No hashes loaded" is never fixed by messing with the
radio; an airodump "0 packets" is never fixed by a hashcat option. Pros bisect:
"Did I capture? Did it convert? Did it load? Did it run?" — and only then open
the manual for that one stage.

Three facts that explain most failures:

1. **Monitor mode + injection is a driver property, not a tool property.** If the
   driver can't do it, *no* tool in the chain works. (RTL8188EUS via the
   out-of-tree `8188eu`/`rtl8188eus` driver does both, but is channel-set flaky —
   see §3.)
2. **Something is always fighting you for the radio.** NetworkManager,
   `wpa_supplicant`, `dhclient` — all will yank your card back to managed mode or
   re-set the channel mid-capture. `airmon-ng check kill` exists for exactly this.
3. **The WPA hash format changed.** Old tutorials say `-m 2500` / `.hccapx`.
   That mode is **dead** in current hashcat. Everything is now **`-m 22000`** /
   `.hc22000`, produced by **hcxpcapngtool**. Half of "hashcat won't load my
   handshake" is someone following a 2018 blog.

---

## 1. The pro decision order (master flow)

Run this top-to-bottom the moment something breaks. Each line is a 5-second check.

```
0.  rfkill list           # radio soft/hard blocked?  -> rfkill unblock all
1.  ip link / iw dev      # does the interface even exist? right name?
2.  iw dev <if> info      # type monitor? what channel?
3.  airmon-ng check       # who is fighting me for the card?  -> check kill
4.  iw list | grep -A8 "Supported interface modes"   # monitor supported?
5.  iw list | grep -A2  "Supported commands"          # does it list "inject"? (heuristic)
6.  CAPTURE test:  airodump-ng -c <ch> --bssid <AP> -w t <if>   # do I see beacons?
7.  INJECT test:   aireplay-ng --test <if>            # injection + which APs hear me
8.  CONVERT test:  hcxpcapngtool -o t.hc22000 t.pcapng  # EAPOL/PMKID count > 0?
9.  LOAD test:     hashcat -m 22000 t.hc22000 --show   # parses without error?
10. DEVICE test:   hashcat -I   and   hashcat -b -m 22000  # GPU present + benches?
```

The first line that fails is your bug. Stop there and jump to its section.

---

## 2. airodump-ng errors

### 2.1 `airodump-ng` exits immediately / "Aborted"

**Symptom:** window opens and closes, or `Aborted (core dumped)`, or it refuses
the interface.

**Causes & fixes (in order):**

- **Interface not in monitor mode / wrong name.** airodump wants the *monitor*
  interface, not `wlan0`.
  ```bash
  sudo airmon-ng start wlan0            # creates wlan0mon (or monX on mac80211)
  iw dev                                # confirm the monitor iface name
  sudo airodump-ng wlan0mon
  ```
- **Radio is rfkill-blocked** → airodump can't bring the iface up.
  ```bash
  rfkill list
  sudo rfkill unblock all
  sudo ip link set wlan0mon up
  ```
- **Stale monitor iface from a crashed run.** Tear down and rebuild:
  ```bash
  sudo airmon-ng stop wlan0mon
  sudo ip link set wlan0 down
  sudo iw dev wlan0 set type monitor
  sudo ip link set wlan0 up
  ```
- **Version/driver mismatch after a USB re-enumeration** (common on the
  macOS→UTM→Kali rig): the adapter came back as a *different* ifname (`wlan1`).
  Re-check `iw dev` before every run; don't hard-code `wlan0mon` in scripts —
  resolve it at runtime.
- **Writing to a path that doesn't exist** with `-w`: airodump aborts if the
  directory for the prefix is missing. `mkdir -p` the capture dir first.

### 2.2 "fixed channel <iface>: -1" / channel-hopping flakiness

**Symptom:** top-left `CH` cycles but the header shows `fixed channel wlan0mon: -1`,
or the channel keeps snapping back to one value, or APs flicker in and out.

**What it means (from aircrack-ng docs):** airodump requested a channel but
*another process changed the interface's channel out from under it.* The usual
culprits: a managed-mode interface still scanning, NetworkManager,
`wpa_supplicant`, a second airodump/airmon instance, or you asked for a channel
the card can't do (e.g. ch 13 on an 11-channel card).

**Fixes:**
```bash
# 1) Kill the interference (THE fix 80% of the time)
sudo airmon-ng check            # list offenders
sudo airmon-ng check kill       # stop NetworkManager, then wpa_supplicant/dhclient

# 2) Lock to a channel instead of hopping (steadier, more data per channel)
sudo airodump-ng -c 6 wlan0mon
sudo airodump-ng -c 1,6,11 wlan0mon     # scan only the real 2.4GHz channels

# 3) Silence the cosmetic -1 message (does NOT fix a real channel fight)
sudo airodump-ng --ignore-negative-one -c 6 wlan0mon
```
**RTL8188EUS gotcha (important for this rig):** the out-of-tree Realtek driver
reports channel changes oddly, so `fixed channel -1` appears even when capture is
fine. If data *is* flowing, treat `-1` as cosmetic and add
`--ignore-negative-one`. If data is **not** flowing, it's a real fight → `check
kill`. Set the channel explicitly with `iw` to confirm the card obeys:
```bash
sudo iw dev wlan0mon set channel 6
iw dev wlan0mon info | grep channel      # did it stick?
```

### 2.3 0 APs / 0 packets / "nothing shows up"

**Causes & fixes (decision order):**

1. **Interface isn't actually in monitor mode.** `iw dev wlan0mon info` must say
   `type monitor`. If it says `managed`, a network manager grabbed it → `check kill`,
   re-enable monitor.
2. **Hopping leaves too little dwell time** — lock a channel (`-c 6`). You will
   often go from 0 to many APs instantly because the card was off-channel.
3. **Wrong band.** The RTL8188EUS is **2.4 GHz only**. If your target is 5 GHz
   you will see nothing, forever. `--band a` won't help a 2.4-only radio.
   ```bash
   sudo airodump-ng --band bg wlan0mon     # only bands this card supports
   ```
4. **Antenna / distance / TX side.** Verify the card works in *managed* mode
   first (it associates to a normal AP). If managed also sees nothing, it's
   hardware/driver, not airodump.
5. **Driver needs a reload** (Realtek classic): `rmmod`/`modprobe` the module,
   then re-create monitor.
6. **Powersave** silently parks the radio:
   ```bash
   sudo iw dev wlan0 set power_save off
   ```
7. **On the macOS→UTM→Kali rig:** a dropped USB passthrough looks exactly like
   "0 packets." `dmesg | tail` and `lsusb` — if the adapter vanished, it's the VM
   seam (see the VM/USB passthrough doc), not airodump.

### 2.4 Capture runs, but "WPA handshake" never appears in the top-right

This is the #1 "no handshake" problem. airodump shows `WPA handshake: <BSSID>`
top-right **only** when all needed EAPOL frames are seen. If it never appears:

- You must be **on the AP's exact channel** — hopping rarely catches a full
  handshake. Lock `-c`.
- You need a **client that connects (or reconnects)**. No client → no 4-way
  handshake. Either wait, or force it with a *targeted* deauth (§9).
- **`--ivs` discards the full frames** you need — never use it for WPA.
- A **`--bssid` filter can drop ACK/analysis packets** in some setups; if a
  handshake "should" be there but doesn't validate, re-run without the filter.
- Confirm in Wireshark: filter `eapol` and count 1→4 of the four messages.
  Pairs M1+M2 (or M2+M3) are enough for hashcat; you don't need all four.

```bash
# Capture scoped to one AP on its channel while you (optionally) deauth:
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
```

### 2.5 `SIOCSIFFLAGS: Unknown error 132` / won't come up

RF is blocked. `sudo rfkill unblock all`, flip any hardware RF switch, then
`ip link set <if> up`.

---

## 3. Monitor mode & interface prep (the layer under every capture tool)

**`airmon-ng check kill` is the first command of every session.** It stops
NetworkManager first, then the remaining offenders (`wpa_supplicant`,
`dhclient`, `avahi-daemon`). The aircrack docs call killing these "very
important" before using the suite.

```bash
sudo airmon-ng check
sudo airmon-ng check kill
sudo airmon-ng start wlan0         # -> wlan0mon
# ... work ...
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager   # restore normal networking
```

**`iw`-only path (no airmon-ng, cleanest for scripts / hcxdumptool):**
```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iw dev wlan0 info                   # confirm: type monitor
```

**Is monitor + injection even supported?**
```bash
iw list | grep -A8 "Supported interface modes"   # must list "* monitor"
sudo aireplay-ng --test wlan0mon                  # injection works? which APs ACK?
```

**Common monitor-mode failures:**

| Error | Cause | Fix |
|---|---|---|
| iface flips back to `managed` | NetworkManager reclaimed it | `airmon-ng check kill`; `nmcli dev set wlan0 managed no` |
| `add_iface: Permission denied` | old airmon-ng / not root | upgrade; run with `sudo` |
| `SIOCSIFFLAGS: Unknown error 132` | rfkill block | `rfkill unblock all` |
| `command failed: Operation not supported (-95)` | driver can't do the mode | wrong/old driver; reload or use a mac80211 driver |
| monitor iface named `mon0` not `wlan0mon` | mac80211 default | just use the name `iw dev` reports |

**RTL8188EUS specifics (this lab's adapter):**
- Uses the out-of-tree `8188eu`/`rtl8188eus` driver (aircrack-ng/8188eus or
  morrownr). Supports monitor + injection, but **channel-setting is quirky** →
  expect `fixed channel -1` (§2.2) and set channel explicitly with `iw` if a tool
  won't.
- 2.4 GHz only. No 5/6 GHz, ever.
- After `check kill` + monitor it is solid; the fragile part is the **USB
  passthrough** on the VM rig, not the driver.

---

## 4. hcxdumptool errors

hcxdumptool is the modern one-shot capture tool (PMKID + EAPOL). It is **much
stricter about environment** than airodump, and it was **rewritten** (v6→v6.3+),
so old flags are gone.

### 4.1 The "VM" / unsupported-platform warning

**Symptom:** older hcxdumptool printed a warning that it is *not intended to run
in a VM / emulator*; current hcxdumptool README states plainly:
> Unsupported: Windows OS, macOS, Android, emulators or wrappers!

**Why:** hcxdumptool does tight, timing-sensitive frame injection straight
against the mac80211 stack. A VM's emulated USB/timing can corrupt that timing,
and (on this rig) the adapter is reached through QEMU USB passthrough — a
*wrapper* in spirit.

**What it means for the macOS→UTM→Kali lab:**
- The warning is about *timing reliability*, not a hard block — hcxdumptool will
  usually still run inside Kali-in-UTM because, from the guest's view, the adapter
  is a real USB device on a real Linux kernel. But expect lower reliability than
  bare metal.
- If PMKID/EAPOL capture is flaky in the VM, that's the warning biting. Pro move:
  **capture with hcxdumptool only when you have native Linux**; inside the VM,
  prefer **airodump-ng + targeted deauth** (more forgiving of timing), and use
  hcxdumptool for passive PMKID harvesting where injection timing matters less.
- Do **not** try to silence it with hacks; treat it as "results here are
  best-effort."

### 4.2 "driver does not support monitor/injection" / refuses the interface

hcxdumptool requires:
- **Linux kernel ≥ 5.15** (latest longterm/stable recommended).
- A chipset that can do **monitor mode** and **full frame injection**.
- An **in-tree** driver — *"Drivers must be part of the official Linux kernel.
  Third-party drivers are not supported."*

**RTL8188EUS caveat:** its driver is **out-of-tree**. So hcxdumptool may warn or
behave imperfectly with it. Fixes / workarounds:
- Confirm injection independently: `sudo aireplay-ng --test wlan0`.
- If hcxdumptool misbehaves on the 8188eus, fall back to the
  **airodump-ng + aireplay-ng** capture path (§2.4, §9), then convert with
  hcxpcapngtool — the *conversion+crack* half of the hcx toolchain works fine
  regardless of how you captured.

### 4.3 "WIRELESS EXTENSIONS are deprecated"

hcxdumptool talks **nl80211/netlink**, not legacy WEXT. This message means a tool
or script is still poking the card via the old ioctl interface. Don't mix
`iwconfig` with hcxdumptool; prep the card with `ip`/`iw` only. The repo ships
`stopnm`/`startnm` helpers and `startnlmon` for a netlink monitor.

### 4.4 Old flags removed / "unknown option" after an update

The rewrite **removed/renamed** most v6 options. Old blogs use flags like
`-o`, `--enable_status=`, `--filterlist_ap=`, `--active_beacon`,
`--do_rcascan` — several are gone or renamed. Fixes:
- `hcxdumptool --help` is the **only** authority for your installed version.
- Keep **hcxdumptool and hcxpcapngtool the same version** (README requirement) —
  a version skew silently produces captures the converter mishandles.
- Modern attack-vector switches you should know (for *scoping*, §4.5):
  `--associationmax=0` (disable PMKID connection attempt),
  `--disable_disassociation`, `--m2max=0` (disable client-connection attack).

### 4.5 "it's hitting everything" — mandatory BPF scoping (allowlist tie-in)

hcxdumptool, left unscoped, transmits to *every* AP/client it hears. The README
is blunt: if you can't fully control the environment, **a BPF filter is
mandatory.** This is exactly how you enforce your **allowlist**:
```bash
# Build a Berkeley Packet Filter that limits activity to your approved BSSID(s):
hcxdumptool -i wlan0 --bpfc="wlan addr3 AA:BB:CC:DD:EE:FF" -w lab.pcapng
# (generate/compile the filter per your version's docs; the point is: scope it)
```
On a real engagement/CTF this is both the safety rail and the reason your capture
isn't polluted with out-of-scope networks.

### 4.6 Headless `ERROR` spam from the status display

Building/running with the status display on a headless box throws errors. The
README says build without `-DSTATUSOUT` in the Makefile for headless use. For a
GUI Kali this won't bite you.

### 4.7 Nothing captured at all

- Card not in monitor / not up → §3.
- You scoped the BPF too tightly (typo in BSSID) → loosen and re-test.
- No clients present and `--associationmax=0` set → you disabled the very vector
  that would have produced a PMKID. Re-enable.
- VM timing (§4.1) → move to bare metal or use the airodump path.

---

## 5. Conversion errors — hcxpcapngtool (`.pcapng` → `.hc22000`)

This is the quiet failure point: capture "worked," but you get **no hashes**.

```bash
hcxpcapngtool -o lab.hc22000 lab.pcapng
# Read the SUMMARY it prints: look for non-zero
#   "PMKID(s)" and "EAPOL M1M2/M2M3 ... written"
```

### 5.1 "0 EAPOL / 0 PMKID / 0 hashes written"

Means the capture contains **no usable handshake or PMKID**. The bug is upstream
in §2/§4, not here. Go back and:
- confirm airodump showed `WPA handshake` (§2.4), or
- confirm a client actually connected (PMKID needs the AP; a usable EAPOL needs a
  client association), then deauth (§9) and re-capture.

### 5.2 Hashes written but cracking never succeeds on a known-good password

**Nonce / packet-loss corruption.** hcxtools explicitly **does not do nonce-error
correction** — after packet loss, the derived PTK is wrong and the correct
password will *never* match. Fixes:
- Recapture with a **cleaner** handshake (closer, less congestion, lock channel).
- Prefer **M1+M2** or **M2+M3** pairs; M4-based pairs with a zeroed nonce are
  unusable. In practice most captures yield "Hash 1 and Hash 2."
- Validate the line looks sane before burning GPU hours (§7.1).

### 5.3 Garbage / lost hashes after you "merged" captures

**Don't `cat` pcapng files together.** hcxpcapngtool assigns hash values via
custom blocks, and merging dump files can destroy them. Convert each capture
separately; it's the **`.hc22000` text output** that is safe to `cat` together
(append), not the raw pcapng.

### 5.4 Version skew

hcxdumptool and hcxpcapngtool **versions must match**. A Kali that updated one
but not the other is a classic silent corruptor. `hcxpcapngtool --version` /
`hcxdumptool --version`.

### 5.5 Filtering to your allowlist before cracking

```bash
hcxhashtool -i lab.hc22000 --essid-list=approved.txt -o scoped.hc22000
# or filter by BSSID; keeps you cracking only in-scope networks
```

---

## 6. hashcat device / backend issues

### 6.1 "ATTENTION! No OpenCL, HIP or CUDA compatible platform found"

**No runtime loaded at all.** Fix by installing the right backend for your GPU:
- **Apple Silicon / Intel Mac (this lab's cracker):** hashcat uses Apple's
  **Metal/OpenCL** backend, which ships with macOS. If it's missing, you're
  usually running an x86 hashcat under Rosetta or a broken Homebrew build —
  reinstall the native build: `brew install hashcat` and run `hashcat -I`.
- **NVIDIA:** driver **+ CUDA Toolkit**.
- **AMD/Linux:** ROCm + be in the `video` and `render` groups (then log out/in).

```bash
hashcat -I       # what backends/devices does hashcat actually see?
```

### 6.2 "No devices found/left"

A runtime loaded, but **every device got excluded** — by `-d`, by
`--backend-devices`, or by a suitability check. Fixes:
- Drop any stale `-d`/`--backend-devices` you copied from a blog.
- `hashcat -I` lists device numbers; `-I` **skips** suitability checks, so a
  device shown by `-I` may still be refused by a real run — **start an actual
  run** to see the skip reason printed.
- CPU is **off by default**; enable it explicitly if that's all you have:
  ```bash
  hashcat -m 22000 lab.hc22000 wordlist.txt -D 1      # CPU
  hashcat -m 22000 lab.hc22000 wordlist.txt -D 1,2    # CPU + GPU
  ```

### 6.3 Runtime "too old" → silent OpenCL fallback / slow

If CUDA < 12.0 or HIP < 6.2.0, hashcat **falls back to OpenCL** and **`--force`
will not override** the gate. Update the toolkit to the minimum. Don't paper over
it with `--force` (which only suppresses warnings and can give wrong results).

### 6.4 Wrong results / errors right after a driver update

Clear the **runtime's own caches**, not just hashcat's kernel cache:
`~/.nv/ComputeCache`, `~/.cache/comgr`, `~/.cache/pocl` (and hashcat's
`kernels/` cache). Stale compiled kernels after a driver bump cause bogus
behavior.

### 6.5 CUDA error 702 `CUDA_ERROR_LAUNCH_TIMEOUT` / `CL_OUT_OF_RESOURCES` / driver reset

The **display driver watchdog** killed a long kernel — mainly on a GPU that is
*also driving your monitor*. Fixes, cheapest first:
- Lower `-n` (`--kernel-accel`) and/or `-u` (`--kernel-loops`).
- Run on a card that **isn't driving a display** (headless second GPU).
- Disable the watchdog per the hashcat "Driver Timeout Patch" wiki page.
- On macOS this surfaces less, but a long run can still trip Metal timeouts —
  break the keyspace into sessions (§7.4).

### 6.6 Flag reality check

- `-O` = optimized kernels, **caps password length** (≈55 for most modes).
  Benchmarks use `-O` by default, normal attacks use pure kernels unless you add
  it. If you set `-O` and your passphrase is >55 chars you'll never find it.
- `-w` **workload-profile** has **no effect** in current hashcat — don't rely on
  `-w 3/4` for speed anymore; tune `-n`/`-u` instead.

---

## 7. hashcat hash-loading / format errors (the WPA ones)

### 7.1 "Old 2500 / hccapx" errors — the #1 WPA mistake

- **`-m 2500` is deprecated and will not run.** hashcat prints a deprecation
  notice and stops. Do **not** "fix" it with `--deprecated-check-disable`.
- **Convert to 22000 instead:**
  ```bash
  hcxpcapngtool -o lab.hc22000 lab.pcapng
  hashcat -m 22000 lab.hc22000 wordlist.txt
  ```
- `.hc22000` is text, **one handshake per line**, so one run cracks many
  networks; join files with `cat a.hc22000 b.hc22000 > all.hc22000`.

### 7.2 "Token length exception" / "No hashes loaded" / "Separator unmatched"

| Printed error | Real cause | Fix |
|---|---|---|
| `Token length exception` | Wrong `-m`; **or the file path doesn't exist** so hashcat treats the *filename* as a hash | double-check `-m 22000`; verify the capture path exists |
| `No hashes loaded` | empty/blank file, or every line filtered out | `wc -l lab.hc22000`; reconvert |
| `Separator unmatched` / parse fail | trailing spaces/tabs on a line (not stripped automatically); or `user:hash` lines without `--username` | `sed -i 's/[ \t]*$//' file`; add `--username` if applicable |
| `No hash-mode matches the structure of the input hash` | you let autodetect run with no `-m` | always pass `-m 22000` for WPA |

### 7.3 "It got slower with more networks"

Expected. Each network = its **own salt**, so throughput drops as you add
salts — still far faster than one run per network. As each salt is fully
cracked, hashcat skips it and the rest speeds up. Watch with `--status`.

### 7.4 Sessions / restore (so a 10-hour run survives a crash)

- **Piped input has no restore point** and can't be resumed. For long jobs pass
  the wordlist as a **file**, or add **`-S`** to keep the keyspace.
- Resume: rerun the original command with the same `--session <name>` and
  `--restore-position` (or `--restore`).
  ```bash
  hashcat -m 22000 --session lab lab.hc22000 rockyou.txt -S
  # after a crash:
  hashcat --session lab --restore
  ```
- Results land in the **potfile** as found; `--show` reprints them, `--left`
  shows the uncracked.

---

## 8. aircrack-ng cracking errors (when you crack with aircrack, not hashcat)

### 8.1 "No valid WPA handshakes found" / "0 handshakes"

The `.cap` has no usable 4-way handshake. Causes (from aircrack docs):
- monitor iface was on the **wrong channel/mode** vs the AP;
- a connection manager interfered;
- too far (or oddly, too close) to the devices;
- capture used **`--ivs`** (discards the full frames WPA needs);
- a **`--bssid` filter dropped ACK** packets used for analysis;
- outdated/unsupported driver.
Fix: recapture (§2.4) — redo the deauth or wait for a client — then retry.

### 8.2 aircrack-ng is just slow

Expected: ~50–300 keys/sec on CPU. The passphrase **must be in the wordlist**;
aircrack does dictionary only. For real speed, **convert to 22000 and use the
GPU** (§7.1). Use aircrack-ng mainly to *verify a handshake exists*:
```bash
aircrack-ng lab.cap            # lists APs and whether each has a handshake
```

---

## 9. Forcing a handshake — aireplay-ng deauth troubleshooting

Deauth is **optional** and only works if a client is **currently associated**.

```bash
# Targeted (preferred): 64 pkts to AP + 64 to client, per the count
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
# Broadcast (less reliable; many clients ignore it): omit -c
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Why a deauth doesn't yield a handshake:**
- You're **too far** — a full capture with **no ACK** from the client proves it
  didn't hear you. Watch the `[ ACKs from client | ACKs from AP ]` counters; `0`
  = not heard, very low = weak signal.
- Your card is a **different mode** (b/g/n) than the client.
- The client **ignores broadcast** deauths → use `-c` (targeted).
- Client **reconnects too fast to notice** — look for reassociation packets to
  confirm it worked.

**Best practice:** keep airodump running on the AP's channel (`-c` + `--bssid` +
`-w`) in one pane while you send a **small** count (start `-0 5`) in another.
Wait a few seconds, then check for the `WPA handshake` flag. Too many deauths can
stop a client reconnecting — less is more. **Authorized targets only.**

---

## 10. Gotchas / pitfalls — quick table

| Symptom | Most likely cause | Fast fix |
|---|---|---|
| Everything "worked" but 0 hashes to crack | capture had no real handshake/PMKID | §2.4 / §5.1 |
| `fixed channel -1` on RTL8188EUS | out-of-tree driver quirk (often cosmetic) | `--ignore-negative-one`; `check kill` if data also missing |
| Card flips to managed mid-capture | NetworkManager/wpa_supplicant | `airmon-ng check kill` |
| hashcat refuses WPA file | following a `-m 2500`/hccapx tutorial | convert to `.hc22000`, `-m 22000` |
| `Token length exception` | wrong `-m` **or bad file path** | verify path + `-m 22000` |
| correct password never cracks | nonce corruption from packet loss | recapture clean (§5.2) |
| hcxdumptool unreliable | running in the VM / out-of-tree driver | capture on bare metal or use airodump path |
| GPU "No devices found/left" | stale `-d`, or suitability skip | drop `-d`; start a real run to see why |
| 5 GHz target invisible | RTL8188EUS is 2.4 GHz only | use a dual-band card for 5 GHz |
| captures merged, hashes gone | `cat`'d pcapng files | convert separately; only `cat` the `.hc22000` |

---

## 11. Pro tips for speed

- **Bisect by stage (§1) before changing any flag.** Saves the most time, always.
- **Lock a channel** (`-c`) the instant you know your target — stop hopping.
- **PMKID first.** `hcxdumptool` PMKID capture needs no client and no deauth — one
  frame from the AP and you may be done. Try it before the noisy deauth dance.
- **One `.hc22000`, many nets.** Convert everything, `cat` into one file, crack in
  one GPU run; mode 22000 handles multiple salts in a single pass.
- **Run hashcat straight on the Mac GPU.** Don't crack inside the Kali VM — pull
  the `.hc22000` out to the macOS host and run native hashcat there (Metal). The
  VM has no real GPU.
- **Keep a session + `-S`** on every long run so a crash/sleep is resumable.
- **`aireplay-ng --test` early** — knowing injection works (and which APs ACK you)
  prevents an hour of "why no handshake."
- **Pin hcxdumptool == hcxpcapngtool versions** in your lab build; version skew is
  a silent time sink.
- **Mask/rule later, dictionary first.** `rockyou` + a good rule set catches most
  lab passwords before you burn hours on brute masks.

---

## 12. Defense / blue-team — the paired view

Every failure above is something a *defender* can make permanent on networks they
run. This is the hardening half of the skill:

- **PMKID harvesting (the "no client needed" shortcut) is defeated by** disabling
  PMKID caching / 802.11r roaming where not needed, or simply by a passphrase
  long/random enough that the resulting hc22000 never cracks. A 20+ char random
  PSK makes §7/§8 moot — the capture succeeds and the crack never finishes.
- **Deauth-forced handshakes (§9) are defeated by 802.11w (PMF / Management Frame
  Protection)** — protected management frames make the deauth injection a no-op,
  so your client never drops and no new handshake is produced. Turning on PMF is
  the single highest-value fix; it's why a modern WPA3/PMF network makes the
  airodump+deauth path simply stop working.
- **The `fixed channel -1` / 0-packet world is the defender's monitoring blind
  spot too:** a WIDS watching for floods of deauth/disassoc frames or for an
  RTL8188EUS-style injector will flag exactly the traffic that §9 generates. If
  you run the network, enable WIDS/rogue-AP detection and alert on deauth storms.
- **Evil-twin is out of scope here as an attack.** The defensive pairing is
  **detection + concept only:** watch for a second BSSID advertising your ESSID,
  for beacon/SSID anomalies, and for clients roaming to an AP that isn't yours —
  and protect clients with 802.11w + server-cert validation on enterprise
  Wi-Fi. This lab does **not** build a credential-phishing/captive-portal
  harvester; that line is not crossed.
- **Capture hygiene as a control:** because nonce-corrupted captures never crack
  (§5.2), congested, PMF-protected, well-sited networks are *naturally* hostile to
  capture — good RF design is a defense.

---

## Sources

Pages actually read for this reference (via WebFetch — the shared WebSearch quota
for this run was exhausted, so sourcing was done by fetching the authoritative
docs directly):

- aircrack-ng — airodump-ng usage & troubleshooting: https://www.aircrack-ng.org/doku.php?id=airodump-ng
- aircrack-ng — cracking WPA/WPA2 (handshake, "no valid handshake"): https://www.aircrack-ng.org/doku.php?id=cracking_wpa
- aircrack-ng — airmon-ng (`check kill`, monitor mode, rfkill/SIOCSIFFLAGS): https://www.aircrack-ng.org/doku.php?id=airmon-ng
- aircrack-ng — deauthentication / aireplay-ng `-0`: https://www.aircrack-ng.org/doku.php?id=deauthentication
- hashcat wiki — Frequently Asked Questions (devices/backends, watchdog, 22000 vs 2500, parse errors, sessions): https://hashcat.net/wiki/doku.php?id=frequently_asked_questions
- ZerBea/hcxdumptool — README (kernel/driver requirements, unsupported platforms/VM, options, BPF scoping, hcxtools workflow): https://github.com/ZerBea/hcxdumptool
- ZerBea/hcxtools — README (hcxpcapngtool conversion, message pairs/nonce, don't-merge, hcxhashtool): https://github.com/ZerBea/hcxtools

Supplementary knowledge applied where docs were thin: RTL8188EUS out-of-tree
driver channel-set quirk, Apple Metal/OpenCL hashcat backend specifics, and the
macOS→UTM→Kali USB-passthrough failure signatures (see the companion
`vm-usb-passthrough-troubleshoot.md` and `adapters-drivers-monitor.md`).
