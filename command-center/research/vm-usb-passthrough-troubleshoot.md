# Kali / UTM VM + USB Passthrough Troubleshooting (Apple Silicon Mac)

> **Scope & authorization.** This reference supports an AUTHORIZED local Wi-Fi
> lab: your own hardware, sanctioned CTF/competition gear, or OSWP study. The
> "device" being passed through is a **TP-Link RTL8188EUS 2.4 GHz adapter** you
> own, feeding a Kali guest for allowlist-gated testing. Nothing here attacks a
> network — it keeps your *lab plumbing* (macOS host → UTM/QEMU → Kali → USB
> radio) alive. The "Defense / safe-lab" section at the end is the hardening
> equivalent: how to avoid bricking the VM, corrupting the disk, or losing the
> adapter mid-capture.

This is the single most common thing that breaks a Mac-based Wi-Fi lab: the
adapter shows up in `lsusb` one minute and is gone the next, monitor mode kills
it, or the whole VM freezes with no SSH. Below is the **decision order a pro
runs**, command-first, with the exact `utmctl`, QEMU, and Kali commands and the
*why* behind each.

---

## 0. The concept (brief)

On an Apple Silicon Mac you cannot put a USB Wi-Fi radio into monitor mode
natively — macOS owns the Wi-Fi stack and there is no monitor-mode driver for a
RTL8188EUS on macOS. So the standard rig is:

```
macOS host  ──▶  UTM (GUI)  ──▶  QEMU (aarch64, -accel hvf -cpu host)  ──▶  Kali guest
                                   └── USB passthrough (usb-host / usb-redir) ──▶ /dev/bus/usb → wlan
```

The adapter is **detached from macOS and handed to QEMU**, which re-presents it
to Kali as a real USB device. Kali loads the Realtek driver, and you get
`wlan0` with monitor-mode + injection.

The fragility comes from **four seams**, each a distinct failure class:

1. **Host gatekeeper (macOS).** Apple-Silicon "Restricted Mode" ("Allow
   accessories to connect") can block or delay the device before UTM ever sees
   it. → §1a.
2. **Backend.** The Apple Virtualization backend historically had *no* arbitrary
   USB passthrough; the **QEMU backend** is what reliably passes a Wi-Fi radio to
   Linux. Pick wrong and nothing later works. → §1b.
3. **Enumeration / binding.** QEMU's `usb-host` can bind by *bus/address* (changes
   on every reset) or by *vendorid/productid* (survives re-enumeration). A driver
   reload, `airmon-ng check kill`, sleep, or hub glitch re-enumerates the device
   and QEMU loses the handle → "passthrough drops." → §5, §6.
4. **The emulated USB controller + ARM64 QEMU quirks.** XHCI (USB 3) vs EHCI
   (USB 2) stability, and ARM64 disk-cache/freeze bugs. → §5, §7.

---

## 1. FIRST decisions: host gatekeeper + which backend

### 1a. macOS "Allow accessories to connect" (the silent first blocker)

On Apple-silicon Macs (Ventura 13+), **Restricted Mode / "Allow accessories to
connect"** governs whether a freshly-plugged USB device is even usable. Default
is *"Ask for new accessories"*, which can leave the radio in limbo for UTM. For
a lab machine, set it permissive:

- **System Settings ▸ Privacy & Security ▸ (scroll) Accessories ▸ "Allow
  accessories to connect"** → choose **"Automatically allow when unlocked"**
  (or "Always allow").
- Options are: *Always ask* / *Ask for new accessories* (default) / *Automatically
  allow when unlocked* / *Always allow*.
- This setting exists only on **Apple silicon**, not Intel, and only on
  Ventura+. If it's missing/greyed, it's tied to your Mac model/macOS version or
  MDM supervision.

> This is the #1 cause of "the adapter works on my Intel Mac but not my M-series"
> and of a device that appears in `system_profiler` but never reaches the VM.

### 1b. Which UTM backend?

USB passthrough of a Wi-Fi adapter to a **Linux** guest is historically a
**QEMU-backend** feature. If you built the VM as "Virtualize" with the Apple
Virtualization backend, you likely had no way to attach the RTL8188EUS at all.
(Apple-backend USB passthrough via private macOS-15 framework APIs was only
*merged into UTM in Feb 2026* — new, macOS-15+, and not what a stable 2.4 GHz
lab should depend on yet.)

**Check your backend** (UTM GUI): select the VM ▸ **Edit** ▸ top of settings
shows **"Emulate"/"Virtualize"** and the backend. For aarch64 you want:

- **System ▸ Architecture:** `ARM64 (aarch64)`
- Backend: **QEMU** (NOT Apple Virtualization) — this is the one that exposes
  the **USB** settings pane, the live USB toolbar menu, and `utmctl usb`.

If you are on the Apple backend, the quickest fix is to **rebuild the VM on the
QEMU backend** and move the disk, rather than fight the Apple USB path.

**Enable USB in the QEMU VM** (UTM ▸ Edit ▸ **QEMU** / **USB**):

- **USB Support:** **USB 3.0 (XHCI)** *or* **USB 2.0 (EHCI)**.
  - Start with **USB 2.0 (EHCI)** for a 2.4 GHz dongle — the RTL8188EUS is a
    USB 2.0 device, EHCI re-enumerates more predictably, and the known-good
    Apple-Silicon passthrough reports run over EHCI/UHCI companion controllers,
    not XHCI. Move to USB 3 only if a device needs the bandwidth.
- **USB Sharing / "Share USB devices…":** enabled, and bump **"USB Devices"**
  count ≥ 1 so there's a free slot to attach into.
- Leave **"USB device auto-connect"** OFF so a reboot doesn't grab the radio
  before Kali is ready — connect it manually (§3) when you want it.

---

## 2. The master decision tree ("my adapter vanished")

Run these **in order**. Each step tells you which seam failed.

```
A. macOS gatekeeper allowing it?                          → §1a (Accessories setting)
B. On the QEMU backend with USB enabled?                  → §1b
C. Does macOS still hold the device? (host claimed it)    → system_profiler SPUSBDataType
D. Is it attached to the VM?                              → utmctl usb list  /  UTM USB menu
E. Does the GUEST see it on the bus?                      → lsusb   (expect 0bda:8179)
F. Did the kernel bind a driver?                          → dmesg | tail ; lsmod | grep 818
G. Is there a wlanX interface?                            → ip link ; iw dev
H. Did monitor mode / a driver reload drop it?            → §5, §6
```

### C. Does macOS still hold the device? (host side)

On the Mac host:

```bash
# See the adapter from macOS's point of view (it appears here BEFORE you pass it)
system_profiler SPUSBDataType | grep -A8 -i '0bda\|realtek\|802.11'
ioreg -p IOUSB -l -w 0 | grep -i -A3 'realtek\|8188\|idVendor'
```

If the device shows here but **not** in the guest, the problem is the *physical
or virtual path* (macOS gatekeeper, backend, controller, hub, cable) — **not a
Kali driver**. Chase §1/§5/§6, not §4. The clean rig: **plug the adapter, then
immediately connect it to the VM** so macOS never settles a vendor kext on it.
Avoid USB hubs — QEMU's own docs say hubs "won't work" for passthrough; plug
**directly** into the Mac, ideally the **same port every time** (location ID
stays stable).

### D. Is it attached to the VM? (`utmctl` — your scriptable control plane)

`utmctl` is UTM's CLI. Full path (alias it):

```bash
# Add to ~/.zshrc so every shell has it:
alias utmctl='/Applications/UTM.app/Contents/MacOS/utmctl'
```

> **Gotcha that wastes hours:** `utmctl` drives UTM via **Apple Events** and
> needs an **active GUI (Aqua) login session** — it does **not** work from a
> plain remote `ssh` shell with no logged-in desktop. If you SSH into the Mac to
> run it, either log in at the console first or run it inside a GUI session
> (e.g. via `launchctl asuser`).

Core commands you will use constantly:

```bash
utmctl list                       # UUIDs, names, running/stopped
utmctl status  "Kali"             # is this VM running?
utmctl start   "Kali"             # boot it
utmctl stop    "Kali"             # graceful ACPI shutdown (guest agent)
utmctl stop    "Kali" --force     # force stop (when ACPI is ignored)
utmctl suspend "Kali"             # pause (RAM kept)
utmctl ip-address "Kali"          # guest IP(s) — great when you forgot the lease
utmctl exec    "Kali" -- id       # run a command in-guest via the QEMU guest agent
```

**USB subcommands (UTM v4.4+ — release note: "You can now use `utmctl usb`
commands to connect and disconnect USB devices from a running VM"):**

```bash
utmctl usb list "Kali"            # devices available + which are connected
utmctl usb connect "Kali" 0bda:8179        # connect by VID:PID (Realtek RTL8188EUS)
utmctl usb connect "Kali" <location-id>    # or by host location ID from the list
utmctl usb disconnect "Kali" <location-id> # hand it back to the host
```

> Argument order and whether `connect` wants **VID:PID** or a **location ID**
> varies by build — **verify on yours** with `utmctl usb --help` and
> `utmctl --help`. Third-party references show `connect` accepting either a
> `VID:PID` (e.g. `046D:C016`) or a location ID, and `disconnect` taking a
> location ID. The VID:PID for this radio is **`0bda:8179`** (Realtek
> RTL8188EUS, as in TP-Link TL-WN722N **v2/v3**). `utmctl usb` is a
> **QEMU-backend-only** capability — it is absent/non-functional on Apple-backend
> VMs.

Equivalent in the **GUI**: the little **USB plug icon** in the running VM
window's toolbar → tick the adapter to attach, untick to detach. A live
attach/detach from this menu is reported to correctly add/remove the device from
a running Linux guest on M1 UTM/QEMU.

### E–G. Inside the Kali guest

```bash
lsusb                              # expect:  Bus 00x Device 00y: ID 0bda:8179 Realtek ...
dmesg | tail -n 40                 # look for rtl8188eu / r8188eu / rtl8xxxu / 8188eu bind + -71/-110 errors
lsmod | grep -E '8188|rtl8xxxu'    # which module grabbed it
ip link                            # is there wlan0 / wlan1 ?
iw dev                             # interface + its current type (managed/monitor)
```

- `lsusb` **shows `0bda:8179`** but **no `wlanX`** → **driver** problem (§4).
- `lsusb` **does not** show it → **passthrough** problem (back to §1/§D, §6).

---

## 3. Fast, reliable attach workflow (the order pros use)

```bash
# ── on macOS host ──
utmctl start "Kali"                       # boot guest FIRST
# wait for Kali to finish booting, THEN:
utmctl usb list "Kali"                    # confirm 0bda:8179 is present & not yet connected
utmctl usb connect "Kali" 0bda:8179       # attach after boot, not before

# ── in Kali guest ──
lsusb | grep 0bda:8179                     # confirm it enumerated
sudo airmon-ng check kill                  # stop NetworkManager/wpa_supplicant that fight monitor mode
sudo airmon-ng start wlan0                 # or the manual iw path in §4
iw dev                                     # verify wlan0mon / type monitor
```

**Why attach *after* boot:** if the device is present during the guest's USB
controller init, a race can leave it half-enumerated (seen in the wild as
"driver loads but no interface appears"). Connecting a already-booted guest is
the most reliable path.

---

## 4. Driver: get `wlan0` to actually appear (RTL8188EUS on Kali)

The RTL8188EUS (`0bda:8179`, as in TP-Link TL-WN722N **v2/v3** — note v1 is an
Atheros AR9271 with a *different* driver) has three candidate drivers and they
conflict:

| Module        | Source                                            | Monitor + injection? |
|---------------|---------------------------------------------------|----------------------|
| `r8188eu`     | in-kernel (staging→mainline)                      | unreliable / no      |
| `rtl8xxxu`    | in-kernel generic Realtek                         | **not** for 8188eus  |
| `8188eu`      | out-of-tree (aircrack-ng / morrownr), Kali DKMS   | **yes**              |

**Install the good driver on Kali (DKMS so it survives kernel upgrades):**

```bash
sudo apt update
sudo apt install -y realtek-rtl8188eus-dkms   # Kali's packaged out-of-tree driver (preferred)
# if the package is unavailable, build from source:
sudo apt install -y bc dkms git build-essential "linux-headers-$(uname -r)"
git clone https://github.com/aircrack-ng/rtl8188eus
cd rtl8188eus
make -j"$(nproc)" && sudo make install
```

**Blacklist the conflicting in-kernel modules:**

```bash
sudo tee /etc/modprobe.d/realtek-wifilab.conf >/dev/null <<'EOF'
blacklist r8188eu
blacklist rtl8xxxu
EOF
sudo depmod -a
```

**Load it cleanly (reboot is the safe default after blacklisting):**

```bash
sudo modprobe -r r8188eu rtl8xxxu 8188eu 2>/dev/null
sudo modprobe 8188eu
dmesg | tail -n 15        # expect 8188eu bind + "rtl8188eu ... wlan0"
```

**Common build failure:** `make` dies with *"No such file or directory ...
/lib/modules/$(uname -r)/build"* → install the matching
`linux-headers-$(uname -r)`. After a Kali kernel upgrade, **DKMS rebuilds
automatically**; a *source* build does not — rebuild it or the module won't load
on the new kernel and `wlan0` silently disappears after reboot. This is why the
DKMS package is strongly preferred in a VM you update often.

**Set monitor mode manually (when `airmon-ng` fights you):**

```bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
iw dev wlan0 info            # confirm "type monitor"
sudo iw dev wlan0 set channel 6
```

Prefer the manual `iw` path over tools that fully *reset* the radio — a reset is
exactly what triggers the §6 re-enumeration drop under passthrough.

---

## 5. "Passthrough drops" — device detaches mid-session

Symptoms: `lsusb` loses `0bda:8179`; `dmesg` shows
`disconnect` / `device descriptor read error -71` / `-110`; interface vanishes.
On Apple-Silicon QEMU this is a **documented pain point** — one upstream report
describes a Wi-Fi adapter that after several re-attaches "stops attaching
entirely" until macOS is rebooted, and another where the RealTek radio enumerates
but is slow and "corrupts data," failing DHCP. Tune the variables below before
concluding the adapter is unsupported.

**Causes & fixes, in likely order:**

1. **USB controller stability.** On XHCI (USB 3), cheap 2.4 GHz dongles glitch.
   **Switch the VM's USB Support to USB 2.0 (EHCI)** (§1b). The known-good
   Apple-Silicon passthrough configs run over EHCI/UHCI, not XHCI. This single
   change fixes the majority of random drops.
2. **A USB reset re-enumerated it and QEMU didn't follow** (sleep, hub power, or
   a driver reload). **Re-attach:** `utmctl usb connect "Kali" 0bda:8179` (or the
   USB toolbar menu). See §6 for the driver-reload case specifically. QEMU's own
   docs note a long-standing relaunch bug: "after relaunching QEMU you may have to
   unplug and plug again the USB device to make it work."
3. **Host sleep / App Nap.** Don't let the Mac sleep during a capture. Hold the
   host awake for as long as QEMU is alive:
   ```bash
   caffeinate -dimsu -w "$(pgrep -n -f QEMU)" &   # -d display -i idle -m disk -s (AC) -u user; -w waits on the PID
   ```
4. **Power / hub.** Remove any USB hub (QEMU: hubs "won't work"); plug the
   adapter directly into the Mac. Underpowered hubs cause `-71` descriptor errors.
5. **Guest-side USB autosuspend** powering the radio down after idle:
   ```bash
   # quick, global, non-persistent:
   echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend
   # per-device right now:
   for f in /sys/bus/usb/devices/*/power/control; do echo on | sudo tee "$f"; done
   ```
   Make it **persistent** so it survives reboot (udev rule keyed to the VID:PID):
   ```bash
   sudo tee /etc/udev/rules.d/70-wifilab-nosuspend.rules >/dev/null <<'EOF'
   ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="0bda", ATTR{idProduct}=="8179", TEST=="power/control", ATTR{power/control}="on"
   EOF
   sudo udevadm control --reload
   ```
   If TLP is installed it can re-enable autosuspend — add the device to
   `USB_DENYLIST` in `/etc/tlp.conf` or stop TLP in the lab VM.
6. **Re-plug recovery from the guest** (soft reset without touching UTM):
   ```bash
   sudo modprobe -r 8188eu && sleep 2 && sudo modprobe 8188eu
   # if the bus handle is wedged, detach+reattach via utmctl from the host instead (§6)
   ```

---

## 6. "Driver reload breaks passthrough" (the classic)

This is the #1 gotcha. Sequence that bites everyone:

```
airmon-ng check kill / modprobe -r 8188eu / plug-cycle
      → device issues a USB reset & re-enumerates
      → it comes back on a NEW host bus/address (hostaddr)
      → QEMU (bound to the old bus/address handle) shows it detached
      → Kali's lsusb no longer lists it
```

**Why it happens (the binding model):** QEMU `usb-host` matches a device **two**
ways —

- `usb-host,hostbus=<bus>,hostaddr=<addr>` — "ad-hoc," the **hostaddr is not
  stable**: a re-plugged / re-enumerated device gets a **new** address and the
  mapping breaks.
- `usb-host,vendorid=0x0bda,productid=0x8179` — matches the **specific device by
  ID and re-attaches it when it reappears**, surviving re-enumeration.

So **binding by VID:PID is what makes passthrough survive a reset.** (Bare QEMU
example: `device_add usb-host,vendorid=0x0bda,productid=0x8179` — IDs are hex,
always `0x`-prefixed.) UTM abstracts this behind the USB menu / `utmctl usb`, so
prefer connecting by **VID:PID** rather than by a transient address.

**The pro workflow that avoids it:**

1. **Do driver work with the device already attached, and avoid plug-cycling.**
   Prefer `sudo iw` to set monitor mode over tools that fully reset the radio.
2. If you must reload the module, expect a detach and **immediately re-attach
   from the host**:
   ```bash
   # host
   utmctl usb disconnect "Kali" 0bda:8179 ; sleep 1 ; utmctl usb connect "Kali" 0bda:8179
   # guest
   lsusb | grep 0bda:8179 && sudo modprobe 8188eu
   ```
3. **Keep the device on the same physical port** so its host location ID is
   stable — then `utmctl usb connect "Kali" <location-id>` is deterministic.
4. **Script the recover-attach** so it's one keystroke (see §10 pro tips).

> Reality check from upstream: passthrough of some Wi-Fi radios on Apple-Silicon
> QEMU is reported as effectively "non-functional" (Atheros AR9271) while others
> partly work (RealTek). The difference is almost always **USB2/EHCI vs
> USB3/XHCI + port/hub stability + binding by VID:PID + the macOS Accessories
> setting**. Exhaust those before buying another adapter.

---

## 7. VM freeze / no-SSH recovery

When Kali hangs (black screen, SSH dead, UTM window unresponsive):

**Step 1 — is it the guest or the whole QEMU process?**

```bash
# host
utmctl status "Kali"          # still "running"?
utmctl ip-address "Kali"      # does the guest agent answer? (if yes, kernel's alive)
utmctl exec "Kali" -- uptime  # can we run anything in-guest?
```

**Step 2 — increasingly firm stops:**

```bash
utmctl stop    "Kali"                 # graceful ACPI shutdown request
# if ignored after ~30s:
utmctl stop    "Kali" --force         # force stop the VM
# last resort — kill the QEMU process:
pgrep -lf 'QEMU.*Kali' ; pgrep -lf QEMULauncher
kill  <pid>        # SIGTERM first
kill -9 <pid>      # only if it won't die
```

**Step 3 — read why it hung:**

```bash
# UTM / QEMU logs via unified logging, plus the per-VM bundle
log show --last 10m --predicate 'process CONTAINS "UTM"' --info 2>/dev/null | tail -n 80
ls -la "$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/"*.utm/   # VM bundle (config + debug log)
```

…and the **serial console** (§8) — if you wired it up *before* the freeze, you
see the kernel panic / last dmesg line directly, which is the difference between
guessing and knowing.

**Step 4 — the ARM64 corruption caveat.** Apple-Silicon QEMU Linux VMs have had
**disk-corruption** bugs (upstream reproduced it with `stress-ng --iomix 4`;
suspected to be partly an aarch64 Linux-kernel issue, seen across QEMU *and*
Apple Hypervisor). Filesystems that checksum (Btrfs) notice it first; ext4 may
silently carry it. After **any** forced kill:

```bash
# in Kali, after it boots again:
sudo dmesg | grep -i -E 'ext4|corrupt|journal|I/O error'
sudo fsck -f /dev/vda1          # from a recovery boot if root is affected
```

**Mitigate up front — storage settings that are reported reliable on Apple
Silicon:**

- Use **NVMe interface with any cache mode**, *or* **VirtIO with "cached"** mode
  for the VM disk (both combinations are reported stable; plain uncached VirtIO
  is where several corruption reports cluster). Set this in UTM ▸ Edit ▸ the
  **Drive**'s **Interface** and the QEMU **cache** option.
- **Snapshot before heavy work**, keep a recent kernel (fixes have landed over
  time), and **shut down gracefully**. Don't run a long capture on a VM you've
  been hard-killing.

---

## 8. Serial console (your lifeline when SSH and GUI are both dead)

A serial console attaches to the guest's kernel console, so you can log in and
read panics even when networking and the graphical console are gone.

**8a. Add the serial device in UTM** (Edit ▸ **Devices** ▸ **New ▸ Serial**):

- **Mode:** *Built-in Terminal* (gives a terminal tab in the UTM window) — or
  *Pseudo-TTY* if you want to attach from the host shell.

**8b. Point Kali's kernel + a login at it.** On aarch64 QEMU `virt`, the serial
port is a **PL011 (AMBA PrimeCell) UART** that Linux exposes as **`ttyAMA0`**.
(On some configs you may also see `ttyS0` or a virtio `hvc0` — confirm with
`dmesg | grep -i tty` and `cat /sys/class/tty/console/active`.)

```bash
# in Kali — add the serial console to the kernel cmdline
sudoedit /etc/default/grub
#   GRUB_CMDLINE_LINUX="console=tty0 console=ttyAMA0,115200"
#   (order matters: the LAST console= is where userspace /dev/console points)
sudo update-grub           # (Debian/Kali) == grub-mkconfig -o /boot/grub/grub.cfg

# start a login prompt on the serial line
sudo systemctl enable --now serial-getty@ttyAMA0.service
sudo reboot
```

> **aarch64 gotcha:** the firmware's **ACPI SPCR** table can auto-route the
> kernel console to the serial port, so you may see boot messages on serial even
> without `console=`. That's fine — but still enable `serial-getty@ttyAMA0`
> explicitly or you get console output with *no login prompt*. systemd only
> auto-spawns a getty on the console named in the kernel args.

**8c. Attach from the host** (Pseudo-TTY mode — UTM shows the `/dev/ttysXXX`
path in the serial device info):

```bash
screen /dev/ttys00X 115200          # or:  minicom -D /dev/ttys00X -b 115200
#   detach screen: Ctrl-a  d        kill: Ctrl-a  k
```

With Built-in Terminal mode you just click the **Serial** tab in the UTM window.
Now a frozen guest still gives you: a login, `dmesg`, `journalctl -k`, and the
exact panic text.

---

## 9. Gotchas & pitfalls (quick-reference)

- **macOS "Allow accessories to connect"** on Apple silicon can silently block a
  new device → set to "Automatically allow when unlocked" (§1a).
- **Apple Virtualization backend** = no reliable Wi-Fi USB passthrough (Apple-
  backend USB only landed in UTM Feb 2026, macOS 15+). Use the **QEMU** backend.
- **`utmctl` needs a GUI login session** (Apple Events) — it fails from a bare
  SSH shell.
- **Attaching the device before the guest boots** → half-enumeration ("driver
  loads, no interface"); attach *after* boot.
- **USB 3 (XHCI)** is flakier than **USB 2 (EHCI)** for 2.4 GHz dongles.
- **USB hubs** → QEMU "won't work" + power errors (`-71`, `-110`). Plug direct.
- **Binding by bus/address** breaks on re-enumeration; **bind by VID:PID**.
- **`airmon-ng` / driver reload** re-enumerates and can drop passthrough — §6.
- **Source-built `8188eu` doesn't survive a kernel upgrade** (use DKMS).
- **`rtl8xxxu` / `r8188eu` not blacklisted** → wrong driver grabs the radio, no
  monitor mode. Check `lsmod`. (And TL-WN722N **v1** is Atheros, not this driver.)
- **USB autosuspend / TLP** powers the radio down → udev rule to force `on` (§5).
- **Mac sleeps / App Nap** mid-capture → device drops. `caffeinate -dimsu -w`.
- **Hard-killing the VM** can corrupt the ARM64 disk — NVMe/virtio-cached +
  snapshot + graceful stop.
- **No serial console configured before a freeze** = you're blind. Wire §8 on
  day one.
- **Changing physical USB ports** changes the location ID → scripts that connect
  by location break. Pin one port.

---

## 10. Pro tips for speed

- **Alias everything** and script the attach so recovery is one command:
  ```bash
  # ~/.zshrc on the Mac host
  alias utmctl='/Applications/UTM.app/Contents/MacOS/utmctl'
  kali-usb() {  # usage: kali-usb on|off|re
    case "$1" in
      on)  utmctl usb connect    "Kali" 0bda:8179 ;;
      off) utmctl usb disconnect "Kali" 0bda:8179 ;;
      re)  utmctl usb disconnect "Kali" 0bda:8179; sleep 1; \
           utmctl usb connect    "Kali" 0bda:8179 ;;      # the re-enumeration fix
    esac
    utmctl usb list "Kali"
  }
  ```
- **Snapshot a known-good state** of Kali (driver installed, blacklist set,
  udev rule in place) so a corrupted or misconfigured VM is a 10-second revert.
- **Pin the adapter to one port** → stable location ID → deterministic scripts.
- **Keep a boot checklist** and automate it with `utmctl exec` once the agent is up:
  ```bash
  utmctl exec "Kali" -- bash -lc 'airmon-ng check kill && ip link set wlan0 down && iw dev wlan0 set type monitor && ip link set wlan0 up && iw dev'
  ```
- **Default to USB 2.0 (EHCI)** for the RTL8188EUS; only reach for USB 3 with a
  device that needs the bandwidth.
- **Watch `dmesg -w`** in a spare Kali pane while you attach — you see the bind
  or the error the instant it happens.
- **Keep `caffeinate` tied to QEMU's PID** so the host can't nap out from under a
  long capture, and release automatically when QEMU exits.

---

## 11. Defense / safe-lab discipline (the "defense" for lab plumbing)

A stable, contained lab *is* the defensive posture here:

- **Authorization first.** Only ever point the radio at your own gear or gear
  you're sanctioned to test. The adapter is allowlist-gated by the broader
  toolkit; the VM plumbing doesn't change that — keep the allowlist in the loop.
- **Isolation.** The Kali VM is a blast radius. Snapshot before each session,
  revert after. Don't run your lab VM as your daily driver.
- **No silent persistence.** Don't auto-connect the USB radio on boot and don't
  leave monitor mode running unattended — attach it deliberately, detach when
  done (`kali-usb off`). Keeping the macOS Accessories setting deliberate (not
  "Always allow" on a shared machine) is itself a close-access-attack defense —
  that setting exists precisely to stop rogue USB accessories.
- **Integrity.** Graceful shutdowns + NVMe/virtio-cached + snapshots defend
  against the ARM64 disk-corruption failure mode, so captured handshakes aren't
  silently corrupted.
- **Reproducibility.** Pin driver versions (DKMS), pin the USB port, script the
  attach — a lab you can rebuild identically is a lab you can trust results from.
- **Detection awareness (carry-over to the attack skills):** monitor-mode
  capture is passive, but the moment you move to active testing the *defensive*
  lesson is that re-enumeration, MAC changes, and injection are all observable —
  the same seams you troubleshoot here are the artifacts a defender would see.

---

## Sources

Sources consulted for this reference (UTM/QEMU behavior, `utmctl usb`,
Apple-Silicon passthrough reports, ARM64 disk corruption, aarch64 serial console,
macOS accessory security, and the RTL8188EUS driver), plus operational knowledge.

**UTM / utmctl**
- UTM `utmctl usb` connect/disconnect introduced in v4.4 — https://docs.getutm.app/updates/v4.4/
- UTM scripting / `utmctl` reference — https://docs.getutm.app/advanced/scripting/
- UTM GitHub discussion #5795 — `utmctl usb` connect/disconnect on a running VM — https://github.com/utmapp/UTM/discussions/5795
- UTM GitHub issue #3778 — USB device sharing settings (passthrough UI) — https://github.com/utmapp/UTM/issues/3778
- UTM GitHub PR #7632 — USB passthrough for the Apple Virtualization backend (macOS 15+, merged Feb 2026) — https://github.com/utmapp/UTM/pull/7632
- Third-party `utmctl` skill reference (usb list/connect/disconnect syntax, backend limits, Apple-Events/SSH note) — https://skillsmp.com/skills/ljagiello-agent-skills-utmapp-skill-md
- Lima PR #1317 — USB devices attach/detach live on M1 UTM/QEMU Linux guest — https://github.com/lima-vm/lima/pull/1317

**QEMU USB passthrough + Apple-Silicon reports**
- QEMU docs — `usb-host` device matching (vendorid/productid vs hostbus/hostaddr), relaunch bug, "hubs won't work" — https://qemu.googlesource.com/qemu/+/refs/tags/v5.2.0-rc0/docs/system/usb.rst
- QEMU GitLab issue #2178 — "USB passthrough on Apple Silicon is unusable" (RTL8187L/AR9271, EHCI/UHCI, lsusb/no-iface/data-corruption, re-attach eventually dies) — https://gitlab.com/qemu-project/qemu/-/issues/2178
- Apple Developer/Community thread 256074704 — enabling USB passthrough for QEMU on Apple Silicon M2 (+ "Allow accessories" host hurdle) — https://discussions.apple.com/thread/256074704
- Parrot Security community — USB Wi-Fi adapter not showing up in UTM (lsusb empty) — https://community.parrotsec.org/t/usb-wifi-adapter-not-showing-up-in-utm/27833
- TrueNAS forum — USB passthrough for a Wi-Fi adapter to a Kali VM (pass the whole controller) — https://www.truenas.com/community/threads/usb-passthrough-for-alfa-awus036axml-wifi-adapter.114770/

**ARM64 disk corruption / cache**
- QEMU GitLab issue #1997 — disk corruption on ARM64 (Apple Silicon) Linux VMs (`stress-ng --iomix 4`) — https://gitlab.com/qemu-project/qemu/-/issues/1997
- UTM GitHub issue #4840 — corruption reports on Apple Silicon — https://github.com/utmapp/UTM/issues/4840
- UTM GitHub PR #5919 / #5869 — NVMe-vs-virtio + cache-mode workarounds (NVMe any cache, or virtio cached, reported reliable) — https://github.com/utmapp/UTM/pull/5919 ; https://github.com/utmapp/UTM/pull/5869
- Proxmox forum — qcow2 risks with `cache=none` (metadata caching volatility) — https://forum.proxmox.com/threads/understanding-qcow2-risks-with-qemu-cache-none-in-proxmox.175933/
- SUSE docs — virtual disk cache modes — https://documentation.suse.com/sles/16.0/html/SLES-virtualization-disk-cache/index.html

**aarch64 serial console**
- Artix Linux QEMU wiki — `virt` PL011 UART = `/dev/ttyAMA0` — https://armtix.artixlinux.org/info/qemu.html
- Lubuntu livecd-rootfs — ARM cloud-image console fix (`console=ttyAMA0` for arm64) — https://git.lubuntu.me/Lubuntu/livecd-rootfs/commit/21321ac018d3771c7536a4cd1295e7eabfc5de54
- Red Hat Bugzilla #1661288 — aarch64 console on ttyAMA0 via ACPI SPCR table — https://bugzilla.redhat.com/show_bug.cgi?id=1661288

**macOS accessory security + RTL8188EUS driver**
- Apple — "Allow USB and other accessories to connect to your Mac" (Restricted Mode, Apple silicon) — https://support.apple.com/en-ge/102282
- Apple deployment guide — manage USB pairing / Restricted Mode — https://support.apple.com/guide/deployment/manage-usb-pairing-depf8a4cb051/web
- Seagate KB — macOS "Allow accessory to connect" options — https://www.seagate.com/support/kb/macos-asking-to-allow-accessory-to-connect/
- aircrack-ng RTL8188EUS driver (8188eu, monitor mode + injection) — https://github.com/aircrack-ng/rtl8188eus
- Kali/community guide — RTL8188EUS / TL-WN722N v2/v3 not detected: driver fixes — https://jonathansblog.co.uk/?p=30363

> Note on method: the shared web-search budget for this research run was
> exhausted mid-sweep (it is pooled across all parallel research agents), so a
> few driver/autosuspend/caffeinate specifics draw on established expert
> knowledge rather than a fresh fetch. Re-verify the exact `utmctl usb` argument
> order and current Apple-backend USB support on *your* installed UTM version
> with `utmctl usb --help`.
