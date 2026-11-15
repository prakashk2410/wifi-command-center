# TROUBLESHOOTER-KB.md — Wi-Fi Command Center "Self-Heal / Doctor"

> **What this is.** A single, exhaustive **error-signature → cause → exact-fix → retry** knowledge base
> for the 100% local Wi-Fi Command Center. It is the brain the local AI (qwen3-agent) consults the
> moment any step fails, so the rig **self-heals with no human help**. Every fix below is a literal,
> copy-pasteable command. The proven self-heal facts (verified on this exact rig) are folded in
> **verbatim** and flagged **[PROVEN]**.
>
> **Authorized-use boundary (unchanged).** This whole stack is for **authorized testing only** — own
> gear / sanctioned competition / learning. The `authorized-targets.txt` allowlist gates **every** active
> transmit (scan-to-capture, deauth, WPS, PMKID). Nothing off-list is touched. The evil-twin area stays a
> **detector + concept only** — no fake-login/captive-portal that harvests real people's passwords. This
> troubleshooter only keeps the lab *equipment* working; it does not widen that boundary.

---

## Architecture recap (who runs what — read this once)

| Role | Host | How the AI reaches it | Key facts |
|---|---|---|---|
| **Controller** | the Mac | local shell | runs `crack-mac.sh`, `utmctl`, orchestration, the UI |
| **Radio** | Kali VM `192.168.64.2` (user `kali`, **passwordless sudo**) | `ssh kali@192.168.64.2 '...'` | runs `wifi-scan.sh`, `grab.sh`, `fix-adapter.sh`; iface `wlan0` |
| **Cracker (GPU)** | the Mac (hashcat **Metal**, ~**185k H/s** WPA2, mode **22000**) | local | never crack inside the VM — it is ~1000× slower |
| **Adapter** | TP-Link **RTL8188EUS**, USB id **`2357:010C`**, driver **`rtl8xxxu`**, **2.4 GHz only**, monitor via `fix-adapter.sh` | USB passthrough into Kali | **NEVER `modprobe`** it — reload drops passthrough |
| **Local model** | Ollama `http://localhost:11434` (OpenAI `/v1`), single model **`qwen3-agent`** | HTTP | the UI must call `/v1` |
| **UI** | `http://127.0.0.1:8787` | browser | local-only bind |

**Radio scripts live on Kali at `/home/kali/` and are invoked from the Mac over SSH**, e.g.
`ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'`. `crack-mac.sh` runs on the Mac.
Paths under `"/Users/macbook/Ai agent /wifi-lab"` contain a **space** — always quote them.

---

## 1. GOLDEN RULES — the proven self-heal facts **[PROVEN, verbatim]**

These were verified on this rig (notably 2026-11-12) and override any guess:

1. **adapter hung / 0 APs → `fix-adapter.sh`** (SOFT monitor reset: `ip link down → set monitor → up`).
2. **`wlan0` gone or wedged → Mac-side USB re-plug:**
   `utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C`
3. **VM down / no SSH → `utmctl stop Kali; sleep 3; utmctl start Kali`**, then **poll SSH ~15–30 s**.
4. **airodump "Aborted" under long load → keep every capture < ~75 s.**
5. **No handshake → a client device must be connected to the target** (else use clientless PMKID).
6. **Target invisible → it is almost certainly on 5 GHz** (the RTL8188EUS is 2.4-only). Not a crack failure.
7. **NEVER `modprobe` / reload the driver on the passed-through USB adapter — it drops the device.**
   A driver reload disconnects the USB device from the guest; recovery is the Mac-side re-attach in rule 2.
   `fix-adapter.sh` deliberately does a **soft** reset (no driver reload) for exactly this reason.

---

## 2. QUICK SELF-HEAL DECISION ORDER (what the Doctor tries, top-to-bottom)

```
0 APs / adapter hung .............. fix-adapter.sh                       (A1,A2,A6)
wlan0 gone / wedged ............... utmctl usb disconnect/connect 2357:010C  (A3)
no SSH / VM down .................. utmctl stop+start Kali, poll 15–30s   (B1,B2,B5)
airodump "Aborted" ................ shorten every capture to <75s         (D1)
no handshake ...................... ensure a client is connected; else PMKID (D2,G1)
deauth has no effect .............. target enforces 802.11w/PMF → go PMKID (G3)
target invisible .................. it's 5GHz; RTL8188EUS is 2.4-only     (A5,G2)
hashcat slow / no device .......... run on the MAC (Metal), not the VM; add -O (F2,F6)
───────────────────────────────────────────────────────────────────────────────
GOLDEN RULE: never modprobe/reload the driver on the passthrough adapter. (A7)
```

**One-shot recovery ladder** (safe to run top-to-bottom; each rung is harmless if not needed):

```bash
# [Mac] 1. is the VM even up?
utmctl status Kali                                  # want: started
# [Mac] 2. can we reach it?
ssh -o ConnectTimeout=6 kali@192.168.64.2 'echo ssh-ok && iw dev | awk "/Interface/{print \$2}"'
# [Mac] 3. VM unreachable → bounce it, then poll
utmctl stop Kali; sleep 3; utmctl start Kali
for i in $(seq 1 15); do ssh -o ConnectTimeout=4 kali@192.168.64.2 'echo up' 2>/dev/null && break; sleep 2; done
# [Mac→Kali] 4. reachable but wlan0 hung → soft reset
ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'   # prints ADAPTER_RESET_DONE on success
# [Mac] 5. still no wlan0 (script exit 2/4) → hard USB re-plug, then soft reset again
utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'
```

---

## 3. QUICK-LOOKUP INDEX (symptom → entry)

**Adapter / driver (A)** — `fixed channel -1` **A1** · 0 APs **A2** · `wlan0` missing **A3** · `Operation not supported (-95)` **A4** · AP never appears **A5** · worked-yesterday-gone-today **A6** · never-modprobe **A7**
**UTM / VM (B)** — timeout / `No route to host` **B1** · `Connection refused` **B2** · adapter absent after boot **B3** · slow under load **B4** · VM frozen **B5** · status/list **B6**
**SSH / transport (C)** — `Host key verification failed` **C1** · `Permission denied (publickey,password)` **C2** · `sudo: a password is required` **C3** · `Pseudo-terminal will not be allocated` **C4** · `Write failed: Broken pipe` **C5** · keepalive/tmux **C6**
**aircrack / airodump (D)** — `Aborted` **D1** · no handshake captured **D2** · `fixed channel -1` mid-capture **D3** · aireplay `No such BSSID available` **D4** · `No valid WPA handshakes found` (partial EAPOL) **D5** · verify a handshake is real **D6**
**hcxdumptool / hcxtools (E)** — `Handshake extraction failed` / empty `.22000` **E1** · no record / FT-PSK / WPA3 **E2** · `failed to read packet` **E3** · hcxdumptool captures nothing **E4** · empty PMKID (old tool) **E5** · **hcxdumptool VM / virtual-iface warning E6** · version-mismatch silent drop **E7**
**hashcat / Metal (F)** — `No hashes loaded` **F1** · `No devices found/left` **F2** · OOM / `Not enough allocatable device memory` **F3** · `Separator unmatched` / `Token length exception` **F4** · `Exhausted` no crack **F5** · far below 185k H/s **F6** · `-m 5500` rejects MSCHAPv2 **F7** · **`best64.rule` bug in `crack-mac.sh` F8** · resume a stopped job **F9**
**Capture logic (G)** — no client → PMKID **G1** · 5GHz invisible **G2** · MFP/802.11w defeats deauth **G3** · WPA3-SAE reality **G4**
**Shell / bash (H)** — `syntax error near unexpected token 'fi'/'done'` **H1** · `unexpected end of file` **H2** · `command not found` on a spaced path **H3** · `No such file or directory` writing output **H4** · `too many arguments` / `unary operator expected` **H5** · `Permission denied` running a script **H6** · `bad interpreter: /bin/bash^M` **H7** · `set -e` / pipefail aborts **H8**
**Python (I)** — `IndentationError` **I1** · `SyntaxError: invalid syntax` **I2** · `ModuleNotFoundError` **I3** · planted-module hijack **I4** · model JSON won't parse **I5** · `UnicodeDecodeError` on a `.cap` **I6**
**UI / local model (J)** — `Address already in use` :8787 **J1** · no live data from model **J2** · model JSON in fences **J3** · Ollama refused / model missing **J4**

---

## A. TP-Link RTL8188EUS adapter / `rtl8xxxu` driver

### A1 — `fixed channel wlan0: -1` (or `-1` in airodump's CH column)
- **SYMPTOM:** airodump-ng top bar shows `fixed channel wlan0: -1`; CH column is `-1`; scan/capture produces nothing.
- **CAUSE:** `wlan0` never actually entered monitor mode, or NetworkManager / wpa_supplicant keeps retuning the interface.
- **FIX:**
  ```bash
  # [Mac→Kali] confirm current type, then kill the daemons fighting it, then soft-reset
  ssh kali@192.168.64.2 'iw dev wlan0 info'                 # look for "type monitor"
  ssh kali@192.168.64.2 'sudo airmon-ng check kill'         # stop NetworkManager/wpa_supplicant
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'   # down → set monitor → up (no reload)
  ```
- **RETRY:** re-run the scan: `ssh kali@192.168.64.2 'sudo bash /home/kali/wifi-scan.sh'`. If CH is a real number, proceed.

### A2 — scan returns **0 APs** though known APs are nearby  **[PROVEN]**
- **SYMPTOM:** `wifi-scan.sh` prints no `BSSID|CH|PWR|CLIENTS|ESSID` lines; `grab.sh` → `RESULT=AP_NOT_FOUND`.
- **CAUSE:** adapter hung, or the channel was never locked (flaky `rtl8xxxu` after load/sleep).
- **FIX:**
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'        # first try: soft reset
  # still 0 APs? hard USB re-plug from the Mac, then soft-reset again
  utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'
  ```
- **RETRY:** `ssh kali@192.168.64.2 'sudo bash /home/kali/wifi-scan.sh'`. If still empty and a target is expected, suspect **5 GHz** → **A5/G2**.

### A3 — `wlan0` **missing** from `ip link` / `iw dev` entirely  **[PROVEN]**
- **SYMPTOM:** `iw dev` shows no interface; `fix-adapter.sh` prints `[!] no wlan interface — the USB adapter dropped from the VM.` and exits **2**.
- **CAUSE:** USB passthrough dropped (host sleep, a driver event, or — the classic mistake — someone `modprobe`'d the driver). See **A7**.
- **FIX (Mac-side re-attach — the only thing that brings it back):**
  ```bash
  utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
  ssh kali@192.168.64.2 'iw dev'                             # wlan0 should be back
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'   # put it back in monitor
  ```
- **RETRY:** confirm `iw dev` lists `wlan0`, then resume the scan/capture. If it is *still* gone, bounce the VM (**B5**).

### A4 — `command failed: Operation not supported (-95)` setting monitor / injection unreliable
- **SYMPTOM:** `iw dev wlan0 set type monitor` → `command failed: Operation not supported (-95)`; or aireplay injection is flaky.
- **CAUSE:** wrong/stock driver loaded (`r8188eu`/`8188eu`) instead of in-kernel `rtl8xxxu`, **or** NetworkManager is fighting for the iface.
- **FIX:**
  ```bash
  ssh kali@192.168.64.2 'sudo airmon-ng check kill'         # stop the fighters FIRST
  ssh kali@192.168.64.2 'sudo ip link set wlan0 down; sudo iw dev wlan0 set type monitor; sudo ip link set wlan0 up'
  ssh kali@192.168.64.2 'iw dev wlan0 info'                 # verify "type monitor"
  ```
  Prefer the in-kernel **`rtl8xxxu`** (modern kernels do monitor mode). **DO NOT** rebuild or `modprobe` an external driver on the passthrough adapter (**A7**).
- **RETRY:** re-run the capture. Persisting `-95` with the right driver usually means the iface is still managed → repeat `airmon-ng check kill`, then `fix-adapter.sh`.

### A5 — target AP **never appears** in any scan  **[PROVEN]**
- **SYMPTOM:** a known/expected SSID is absent from `wifi-scan.sh` output across all 2.4 GHz channels.
- **CAUSE:** it is almost certainly on **5 GHz / 6 GHz**. The RTL8188EUS is **2.4 GHz only** — this is a *capture* limit, not a crack failure.
- **FIX / decision:**
  ```bash
  # A dual-band SSID usually also has a 2.4GHz BSSID — capture THAT one:
  ssh kali@192.168.64.2 'sudo bash /home/kali/wifi-scan.sh' | grep -i "<ESSID>"
  ```
  If the SSID is 5 GHz-only, **report "likely 5 GHz, out of adapter range"** and stop — do not loop retries.
- **RETRY:** none for a 5 GHz-only target (physics). Re-scan only if you suspect the AP was simply off/asleep.

### A6 — monitor mode "**worked yesterday, gone today**"
- **SYMPTOM:** everything was fine; after long uptime or a host sleep the adapter no longer captures.
- **CAUSE:** adapter/USB state wedged after extended uptime or sleep.
- **FIX (escalate in order):**
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'                        # 1 soft reset
  utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C        # 2 USB re-plug
  utmctl stop Kali; sleep 3; utmctl start Kali                                       # 3 VM bounce (last resort)
  ```
- **RETRY:** after each rung, `ssh kali@192.168.64.2 'sudo bash /home/kali/wifi-scan.sh'`; stop at the first that works.

### A7 — **GOLDEN RULE: never `modprobe` the passthrough adapter**  **[PROVEN]**
- **SYMPTOM (what it causes):** right after a `modprobe -r rtl8xxxu` / `modprobe rtl8xxxu` (or r8188eu), `wlan0` **vanishes** from the VM (→ A3).
- **CAUSE:** reloading the driver disconnects the USB device from the guest; the guest cannot re-enumerate it on its own.
- **FIX:** don't do it. For a hung adapter use the **soft** reset (`fix-adapter.sh`: `ip link down → iw set monitor → up`). If the driver truly must be reset, do the **Mac-side USB re-plug** (A3) instead of `modprobe`.
- **RETRY:** if a `modprobe` already happened → run the A3 re-attach, then `fix-adapter.sh`.

---

## B. UTM VM / Kali availability

### B1 — SSH **times out** / `No route to host`  **[PROVEN]**
- **SYMPTOM:** `ssh: connect to host 192.168.64.2 port 22: Operation timed out` **or** `... No route to host`.
- **CAUSE:** VM is down, suspended, or its network isn't up yet.
- **FIX:**
  ```bash
  utmctl status Kali                       # if not "started":
  utmctl stop Kali; sleep 3; utmctl start Kali
  for i in $(seq 1 15); do ssh -o ConnectTimeout=4 kali@192.168.64.2 'echo up' 2>/dev/null && break; sleep 2; done
  ```
- **RETRY:** once `echo up` prints, reissue the original SSH command. Poll **15–30 s** before declaring failure.

### B2 — SSH `Connection refused` (host answers, port closed)
- **SYMPTOM:** `ssh: connect to host 192.168.64.2 port 22: Connection refused` (fast, not a timeout).
- **CAUSE:** VM is up but `sshd` hasn't finished starting after boot.
- **FIX:**
  ```bash
  utmctl status Kali                       # expect "started"
  for i in $(seq 1 15); do ssh -o ConnectTimeout=4 kali@192.168.64.2 'echo up' 2>/dev/null && break; sleep 2; done
  ```
- **RETRY:** keep polling 15–30 s. If `sshd` never comes up, bounce the VM (**B5**) and poll again.

### B3 — VM up but the **USB adapter is absent** after boot
- **SYMPTOM:** SSH works, but `iw dev` lists no `wlan0`.
- **CAUSE:** the adapter wasn't attached to this VM session.
- **FIX:**
  ```bash
  utmctl usb connect Kali 2357:010C        # attach it; if that errors, disconnect first:
  utmctl usb disconnect 2357:010C; sleep 3; utmctl usb connect Kali 2357:010C
  ssh kali@192.168.64.2 'iw dev && sudo bash /home/kali/fix-adapter.sh'
  ```
- **RETRY:** confirm `wlan0` present and in monitor, then scan.

### B4 — commands succeed but are **extremely slow / time out** under load
- **SYMPTOM:** SSH commands stall; captures lag; general sluggishness.
- **CAUSE:** VM CPU is saturated by a long capture or overlapping heavy jobs.
- **FIX:** keep each capture **< ~75 s** (**D1**); don't overlap heavy jobs; **crack on the Mac, not the VM**. Pipeline instead of serialize: the moment a handshake/PMKID lands, `scp` it to the Mac and crack there while Kali hunts the next target.
- **RETRY:** re-issue the command once the capture window closes.

### B5 — VM **frozen / unresponsive** (console black, no SSH, no progress)
- **SYMPTOM:** neither SSH nor the UTM console respond.
- **CAUSE:** guest hang.
- **FIX:**
  ```bash
  utmctl stop Kali; sleep 3; utmctl start Kali
  for i in $(seq 1 20); do ssh -o ConnectTimeout=4 kali@192.168.64.2 'echo up' 2>/dev/null && break; sleep 2; done
  ssh kali@192.168.64.2 'iw dev'           # re-attach USB (B3) if wlan0 missing
  ```
- **RETRY:** after `echo up`, re-attach the adapter if needed, then resume.

### B6 — handy VM status / inventory
```bash
utmctl list                 # all VMs + states
utmctl status Kali          # just Kali
utmctl usb list Kali        # USB devices attached to the VM (confirm 2357:010C present)
```

---

## C. SSH / shell transport

### C1 — `Host key verification failed` after a VM rebuild
- **SYMPTOM:** `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` / `Host key verification failed.`
- **CAUSE:** `known_hosts` entry no longer matches (VM was rebuilt / re-imaged). **Lab host only.**
- **FIX:**
  ```bash
  ssh-keygen -R 192.168.64.2               # drop the stale key (safe for this lab host)
  ssh kali@192.168.64.2 'echo ok'          # accept the new key on reconnect
  ```
- **RETRY:** reissue the command. (On a *public* host this warning means a real MITM — but 192.168.64.2 is your own VM.)

### C2 — `Permission denied (publickey,password)`
- **SYMPTOM:** login rejected.
- **CAUSE:** key not installed, wrong user, or wrong identity file.
- **FIX:** the user is **`kali`** (passwordless sudo). Install the controller's pubkey or point at the right key:
  ```bash
  ssh-copy-id kali@192.168.64.2            # or: ssh -i ~/.ssh/<id> kali@192.168.64.2
  ```
- **RETRY:** `ssh kali@192.168.64.2 'echo ok'`.

### C3 — `sudo: a password is required`
- **SYMPTOM:** a `sudo` command over SSH prompts/for a password and fails non-interactively.
- **CAUSE:** the passwordless-sudo rule (`NOPASSWD` for `kali`) is missing or broken.
- **FIX:** expected config is `NOPASSWD` for `kali`. Repair from the **UTM console** (not over the blocked SSH):
  ```bash
  # in the VM console: echo 'kali ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/kali && sudo chmod 440 /etc/sudoers.d/kali
  ```
  Don't block the whole pipeline on this — most radio commands still work; fix it out of band.
- **RETRY:** `ssh kali@192.168.64.2 'sudo true && echo sudo-ok'`.

### C4 — `Pseudo-terminal will not be allocated` / a curses tool misbehaves over SSH
- **SYMPTOM:** airodump's live UI or another TUI renders wrong / won't run over `ssh host 'cmd'`.
- **CAUSE:** non-interactive SSH has no PTY.
- **FIX:** add `-tt` to force a PTY:
  ```bash
  ssh -tt kali@192.168.64.2 'sudo airodump-ng -c 6 --bssid <BSSID> wlan0'
  ```
  (The project scripts avoid this by writing CSV and polling files instead of driving the TUI.)
- **RETRY:** rerun with `-tt`.

### C5 — `Write failed: Broken pipe` mid-capture / mid-crack
- **SYMPTOM:** a long SSH job dies with `Write failed: Broken pipe` or `client_loop: send disconnect`.
- **CAUSE:** the SSH stream went idle/dropped during a long run.
- **FIX:** run long jobs **detached** and poll the output file rather than holding the stream:
  ```bash
  ssh kali@192.168.64.2 'nohup sudo bash /home/kali/grab.sh <BSSID> >/tmp/grab.log 2>&1 &'
  ssh kali@192.168.64.2 'tail -n 20 /tmp/grab.log'      # poll
  # or wrap in tmux:  ssh -tt kali@192.168.64.2 'tmux new -As cap "sudo bash /home/kali/grab.sh <BSSID>"'
  ```
- **RETRY:** reconnect and `tail` the log / re-attach the tmux session — the job kept running.

### C6 — keep long sessions alive (prevention)
```bash
# add to ~/.ssh/config on the Mac:
Host kali
  HostName 192.168.64.2
  User kali
  ServerAliveInterval 15
  ServerAliveCountMax 4
```
Then `ssh kali '...'`. Prevents idle drops (**C5**).

---

## D. aircrack-ng / airodump-ng / capture

### D1 — airodump prints `Aborted` during a long run  **[PROVEN]**
- **SYMPTOM:** `airodump-ng` dies with `Aborted` (often during sustained captures).
- **CAUSE:** known `rtl8xxxu` instability under sustained load.
- **FIX:** **keep every capture window < ~75 s**; chunk long jobs. This is exactly what the project scripts are tuned around — `wifi-scan.sh` uses `timeout 3` per channel, `grab.sh` uses `timeout 4` to locate + short deauth rounds.
  ```bash
  # bad:  airodump-ng ... (left running for minutes)
  # good: cap in short bursts via grab.sh, repeat as needed
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> [channel]'
  ```
- **RETRY:** re-run `grab.sh`; if it keeps aborting even short, `fix-adapter.sh` then retry.

### D2 — **no handshake captured** even on-target  **[PROVEN]**
- **SYMPTOM:** `grab.sh` → `RESULT=NO_HANDSHAKE clients_seen=[...]`; aircrack shows `0 handshake`.
- **CAUSE #1 (most common):** **no client is associated/active** on the target — there is nothing to deauth, so no 4-way handshake occurs.
- **FIX:**
  ```bash
  # If clients_seen is non-empty, just retry (grab.sh already targeted them):
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> <channel>'
  # If clients_seen is EMPTY → go clientless PMKID (no client needed):
  ssh kali@192.168.64.2 'sudo hcxdumptool -i wlan0 -w /tmp/dump.pcapng -c 1,6,11'   # keep <75s
  ```
  (Allowlisted deauth is only to force a *reconnect* so the handshake is captured — standard authorized tooling.)
- **RETRY:** retry `grab.sh` with a connected client, or crack the PMKID the instant it lands (**E / F**).

### D3 — `fixed channel wlan0: -1` **mid-capture**
- **SYMPTOM:** capture was fine, then CH flips to `-1` and frames stop.
- **CAUSE:** channel-hopping is fighting a channel-locked capture, or monitor mode dropped.
- **FIX:** lock the channel explicitly and confirm monitor:
  ```bash
  ssh kali@192.168.64.2 'sudo iw dev wlan0 set channel <CH>; iw dev wlan0 info'
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'    # if it dropped monitor
  ```
- **RETRY:** re-run `grab.sh <BSSID> <CH>` (pass the channel to skip the flaky scan).

### D4 — aireplay-ng `No such BSSID available` / injection fails
- **SYMPTOM:** `aireplay-ng` → `No such BSSID available.` or `Waiting for beacon frame ... got nothing`.
- **CAUSE:** wrong channel, not actually in monitor, or the BSSID is out of 2.4 GHz range.
- **FIX:**
  ```bash
  ssh kali@192.168.64.2 'sudo iw dev wlan0 set channel <CH>; iw dev wlan0 info'   # right channel + monitor
  ssh kali@192.168.64.2 'sudo bash /home/kali/wifi-scan.sh' | grep -i <BSSID>      # confirm it's on 2.4GHz & its CH
  ```
  If the BSSID isn't in the 2.4 GHz scan → it's 5 GHz (**A5/G2**).
- **RETRY:** rerun the deauth/capture on the confirmed channel.

### D5 — capture file exists but `No valid WPA handshakes found`
- **SYMPTOM:** `aircrack-ng /tmp/cap-01.cap` → `No valid WPA handshakes found`; `hcxpcapngtool` yields an empty `.22000`.
- **CAUSE:** only *partial* EAPOL was captured (missing M1/M2/M3) — the pair isn't crackable.
- **FIX:** recapture with a connected, active client; verify the pair before cracking:
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> <CH>'
  ssh kali@192.168.64.2 'hcxpcapngtool /tmp/cap-01.cap'     # must report an EAPOL MESSAGE PAIR or RSN PMKID
  ```
- **RETRY:** once a valid pair/PMKID is present, convert and crack (**F**).

### D6 — verify a handshake is actually real (do this before burning GPU time)
```bash
ssh kali@192.168.64.2 'aircrack-ng /tmp/cap-01.cap'         # look for "1 handshake"
ssh kali@192.168.64.2 'hcxpcapngtool /tmp/cap-01.cap'       # "EAPOL MESSAGE PAIR" / "RSN PMKID"
```
grab.sh already does this gate (`grep -q "1 handshake"`); only `RESULT=HANDSHAKE_CAPTURED` is worth cracking.

---

## E. hcxdumptool / hcxtools (PMKID + conversion)

### E1 — `hcxpcapngtool`: `Handshake extraction failed` / output `.22000` is empty
- **SYMPTOM:** `hcxpcapngtool -o /tmp/hash.hc22000 <cap>` produces a 0-byte file; `crack-mac.sh` → `[!] no WPA handshake/PMKID found`.
- **CAUSE:** the capture has no usable EAPOL (no M1-with-PMKID and no M2/M3) — AP effectively not in range/active.
- **FIX:** recapture closer, with an active client:
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> <CH>'
  ```
- **RETRY:** re-convert; if still empty, confirm a valid pair with `hcxpcapngtool <cap>` (**D5/D6**).

### E2 — `hcxpcapngtool` produces **no record** / "not valid handshakes"
- **SYMPTOM:** conversion runs but emits nothing usable.
- **CAUSE:** the handshake is **FT-PSK (802.11r)** — which hashcat/john can't use — **or** it's **WPA3-SAE**, which has **no offline PSK-recovery mode at all**.
- **FIX:** target a plain **WPA2-PSK** handshake/PMKID. For WPA3, your only offline opening is **transition mode** (grab the WPA2 material that still exists) — see **G4**. Don't promise a clean-WPA3 crack.
- **RETRY:** recapture a WPA2 pair; if the network is WPA3-only, mark it out of scope for offline cracking.

### E3 — `failed to read packet` / parser errors on the cap
- **SYMPTOM:** `hcxpcapngtool` / aircrack errors like `failed to read packet` or truncated-file complaints.
- **CAUSE:** the pcap was edited / "cleaned" / truncated.
- **FIX:** **never edit or "clean" a dump.** Re-capture and feed the **raw** file straight to the converter:
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> <CH>'    # fresh raw /tmp/cap-01.cap
  ```
- **RETRY:** convert the fresh raw capture.

### E4 — hcxdumptool captures **nothing** on the RTL8188EUS
- **SYMPTOM:** `hcxdumptool` runs but writes an empty pcapng.
- **CAUSE:** monitor not ready, or hcxdumptool fighting NetworkManager; some hcxdumptool builds are picky with this chipset.
- **FIX:**
  ```bash
  ssh kali@192.168.64.2 'sudo airmon-ng check kill && sudo bash /home/kali/fix-adapter.sh'
  # reliable fallback on this rig: capture with airodump (grab.sh) then convert
  ssh kali@192.168.64.2 'sudo bash /home/kali/grab.sh <BSSID> <CH>'
  ```
- **RETRY:** convert the airodump `.cap` with `hcxpcapngtool` — the fallback path is the dependable one here.

### E5 — empty PMKID file from the old `hcxpcaptool`
- **SYMPTOM:** old `hcxpcaptool` yields nothing.
- **CAUSE:** deprecated tool, **or** the AP simply doesn't emit a PMKID.
- **FIX:** use the current **`hcxpcapngtool -o out.22000 in.pcapng`** (mode **22000**). Not every AP sends a PMKID → fall back to a full 4-way handshake (**D2**).
- **RETRY:** re-convert with `hcxpcapngtool`; if no PMKID, capture a handshake instead.

### E6 — **hcxdumptool VM / "virtual interface" warning**
- **SYMPTOM:** hcxdumptool warns about the interface being virtual / not setting monitor on a VM passthrough / refusing to manage the iface.
- **CAUSE:** hcxdumptool trying to own monitor mode on a passthrough/virtual interface (fragile on this rig).
- **FIX:** let **`fix-adapter.sh` own the monitor reset**; don't pass hcxdumptool's own monitor-set flag, and don't run it on a virtual iface. **NEVER `modprobe`** here either (**A7**).
  ```bash
  ssh kali@192.168.64.2 'sudo bash /home/kali/fix-adapter.sh'        # monitor set the proven way
  ssh kali@192.168.64.2 'sudo hcxdumptool -i wlan0 -w /tmp/dump.pcapng -c 1,6,11'   # no monitor flag; <75s
  ```
- **RETRY:** if it still warns/stalls, use the airodump→hcxpcapngtool fallback (**E4**).

### E7 — conversion silently **drops pairs** (version mismatch)
- **SYMPTOM:** a capture you believe is good converts to fewer/no hashes than expected.
- **CAUSE:** `hcxdumptool` and `hcxpcapngtool` are on **different versions**.
- **FIX:** keep the two on the **same version**. Check: `ssh kali@192.168.64.2 'hcxdumptool --version; hcxpcapngtool --version'`. For trusted hcx captures you can also speed cracking with `--nonce-error-corrections=0`.
- **RETRY:** re-convert after aligning versions.

---

## F. hashcat (Mac GPU, Metal — mode 22000)

### F1 — `No hashes loaded`
- **SYMPTOM:** `hashcat ... ` → `No hashes loaded.`
- **CAUSE:** wrong `-m` mode or a malformed hash line.
- **FIX:** WPA PMKID/EAPOL = **`-m 22000`** (not deprecated 2500/16800). MSCHAPv2 = **`-m 5500`** with the full layout (**F7**). Validate the file:
  ```bash
  wc -l /tmp/hash.hc22000 && head -c 120 /tmp/hash.hc22000; echo
  hashcat -m 22000 /tmp/hash.hc22000 --show        # should at least parse
  ```
- **RETRY:** re-run with the correct mode / a clean line.

### F2 — `No devices found/left` / no Metal GPU
- **SYMPTOM:** `No devices found/left.`; or it only lists a CPU.
- **CAUSE:** running hashcat **inside the VM** (no GPU), or the Metal device isn't being selected.
- **FIX:** **crack on the Mac**, never in Kali. List and pin the GPU:
  ```bash
  hashcat -I                                        # confirm a Metal device is present
  hashcat -m 22000 -O -w 3 -d 1 /tmp/hash.hc22000 "/Users/macbook/Ai agent /wifi-lab/rockyou.txt"
  ```
- **RETRY:** re-run on the Mac with `-d 1` (and `-O`, **F6**).

### F3 — `Not enough allocatable device memory` / Metal OOM
- **SYMPTOM:** `Device #1: Not enough allocatable device memory` or an OOM abort.
- **CAUSE:** workload too high for the Mac GPU (big rules + big list at `-w 4`).
- **FIX:** lower workload / shrink the batch:
  ```bash
  hashcat -m 22000 -O -w 2 /tmp/hash.hc22000 <wordlist>    # -w 2 (or 1); fewer/smaller rules; split the list
  ```
- **RETRY:** re-run at `-w 2`; step down to `-w 1` if it recurs.

### F4 — `Separator unmatched` / `Token length exception`
- **SYMPTOM:** `Separator unmatched` or `Token length exception` while loading.
- **CAUSE:** stray whitespace/CRLF, or the wrong field count for the mode.
- **FIX:**
  ```bash
  sed -i '' 's/\r$//' /tmp/hash.hc22000            # strip CR (macOS/BSD sed)
  awk 'NF' /tmp/hash.hc22000 > /tmp/hash.clean && mv /tmp/hash.clean /tmp/hash.hc22000   # drop blank lines
  ```
  One hash per line; for 22000 the line is the `WPA*01*`/`WPA*02*` record from `hcxpcapngtool` (don't hand-edit it).
- **RETRY:** reload; compare against `hashcat --example-hashes -m 22000` if unsure.

### F5 — finishes `Exhausted`, nothing cracked
- **SYMPTOM:** `Status....: Exhausted` with no password.
- **CAUSE:** the password wasn't in that wordlist/mask — not an error.
- **FIX:** escalate tiers (probability-per-second order):
  ```bash
  crack-mac.sh "/tmp/cap-01.cap" 2        # rockyou×rules + 10-digit
  crack-mac.sh "/tmp/cap-01.cap" 3        # SecLists WiFi-WPA + big lists×rules
  # highest real-world yield after numerics — word+year hybrid:
  hashcat -m 22000 -O -w 3 -a 6 /tmp/hash.hc22000 "/Users/macbook/Ai agent /wifi-lab/rockyou.txt" '?d?d?d?d'
  # targeted: seed from the ESSID/owner; small base × heavy rules
  ```
- **RETRY:** run the next tier; keep the shared potfile so nothing re-runs (**F9**).

### F6 — hashcat **far below** the ~185k H/s baseline
- **SYMPTOM:** speed is a fraction of ~185k H/s WPA2.
- **CAUSE:** thermal throttle, `-w` too low, missing `-O`, or (worst) running in the VM.
- **FIX:** run on the **Mac Metal** GPU, add the optimized kernel, raise workload:
  ```bash
  hashcat -m 22000 -O -w 3 /tmp/hash.hc22000 <wordlist>    # -O ~doubles WPA2 on Metal (caps len ~27, fine for real keys)
  ```
  Let the Mac cool between deep runs; use `-w 4` only if you don't need the Mac responsive.
- **RETRY:** re-run with `-O -w 3`; confirm the device line shows the GPU, not the CPU.

### F7 — `-m 5500` rejects your MSCHAPv2 data (enterprise/EAP module)
- **SYMPTOM:** `-m 5500` won't load the pair.
- **CAUSE:** you supplied a bare `challenge:response` instead of the full NetNTLMv1 field layout.
- **FIX:** build the line as **`username::::response:challenge`** (the `hostapd-wpe` "hashcat" log line already prints it this way):
  ```bash
  hashcat -m 5500 /tmp/mschap.txt "/Users/macbook/Ai agent /wifi-lab/rockyou.txt" -r "$(brew --prefix hashcat)/share/hashcat/rules/best66.rule"
  ```
  (Enterprise capture is lab/allowlisted-RADIUS-only — detector + owned-lab tool, never live user phishing.)
- **RETRY:** reload with the correct layout.

### F8 — **BUG in `crack-mac.sh`: `best64.rule` silently no-ops**  **[rig-specific]**
- **SYMPTOM:** level-2/3 "rockyou × rules" tiers appear to run but add nothing; no error.
- **CAUSE:** `crack-mac.sh` references `$RULES/best64.rule` (lines ~51 & ~60), but **hashcat v8 on this box ships `best66.rule`** (best64 was renamed/replaced). The `[ -f "$RULES/best64.rule" ]` guard is false → the rules step is skipped silently. It also omits **`-O`** (**F6**).
- **FIX:** confirm what's installed, then point the script at it:
  ```bash
  ls "$(brew --prefix hashcat)/share/hashcat/rules" | grep -Ei 'best66|top10_2025|d3ad0ne|dive'
  # edit crack-mac.sh: best64.rule → best66.rule  (and add top10_2025.rule as a second rules pass)
  # also add -O to the dict()/mask() hashcat calls for the big Metal speedup
  ```
  Quick manual rules run meanwhile:
  ```bash
  hashcat -m 22000 -O -w 3 /tmp/hash.hc22000 "/Users/macbook/Ai agent /wifi-lab/rockyou.txt" -r "$(brew --prefix hashcat)/share/hashcat/rules/best66.rule"
  ```
- **RETRY:** re-run `crack-mac.sh ... 2` after the edit; the rules tier now fires.

### F9 — resume a stopped / crashed job (and reuse past cracks)
- **SYMPTOM:** a long run was interrupted; you don't want to restart from zero.
- **CAUSE:** no session/potfile persistence by default.
- **FIX:** run deep jobs with a named session + a shared potfile so a crash resumes and every past crack is instant:
  ```bash
  hashcat -m 22000 -O -w 3 --session=rnd1 --potfile-path "/Users/macbook/Ai agent /wifi-lab/shared.potfile" \
    /tmp/hash.hc22000 "/Users/macbook/Ai agent /wifi-lab/rockyou.txt"
  hashcat --session=rnd1 --restore           # resume after a stop/crash
  hashcat -m 22000 /tmp/hash.hc22000 --show  # free wins: already-cracked keys fall out in ms
  ```
- **RETRY:** `--restore`, or just `--show` first on every new capture.

---

## G. Capture logic — no-client / 5 GHz / PMF / WPA3

### G1 — no handshake because **nothing is connected**  **[PROVEN]**
- **SYMPTOM:** target has `CLIENTS=0` in `wifi-scan.sh`; `grab.sh` returns `NO_HANDSHAKE clients_seen=[]`.
- **CAUSE:** a 4-way handshake needs an associated client to deauth; there is none.
- **FIX:** go **clientless PMKID** (single frame, no deauth):
  ```bash
  ssh kali@192.168.64.2 'sudo hcxdumptool -i wlan0 -w /tmp/dump.pcapng -c 1,6,11'   # <75s
  scp kali@192.168.64.2:/tmp/dump.pcapng /tmp/ && hcxpcapngtool -o /tmp/hash.hc22000 /tmp/dump.pcapng
  ```
- **RETRY:** crack the PMKID immediately (**F**); or wait for a client and use `grab.sh`.

### G2 — target invisible = **5 GHz**  **[PROVEN]**
- **SYMPTOM:** expected AP never shows on any 2.4 GHz channel.
- **CAUSE:** it's on 5/6 GHz; RTL8188EUS is 2.4-only.
- **FIX / RETRY:** report "likely 5 GHz, out of adapter range"; capture the 2.4 GHz BSSID of a dual-band SSID if one exists. See **A5**. No retry for 5 GHz-only.

### G3 — deauth has **zero effect** (client stays connected)
- **SYMPTOM:** repeated deauth, the client never drops / re-handshakes.
- **CAUSE:** the target enforces **802.11w / PMF** (WPA3 or hardened WPA2) — it cryptographically rejects classic deauth/disassoc. **This is a positive finding, not a tool failure.**
- **FIX:** stop escalating frames; pivot to clientless **PMKID** (**G1**). Record "target enforces PMF."
- **RETRY:** PMKID path; don't flood deauth (>30 frames/burst is just noise).

### G4 — WPA3-SAE reality (set expectations honestly)
- **SYMPTOM:** a WPA3 network won't yield crackable material.
- **CAUSE:** WPA3-Personal uses SAE (Dragonfly) — **no practical offline PSK crack**; mode 22000 does nothing on clean WPA3.
- **FIX:** your only offline opening is **WPA3 transition mode** (mixed WPA2/WPA3) — capture the WPA2 handshake/PMKID that still exists and crack it normally. (Per 2025 data only ~0.84% of APs are WPA3 at all, mostly transition mode.)
- **RETRY:** if WPA3-only, mark out of scope for offline cracking; the evil-twin/downgrade area is **detector + concept only**.

---

## H. Shell / bash — syntax & code errors (the glue scripts)

### H1 — `syntax error near unexpected token 'fi'` (or `'done'`, `')'`)
- **SYMPTOM:** `script.sh: line N: syntax error near unexpected token 'fi'`.
- **CAUSE:** an `if` missing its `then`, a `for`/`while` missing `do`, or an unbalanced block.
- **FIX:**
  ```bash
  bash -n "/Users/macbook/Ai agent /wifi-lab/<script>.sh"    # syntax-check WITHOUT executing
  ```
  Ensure every `if`→`then`…`fi`, every `for`/`while`→`do`…`done`.
- **RETRY:** re-run after `bash -n` passes clean.

### H2 — `unexpected end of file`
- **SYMPTOM:** `syntax error: unexpected end of file`.
- **CAUSE:** an unclosed quote, here-doc, or brace.
- **FIX:** check for an odd number of quotes; make sure a here-doc terminator (`EOF`) is at **column 0**; `bash -n` to locate.
  ```bash
  grep -n '"' "/Users/macbook/Ai agent /wifi-lab/<script>.sh" | wc -l   # odd count → a quote is unclosed
  ```
- **RETRY:** fix the pair, re-run `bash -n`, then execute.

### H3 — `command not found` for a path with a **space**  **[rig-specific]**
- **SYMPTOM:** `/Users/macbook/Ai: command not found` or `agent: No such file or directory`.
- **CAUSE:** the path `"/Users/macbook/Ai agent /wifi-lab"` was **unquoted** and split on the space.
- **FIX:** always quote the path or the variable:
  ```bash
  LAB="/Users/macbook/Ai agent /wifi-lab"
  ls "$LAB/command-center"                 # quotes are mandatory
  ```
- **RETRY:** re-run with every occurrence quoted.

### H4 — `No such file or directory` writing outputs
- **SYMPTOM:** redirect/`>` into a subdir fails.
- **CAUSE:** the subdir doesn't exist yet.
- **FIX:**
  ```bash
  mkdir -p "/Users/macbook/Ai agent /wifi-lab/command-center/<subdir>"
  ```
- **RETRY:** re-run the write.

### H5 — `[: too many arguments` / `unary operator expected`
- **SYMPTOM:** a `[ ... ]` test errors.
- **CAUSE:** an unquoted variable expanded to empty or multiple words.
- **FIX:** quote all test operands; prefer `[[ ]]` in bash:
  ```bash
  [ "$x" = "y" ]        # not: [ $x = y ]
  [[ -n "$CL" ]]
  ```
- **RETRY:** re-run.

### H6 — `Permission denied` running a script
- **SYMPTOM:** `./script.sh: Permission denied`.
- **CAUSE:** not executable.
- **FIX:**
  ```bash
  chmod +x "/Users/macbook/Ai agent /wifi-lab/<script>.sh"   # or just: bash "<script>.sh"
  ```
- **RETRY:** re-run (via `bash <script>` sidesteps the bit entirely).

### H7 — `bad interpreter: /bin/bash^M`
- **SYMPTOM:** `/bin/bash^M: bad interpreter: No such file or directory`.
- **CAUSE:** the file has Windows CRLF line endings.
- **FIX:**
  ```bash
  sed -i '' 's/\r$//' "/Users/macbook/Ai agent /wifi-lab/<script>.sh"   # macOS/BSD sed
  # (on Kali:  dos2unix /home/kali/<script>.sh )
  ```
- **RETRY:** re-run.

### H8 — script aborts early / silently under `set -euo pipefail`
- **SYMPTOM:** a script using `set -e`/`set -o pipefail` stops at the first non-zero command (the project scripts use `set -uo pipefail`).
- **CAUSE:** a command in a pipe returned non-zero (e.g. a `grep` with no match), aborting the run; or an **unset** variable under `set -u`.
- **FIX:** guard intentional "may-fail" commands and default your vars:
  ```bash
  grep -q foo file || true          # don't let an expected no-match kill the script
  VAR="${1:-}"                      # default to empty under set -u (as grab.sh/crack-mac.sh do)
  bash -x "<script>.sh"             # trace to see exactly where it stops
  ```
- **RETRY:** re-run with the guard / default in place.

---

## I. Python — syntax & code errors

### I1 — `IndentationError: unexpected indent` / `inconsistent use of tabs and spaces`
- **SYMPTOM:** parser rejects the file on indentation.
- **CAUSE:** mixed tabs and spaces.
- **FIX:** use **4 spaces** throughout; pre-check without running:
  ```bash
  python3 -m py_compile the_script.py
  ```
- **RETRY:** re-run after `py_compile` is clean.

### I2 — `SyntaxError: invalid syntax` on f-strings / walrus `:=`
- **SYMPTOM:** modern syntax rejected.
- **CAUSE:** an old interpreter (python2 / stale python3).
- **FIX:** invoke `python3` explicitly. For scripts that read **untrusted downloaded data**, run isolated so a planted local module can't hijack imports:
  ```bash
  python3 -I the_script.py
  ```
- **RETRY:** re-run under `python3`.

### I3 — `ModuleNotFoundError`
- **SYMPTOM:** `ModuleNotFoundError: No module named 'x'`.
- **CAUSE:** wrong venv/interpreter.
- **FIX:** activate the intended venv or use its full interpreter path; install into **that same** env:
  ```bash
  source .venv/bin/activate && pip3 install x      # or: /path/to/venv/bin/python the_script.py
  ```
- **RETRY:** re-run with the correct interpreter.

### I4 — a planted module hijacks `import` (e.g. a local `json.py`)
- **SYMPTOM:** imports behave strangely after handling a downloaded wordlist/capture folder.
- **CAUSE:** Python loads modules from the script's dir and CWD, so a planted `json.py` runs on `import json`.
- **FIX:** keep your scripts in a **different directory** from downloaded data; pass data paths as **arguments**; run with `python3 -I` (isolated) so CWD/`PYTHON*` env can't inject.
- **RETRY:** re-run from a clean dir with `-I`.

### I5 — the local model's JSON output won't parse
- **SYMPTOM:** `json.decoder.JSONDecodeError: Expecting value` when parsing qwen3-agent tool output.
- **CAUSE:** the model wrapped JSON in prose or ```` ```json ```` fences.
- **FIX:** strip fences and extract the first `{...}` block; **validate before acting**, and **never run an allowlist-gated action on unparsed/unvalidated output**:
  ```python
  import re, json
  m = re.search(r'\{.*\}', text, re.S)
  data = json.loads(m.group(0)) if m else None
  ```
- **RETRY:** re-prompt the model for strict JSON if extraction fails.

### I6 — `UnicodeDecodeError` reading a `.cap`/`.pcapng`
- **SYMPTOM:** `UnicodeDecodeError: 'utf-8' codec can't decode byte ...`.
- **CAUSE:** a binary capture was opened in text mode.
- **FIX:** open binary as binary: `open(path, 'rb')`. Don't parse raw captures as text — hand them to `hcxpcapngtool` instead.
- **RETRY:** re-run with `'rb'` (or route through hcxtools).

---

## J. UI / local model (Ollama + port 8787)

### J1 — `Address already in use` binding `127.0.0.1:8787`
- **SYMPTOM:** UI server fails: `EADDRINUSE` / `Address already in use`.
- **CAUSE:** a previous dev server still holds the port.
- **FIX:**
  ```bash
  lsof -i :8787           # find the PID
  kill <PID>              # free it (or pick another port)
  ```
  Bind to **127.0.0.1 only** (local-only, matches the project's design).
- **RETRY:** restart the UI; confirm `http://127.0.0.1:8787` loads.

### J2 — UI loads but shows **no live data** from the model
- **SYMPTOM:** panels empty; model calls hang/fail.
- **CAUSE:** Ollama not reachable / not running.
- **FIX:**
  ```bash
  curl -s http://localhost:11434/v1/models        # should list qwen3-agent
  ollama list                                      # is it pulled?
  ```
  Ensure the UI calls the **OpenAI-compatible `/v1`** endpoint at `localhost:11434`.
- **RETRY:** reload the UI once `/v1/models` responds.

### J3 — JSON parse errors from the model's tool output (UI side)
- **SYMPTOM:** UI throws on the model's response.
- **CAUSE / FIX / RETRY:** same as **I5** — strip ```` ```json ```` fences, extract the first `{...}`, validate before acting, never execute allowlist-gated actions on unparsed output.

### J4 — Ollama **connection refused** / model missing
- **SYMPTOM:** `curl: (7) Failed to connect to localhost port 11434` or an empty `/v1/models`.
- **CAUSE:** `ollama` daemon down, or `qwen3-agent` not pulled.
- **FIX:**
  ```bash
  ollama serve >/tmp/ollama.log 2>&1 &     # start the daemon if down
  ollama pull qwen3-agent                   # ensure the single model is present
  curl -s http://localhost:11434/v1/models
  ```
- **RETRY:** reload the UI (**J2**).

---

## Appendix — reference paths, IDs, and one-shot snippets

**Paths (quote the space):**
```
Lab root ....... "/Users/macbook/Ai agent /wifi-lab"
This KB ........ "/Users/macbook/Ai agent /wifi-lab/command-center/TROUBLESHOOTER-KB.md"
Allowlist ...... "/Users/macbook/Ai agent /wifi-lab/authorized-targets.txt"
Radio scripts .. /home/kali/{fix-adapter,wifi-scan,grab}.sh   (on Kali; run via ssh)
Mac cracker .... "/Users/macbook/Ai agent /wifi-lab/crack-mac.sh"
rockyou ........ "/Users/macbook/Ai agent /wifi-lab/rockyou.txt"
weak pins ...... "/Users/macbook/Ai agent /wifi-lab/weakpins.txt"
SecLists WiFi .. "/Users/macbook/Ai agent /wifi-lab/wordlists-seclists/Passwords/WiFi-WPA/"
hashcat rules .. $(brew --prefix hashcat)/share/hashcat/rules        (use best66.rule, not best64 — see F8)
hash file ...... /tmp/hash.hc22000      capture ... /tmp/cap-01.cap   PMKID ... /tmp/dump.pcapng
```

**IDs / endpoints:**
```
Kali SSH ....... ssh kali@192.168.64.2   (user kali, passwordless sudo)
USB adapter .... 2357:010C   (TP-Link RTL8188EUS, rtl8xxxu, 2.4GHz only)   VM name: Kali
Ollama ......... http://localhost:11434  (OpenAI /v1)   model: qwen3-agent
UI ............. http://127.0.0.1:8787
hashcat ........ -m 22000 -O -w 3 -d 1   (Metal, ~185k H/s WPA2)
```

**Script exit/result signals the Doctor can branch on:**
```
fix-adapter.sh : "ADAPTER_RESET_DONE" (ok) | exit 2 (no wlan iface → USB re-plug) | exit 4 (not monitor → USB re-plug)
grab.sh        : "RESULT=HANDSHAKE_CAPTURED file=/tmp/cap-01.cap" | "RESULT=NO_HANDSHAKE clients_seen=[...]" | "RESULT=AP_NOT_FOUND"
crack-mac.sh   : "PASSWORD: <key>" (cracked) | "NOT cracked at level N — likely a strong password"
```

**Health one-liner (run first when anything looks wrong):**
```bash
utmctl status Kali; \
ssh -o ConnectTimeout=6 kali@192.168.64.2 'echo ssh-ok; iw dev | awk "/Interface/{print \$2}"; iw dev wlan0 info 2>/dev/null | awk "/type/{print \"mode=\"\$2}"'; \
curl -s http://localhost:11434/v1/models >/dev/null && echo ollama-ok || echo ollama-DOWN
```

---

*End of TROUBLESHOOTER-KB. Authorized testing only; the allowlist gates every active transmit; evil-twin stays detector + concept. Equipment self-heal only — never `modprobe` the passthrough adapter; keep captures < ~75 s; crack on the Mac.*
