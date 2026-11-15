# Wi-Fi Lab — Setup (Kali VM + adapter)

The "radio" runs in a **Kali Linux VM** with a USB Wi-Fi adapter that supports **monitor mode + injection**. Your host runs the dashboard and the GPU cracker.

## 1. Kali VM
- Install a virtualizer (UTM on macOS, or VirtualBox/VMware) and a Kali Linux image.
- Networking: give it an address your host can reach. This project uses `192.168.64.2`.

## 2. USB Wi-Fi adapter
- Use a chipset that supports **monitor mode + packet injection** (e.g. RTL8188EUS, Atheros AR9271, RTL8812AU).
- Pass it through to the Kali VM (UTM: *USB Devices → connect*).

## 3. Passwordless SSH (host → Kali)
```bash
ssh-copy-id kali@192.168.64.2     # one-time; afterwards key auth, no password
```
The backend SSHes to Kali to run the radio scripts in `command-center/kali-scripts/` and `scripts/`.

## 4. Monitor mode
```bash
sudo airmon-ng check kill
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```
The dashboard's **Adapter Doctor** automates this and recovers a wedged adapter (soft reset → USB re-plug → VM bounce) — never `modprobe` a passed-through USB adapter.

## 5. Cracking (on the host GPU)
Cracking runs on your host with **hashcat** (mode 22000) — much faster than the VM's CPU. `scripts/crack-mac.sh` is tiered: weak-pins → wordlists → masks. See the script header for where to place wordlists.

## 6. Run
```bash
cd command-center/backend
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8787
```
Open **http://localhost:8787**, add **your own** targets in the Targets panel, and go. Nothing runs against a BSSID that isn't on your allowlist.
