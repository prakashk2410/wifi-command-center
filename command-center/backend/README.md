# Wi-Fi Command Center — Backend (FastAPI)

A **100% local, authorized-only** Wi-Fi audit console backend. It wires together the three
pieces of the lab and puts a hard allowlist gate in front of every attack:

```
  Browser UI (../ui)  ──HTTP + WebSocket──▶  THIS BACKEND (Mac, :8787)
                                               │   ├── SSH ──▶ Kali VM (192.168.64.2) ── TP-Link RTL8188EUS (2.4GHz monitor)
                                               │   ├── local  ─▶ Mac GPU crack (hashcat Metal, crack-mac.sh)
                                               │   └── HTTP ──▶ Ollama :11434 /v1 (qwen3-agent)  ← natural-language driver
```

**Mac is the controller + GPU cracker + UI host. Kali is the radio. The Mac GPU cracks.**

---

## The safety model (do not weaken)

1. **The allowlist gates every attack.** `authorized-targets.txt` is the *only* thing that
   decides what may be attacked. `actions.run_action()` is the single choke point: any action
   that names a BSSID (`capture_handshake`, `deauth`, `wps`, `pmkid`) is **hard-refused**
   (`GATE=REFUSED`) before it runs if that BSSID is not on the list. The file is re-read on
   every call — remove a line and it's instantly off-limits. Matching is case-insensitive and
   ignores `#` lines (identical to the shell gate in `wifi-audit.sh`).
2. **No credential harvesting, ever.** There is no fake-login / captive-portal / evil-twin
   password capture anywhere in this backend. `rogue_detect` is a passive **detector** that
   flags possible SSID/BSSID twins and captures nothing.
3. **The AI drives, it does not authorize.** By default the local model may call the 8 gated
   actions but **cannot** write the allowlist (`authorize` is filtered out of its toolset).
   Authorization stays a human action — set `WIFI_ALLOW_AI_AUTHORIZE=1` only if you accept
   that tradeoff. Either way the file gate still applies.
4. **Loopback only.** The server binds `127.0.0.1`. Never expose it on a routable interface.

---

## Prerequisites

- **Kali VM** reachable at `ssh kali@192.168.64.2` with **key auth** and **passwordless sudo**,
  and the proven scripts present in `/home/kali/`: `wifi-scan.sh`, `grab.sh`, `fix-adapter.sh`
  (plus `aircrack-ng`, `aireplay-ng`, and — for the composed modules — `reaver`/`wash` and
  `hcxdumptool`).
- **Mac** has `hashcat` (Metal) + `hcxtools` for `crack-mac.sh`, and `utmctl` on PATH for the
  Doctor's VM/USB self-heal.
- **Ollama** running locally with the `qwen3-agent` model pulled (for `/ai`): `ollama serve`.
- **Python 3.9+**.

The lab path (note the space) and script/allowlist locations are taken from the existing lab by
default and are all environment-overridable (see **Configuration**).

---

## Run

```bash
cd "/Users/macbook/Ai agent /wifi-lab/command-center/backend"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8787 --reload
```

Then open **http://localhost:8787** (served from `../ui`). `python3 app.py` also works.

---

## Configuration (environment variables)

| Var | Default | Meaning |
|---|---|---|
| `WIFI_LAB_DIR` | `/Users/macbook/Ai agent /wifi-lab` | lab root (holds `crack-mac.sh`, wordlists) |
| `WIFI_AUTH_FILE` | `<lab>/authorized-targets.txt` | the allowlist |
| `WIFI_CAP_DIR` | `~/wifi-lab-captures` | where captures are pulled to on the Mac |
| `WIFI_KALI_HOST` | `kali@192.168.64.2` | SSH target |
| `WIFI_KALI_SCRIPT_DIR` | `/home/kali` | where the `.sh` live on Kali |
| `WIFI_IFACE` | `wlan0` | monitor interface in Kali |
| `WIFI_USB_ID` | `2357:010C` | TP-Link USB id (Doctor hard reset) |
| `WIFI_VM_NAME` | `Kali` | UTM VM name (Doctor VM bounce) |
| `OLLAMA_URL` | `http://localhost:11434` | local model endpoint |
| `OLLAMA_MODEL` | `qwen3-agent` | model name |
| `WIFI_ALLOW_AI_AUTHORIZE` | `0` | `1` lets the AI write the allowlist (off by design) |
| `WIFI_UI_DIR` | `../ui` | static UI folder |
| `WIFI_BIND` / `WIFI_PORT` | `127.0.0.1` / `8787` | bind address / port (for `python3 app.py`) |

---

## API contract (for the UI / `app.js`)

### REST
| Method · Path | Body | Returns |
|---|---|---|
| `GET /health` | — | liveness + `{kali_reachable, ollama_model, allowlist_count, last_scan_count, ai_can_authorize}` |
| `GET /actions` | — | `{actions:[{name,gated}]}` |
| `GET /allowlist` | — | `{count, allowlist:[{bssid,label}]}` |
| `POST /allowlist/add` | `{bssid, label?}` | `{ok, added, bssid}` |
| `POST /allowlist/add_from_scan` | `{index?}` or `{bssid?}` | `{ok, added, bssid}` |
| `POST /allowlist/authorize_all_scanned` | `{confirm:true}` | `{ok, added:[...], count}` |
| `POST /action/{name}` | action params | `{ok, logs:[...], result:{...}}` (non-streaming) |
| `POST /ai` | `{prompt}` | `{ok, logs:[...], reply, ai_text:[...], executed:[...]}` |

### WebSocket `/ws` (preferred — live stream + STOP)

Send:
```json
{"type":"run","action":"scan","params":{}}
{"type":"run","action":"capture_handshake","params":{"bssid":"AA:BB:CC:DD:EE:FF","channel":6}}
{"type":"run","action":"deauth","params":{"bssid":"AA:BB:CC:DD:EE:FF","mode":"targeted","client":"11:22:33:44:55:66","duration":20}}
{"type":"ai","prompt":"scan the band, then capture and crack #2 at level 1"}
{"type":"stop"}
```
Receive:
```json
{"type":"log","line":"..."}                         // streamed stdout/status
{"type":"ai","text":"..."}                          // model's reply text
{"type":"result","action":"scan","result":{...}}    // final structured result of a run
{"type":"ai_done","reply":"...","executed":[...]}   // end of an AI turn
{"type":"error","message":"..."}
```

### Action params & results

| Action | Params | Result highlights |
|---|---|---|
| `scan` | — | `{count, aps:[{idx,bssid,channel,power,clients,essid,authorized}]}` |
| `capture_handshake` *(gated)* | `bssid`, `channel?` | `{status:HANDSHAKE_CAPTURED\|NO_HANDSHAKE\|AP_NOT_FOUND, capfile?}` |
| `crack` | `level(1-3)`, `capfile?` | `{cracked, password?, level}` (Mac GPU) |
| `deauth` *(gated)* | `bssid`, `mode(targeted\|broadcast)`, `client?`, `count?`, `duration?` | `{mode,count,duration}` (bounded, STOP-able) |
| `wps` *(gated)* | `bssid`, `channel?`, `method(pixie\|pin)` | `{found, pin?, psk?}` |
| `pmkid` *(gated)* | `bssid`, `channel?`, `seconds?(<=75)` | `{captured, capfile?}` |
| `rogue_detect` | `ssid`, `seconds?` | `{findings:[{essid,bssids,severity:"possible",why}]}` (detector only) |
| `doctor` | `level(auto\|soft\|hard\|vm)` | `{status:{vm,wlan0,monitor,injection,band,aps}}` (feeds the HUD chips) |

---

## How the actions map to the lab

- `scan` → `ssh kali 'sudo bash /home/kali/wifi-scan.sh'` (passive; parses `BSSID|CH|PWR|CLIENTS|ESSID`).
- `capture_handshake` → `ssh kali 'sudo bash /home/kali/grab.sh <BSSID> [CH]'`, then `scp` the `.cap` to the Mac.
- `crack` → **local** `bash crack-mac.sh [cap] [level]` (hashcat Metal, tiered).
- `doctor` → `ssh kali 'sudo bash /home/kali/fix-adapter.sh'` + Mac-side `utmctl` USB re-plug / VM bounce.
- `deauth` / `wps` / `pmkid` have no dedicated script yet, so they are **composed inline** in
  `actions.py` from the same standard Kali tools (`aireplay-ng` / `wash`+`reaver` / `hcxdumptool`),
  bounded by `timeout` and behind the identical gate. **`hcxdumptool` flags vary by version** — the
  PMKID command is intentionally the one version-sensitive spot; adjust its flags if your installed
  `hcxdumptool` differs.
- `rogue_detect` reuses the passive scan as its sensor and reports SSID/BSSID collisions as *possible*
  twins. No gate (it attacks nothing).

## Self-heal built in (matches the proven facts)

`doctor` escalates **soft reset → Mac-side USB re-plug (`utmctl usb disconnect/connect 2357:010C`) →
VM bounce (`utmctl stop/start Kali` + SSH poll)**, and **never** `modprobe`s the passed-through
adapter. Captures are time-bounded (`pmkid` hard-capped at 75s) so airodump doesn't throw "Aborted".
On a scan returning 0 APs the log points you straight at the Doctor and notes a missing AP is almost
always 5/6 GHz (this adapter is 2.4-only).

---

*Authorized testing only. The allowlist gates everything; there is no credential harvester, by design.*
