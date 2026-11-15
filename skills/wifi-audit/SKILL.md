---
name: wifi-audit
description: >-
  Operates the authorized local Wi-Fi audit Command Center (scan, capture, crack, deauth, WPS, PMKID,
  triage, doctor) and teaches each play with its one-line defense. Use when the user mentions Wi-Fi,
  handshakes, cracking, the Command Center, Kali, or the audit console. Authorized / own-gear targets only.
version: 3
updated: 2026-11-15
triggers: [wifi, handshake, crack, deauth, wps, pmkid, command center, kali, scan, audit]
references:
  - ../../wifi-lab/command-center/SKILL.md
  - ../../wifi-lab/command-center/SKILL-MASTER.md
  - ../../wifi-lab/command-center/TROUBLESHOOTER-KB.md
status: stable
confidence: high
---

# WIFI-AUDIT (branch points to the live tool — nothing was moved)

The full operating brain already exists and is maintained in the Command Center. Do **not** duplicate it here —
read it in place:

- **Operating brain / front door:** `wifi-lab/command-center/SKILL.md`
  (hard rules, 4-phase workflow, all tools, crack tiers + masks, self-heal table, backend/allowlist mechanics)
- **Deep attack reference:** `wifi-lab/command-center/SKILL-MASTER.md`
- **Secondary quick-ref:** `wifi-lab/command-center/SKILL-wifi-attacks.md`
- **Troubleshooter KB:** `wifi-lab/command-center/TROUBLESHOOTER-KB.md`
- **Runtime system prompt:** `wifi-lab/command-center/ai/operating-prompt.md` · **Tool schemas:** `.../ai/tool-schemas.json`
- **Scripts (RUN, don't read):** `wifi-lab/` (crack-mac.sh, wifi-scan.sh, grab.sh, fix-adapter.sh …)

**Core invariant:** the allowlist `wifi-lab/authorized-targets.txt` gates every attack — only networks the
user is authorized to test (own gear / sanctioned competition). That's about not touching other people's
networks, and it's exactly how the user already operates.
