---
name: mac-automation
description: >-
  Automates actions on the user's own Mac — launching apps, AppleScript/JXA, clicking/typing, screenshots —
  and (later) remote "give a command from my phone" triggering. Use when the user wants the agent to DO
  something on the computer or control it remotely. Own machine only; confirm before side-effecting actions.
version: 1
updated: 2026-11-15
triggers: [open app, click, type, applescript, automate, remote control, screenshot, launch]
references: [references/app-recipes.md]
status: draft
confidence: low
---

# MAC-AUTOMATION (Phase 5 — needs installs; do last)

## Plan (not yet installed)
- **Hub:** Goose + MCP extensions — `macos-automator-mcp` (deterministic AppleScript/JXA) + **Peekaboo**
  (screenshot + click/type for GUI gaps). Grant Screen Recording + Accessibility + Automation to the launcher.
- **Model note:** a text-only model can't reliably click screenshots — prefer AppleScript/JXA (deterministic)
  over vision clicking. Keep ≤5 active tools or Qwen3 starts emitting tool-calls as plain text.
- **Remote trigger:** a Telegram bot over a **Tailscale** tailnet (no public ports, ACL locked to your devices);
  `tmux` keeps it alive across disconnects.

## HARD safety rules (when built)
- **Confirm before every side-effecting action.** Never auto-run / `-y` / danger-full-access.
- **Tailscale only** — never port-forward Ollama or a web UI to the public internet.
- A remote command must require an explicit **"reply yes"** round-trip, so a malformed or injected command
  cannot auto-execute. For max isolation, run GUI control inside a VM.

## Note
Open Interpreter's current build is a sandboxed *coding* agent with no GUI mouse/keyboard control — don't rely
on it to "control the Mac." Use Goose + macos-automator/Peekaboo for that.
