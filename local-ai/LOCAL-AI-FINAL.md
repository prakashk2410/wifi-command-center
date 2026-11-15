# LOCAL AI — FINALIZED (2026-11-15)

One tuned, uncensored, **local** model that builds, debugs, and self-checks websites on your Mac — measured, not vibes.

## The model (settled)
**`qwen3-agent`** — abliterated Qwen3-30B-A3B (MoE, ~3.3B active, Q4_K_M, ~18 GB). One model, RAM-safe on 36 GB.
A/B-tested against `qwen3-coder:30b` and **won** (0.33 vs 1.5 first-pass defects), so it stays the coding driver.
Speed ~44–52 tok/s. Tuned: Flash-Attention + q8 KV + `num_ctx 16384` (the fix that stopped mid-build truncation).

## How to use it
- **One-shot a clean page (recommended):**
  ```bash
  cd "websites" && python3 webgen.py "mysite/index.html" "Build a … page: …"
  ```
  → generates with the hardened brief → runs **both gates** → auto-repairs → writes a page that passes structure *and* a real browser render. Preview: `python3 -m http.server 8899` then open `localhost:8899/mysite/`.
- **Interactive coding in a repo:** `~/local-coder.sh` (aider, now `ollama_chat/` + the tuned model-settings). 
- **In VS Code:** Cline → provider Ollama, model `qwen3-agent`, context 32768, auto-approve off.

## The two quality gates
1. **`websites/webcheck.py`** (stdlib, instant): one `<h1>`, a `<main>`, `<h2>` per section, no dead buttons/empty links, no stale year, `:focus-visible`.
2. **`websites/checks/render.js`** (headless Chromium + axe): color contrast, grid/flex-on-wrong-element, <44px tap targets — the things only a real render catches. Run standalone: `node websites/checks/render.js http://localhost:8899/mysite/`.

## Measured results
- First-pass structural defects: **2–7 (before) → 0.33 (after hardening)**.
- Full pipeline: fresh pages come out **clean on both gates** (e.g. `websites/launch/`).
- Reliability: tool-calling **10/10 (100%)**, instruction-following 8/10, gate-refusal 1/1.
- Capability: builds a **Sudoku solver** one-shot; **self-debugs** a broken parser in one round.
- Benchmarks are re-runnable: `bench/reliability.py`, `bench/stress.py`, `bench/retry_parser.py`, `websites/ab_models.py`.

## Memory that grows
`skills/` — a markdown skill tree (INDEX + branches: wifi-audit, web-building, mac-automation, coding-general, study-qa) that compounds via `skills/SKILL-ROUTINE.md` so the agent doesn't forget.

## Honest limits
- Color contrast + 44px targets are the model's stubborn spots — the render gate catches them and the repair round usually fixes them, but a must-be-perfect page may need a one-line accent/min-height tweak.
- `qwen3-coder:30b` (18 GB) is installed but **unused** (A/B said keep the agent) — `ollama rm qwen3-coder:30b` to reclaim the space, or keep it for other jobs.
- Mac remote-control (Goose + Tailscale) is still a future phase — not built.

## Boundaries (unchanged)
The model is yours and uncensored for the benign bulk — coding, websites, study, the authorized Wi-Fi console. The two things that stay off the table regardless of model: a client-luring evil-twin credential harvester and a router password-exfiltration backdoor.
