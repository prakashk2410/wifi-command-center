---
name: coding-general
description: >-
  General coding help with the local model — writing, refactoring, debugging, tests, and small scripts via
  aider. Use for any "write/fix/refactor/debug/test this code" request that isn't specifically a website or
  Mac-automation task.
version: 1
updated: 2026-11-15
triggers: [code, refactor, debug, tests, fix bug, aider, script, function, error]
references: [references/CONVENTIONS.md]
status: draft
confidence: medium
---

# CODING-GENERAL

## When to use
Any code task that isn't clearly web-building or mac-automation.

## How
- Launch aider with the local model: `~/local-coder.sh` (inside the repo you're editing). It points at
  `ollama/qwen3-agent` and sets `OLLAMA_CONTEXT_LENGTH=8192`.
- aider uses robust SEARCH/REPLACE edits that work well on local models.
- `references/CONVENTIONS.md` is auto-loaded (it's in `.aider.conf.yml` `read:`) — keep your global code
  preferences there. Per-project rules go in that repo's own `CONVENTIONS.md`.

## Gotchas
- If the model loops or ignores instructions, context is probably truncating — raise `OLLAMA_CONTEXT_LENGTH`.
- Use `/no_think` for routine edits; reserve thinking mode for genuinely hard logic.
