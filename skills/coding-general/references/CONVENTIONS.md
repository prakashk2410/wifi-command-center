# CONVENTIONS — global coding preferences (auto-loaded by aider)

> Edit this to match how YOU like code. It's read into every aider session (and is a good base to copy into
> each project's own CONVENTIONS.md). Keep it short — long conventions eat context.

## Defaults (customize these)
- Prefer clear, readable code over clever one-liners. Small functions.
- Comment the *why*, not the *what*. No comment spam.
- Match the existing style of the file/project you're editing before imposing new style.
- Don't add dependencies without saying so and why.
- When unsure about intent, ask one short question instead of guessing on something hard to undo.

## Languages (fill in your preferences)
- Python: type hints on public functions; f-strings; `ruff`/`black` style if present.
- JS/TS: modern ES modules; prefer TypeScript for new web code; no unused vars.
- Shell: `set -euo pipefail` in scripts; quote variables.

## Testing
- Add/adjust tests when changing behavior. State plainly if you skipped tests and why.

## Safety
- Never hardcode secrets/keys. Read them from env or a local untracked file.
- Before deleting or overwriting a file, say what will be lost.
