---
name: skill-routine
description: >-
  The "gardener" meta-skill: how the agent captures, triages, promotes and prunes skills so knowledge
  compounds instead of rotting. Use at the end of a task or session, or whenever something durable was learned.
version: 1
updated: 2026-11-15
status: stable
---

# SKILL-ROUTINE — keep the skill tree alive (curate, don't hoard)

Naive "append everything" libraries re-teach old mistakes. Curate. Five moves:

1. **CAPTURE (mid-task, cheap).** When something works or fails in a non-obvious way, append 3 dated lines to
   `_inbox/NOTES.md`: `{date} | {task} | what worked/failed + the EXACT command or fix`. Never stop the job to do this.

2. **TRIAGE (session end, or when `_inbox` > ~10 lines).** For each inbox note:
   - Fits an existing skill? → **UPDATE** that `SKILL.md` (or its reference).
   - A new capability? → copy a skill template, make a new branch dir, add ONE row to `INDEX.md`.
   - One-off / noise? → delete it.

3. **PROMOTE on repeat.** A lesson seen **≥2–3×**, or one that caused a real failure, graduates from a loose
   reference note into the `SKILL.md` body (or a HARD RULE at its top). Bump `version` + `updated` + `confidence`.

4. **PRUNE / deprecate.** Fix contradicted lines in place and date them. Mark dead skills `status: deprecated`
   rather than deleting history.

5. **KEEP THE TRUNK CHEAP.** `INDEX.md` only ever gains one short row per skill. Never paste skill bodies into it.

## Rules
- A `SKILL.md` stays **< ~500 lines**; overflow goes to `references/` (one level deep only).
- Any reference file > ~100 lines gets a short table-of-contents at the top.
- Front-matter on every skill: `name` (lowercase/hyphens, ≤64 chars, no reserved vendor words),
  `description` (third person, says WHAT + WHEN, ≤1024 chars), plus `version`, `updated`, `triggers`,
  `status`, `confidence`. The `name`+`description` keep files portable to other agent frameworks unchanged.

## Skill template (copy for a new branch)
```
---
name: <slug>
description: >-
  <third-person: what this does and WHEN to use it, with trigger words>
version: 1
updated: <YYYY-MM-DD>
triggers: [<word>, <word>]
references: []
status: draft
confidence: medium
---

# <SKILL NAME>
## When to use
## How (steps / commands)
## Gotchas (promoted from _inbox over time)
## Defense / one-line why (if relevant)
```
