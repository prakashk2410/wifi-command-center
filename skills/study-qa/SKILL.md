---
name: study-qa
description: >-
  Answers study and technical questions and clears doubts, at the user's level, with concrete examples.
  Use when the user asks to explain a concept, "what is / how does / why", or is studying for an exam.
version: 1
updated: 2026-11-15
triggers: [explain, what is, how does, why, concept, exam, teach me, doubt]
status: draft
confidence: medium
---

# STUDY-QA

## When to use
"Explain X", "what is / how does / why", clearing a doubt, exam prep.

## How
- Answer at the user's level: short plain explanation first, then a concrete example, then the one thing that
  usually trips people up.
- For big topics, give the shape first (the 3–4 key ideas), then let them pick where to go deep.
- Offer to demo it where possible (code, a command, a diagram) rather than only describing.
- This is a strength of the uncensored general model — no benign over-refusal on edgy-but-legitimate study topics.

## Gotcha
- For agent/tool turns use `/no_think`; but for genuinely hard reasoning (math, tricky logic), thinking mode on is fine.
