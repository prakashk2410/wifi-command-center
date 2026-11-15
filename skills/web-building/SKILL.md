---
name: web-building
description: >-
  Builds and iterates on websites and web apps with the local model — scaffolding, components, styling,
  dev-server preview, and deploy. Use when the user mentions a website, landing page, HTML/CSS, React,
  Next, Vite, a frontend, or deploying a site.
version: 1
updated: 2026-11-15
triggers: [website, landing page, html, css, react, next, vite, frontend, deploy, tailwind]
references:
  - references/deploy-playbook.md
  - references/component-patterns.md
status: draft
confidence: medium
---

# WEB-BUILDING

## When to use
Any "build / fix / style / deploy a website or web app" request.

## Workflow (local-model friendly)
1. **Pick the harness:** aider (now) for repo-aware edits; Cline (once VS Code is installed) for autonomous
   multi-file scaffolding + in-editor browser preview. Drive coding with **Qwen3-Coder** (load on demand) when added.
2. **Pin conventions:** every site repo gets its own `CONVENTIONS.md` / `AGENTS.md` at the root (stack, style,
   folder layout) so the agent follows your rules.
3. **Raise context:** local coding agents go "dumb"/loop when Ollama context defaults to 4096 and silently
   truncates. Use **≥8192 for aider, ~32k for Cline**.
4. **Preview + iterate:** run the dev server; use the browser preview to adjust visually.
5. **Deploy:** keep local, or use managed hosting (this environment also exposes Vercel/Supabase connectors).

## Gotchas (grow this over time)
- Context truncation is the #1 cause of a local coding agent misbehaving — raise `num_ctx` first.
- Use the non-thinking Coder variant for tool/agent loops; thinking mode inflates tokens and can blank out.
