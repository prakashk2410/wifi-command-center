# Local AI — Setup (offline, pick by RAM)

The dashboard can be run by a **local LLM** through [Ollama](https://ollama.com) — it operates the tools and explains each step. 100% offline, no cloud, no accounts.

## 1. Install Ollama
Download from **https://ollama.com** (macOS / Linux / Windows). It runs a local server at `http://localhost:11434`.

## 2. Pick a model for your RAM
Ollama loads one model at a time — match it to your RAM:

| RAM | Model | Pull command | Notes |
|---|---|---|---|
| **4 GB** | Llama 3.2 3B | `ollama pull llama3.2:3b` | smallest; basic chat, weak at tool-use |
| **6–8 GB** | Qwen2.5-Coder 7B | `ollama pull qwen2.5-coder:7b` | great coding, light |
| **16 GB** | Qwen2.5-Coder 14B | `ollama pull qwen2.5-coder:14b` | stronger reasoning |
| **24–32 GB** | Qwen3 30B-A3B (MoE) | `ollama pull qwen3:30b-a3b` | fast MoE (~3B active), strong |
| **36 GB+** | Uncensored 30B (abliterated) | `ollama pull huihui_ai/qwen3-abliterated:30b` | low-refusal — see note ↓ |

**About the 36 GB+ / uncensored option:** an *abliterated* build has its refusal guardrails removed, so it answers freely. Publisher: **https://huggingface.co/huihui-ai** (also on Ollama as `huihui_ai/qwen3-abliterated:30b`). Fewer guardrails means **you** are fully responsible for how you use it — keep it legal and ethical.

## 3. Speed tuning (any Ollama; `local-ai/tune-ollama-speed.sh` does it on a Mac)
Set these, then restart Ollama:
```
OLLAMA_FLASH_ATTENTION=1
OLLAMA_KV_CACHE_TYPE=q8_0
OLLAMA_CONTEXT_LENGTH=16384
OLLAMA_KEEP_ALIVE=5m
```
On Qwen3 models, add `/no_think` to routine prompts — "thinking" mode can 5–10× the tokens.

## 4. Skill tree (so the agent doesn't forget)
`skills/` is a markdown "memory" the agent loads:
- **`skills/INDEX.md`** — the trunk; one row per skill, always in context.
- **`skills/SKILL-ROUTINE.md`** — how the agent captures / promotes / prunes skills over time.
- **`skills/<topic>/SKILL.md`** — one branch per topic (`wifi-audit`, `coding-general`, …).

Point your agent (or its system prompt) at `skills/INDEX.md`; it reads only the branch whose trigger words match the task. After it learns something durable, it appends to that branch — so knowledge **compounds** instead of resetting each session.

## 5. Drive it
- **Chat (like ChatGPT):** any Ollama chat app — Ollama's own app, Chatbox, or Open WebUI.
- **Coding (edits files):** `aider --model ollama/<model>`, or Cline in VS Code.
- **This dashboard:** the backend talks to Ollama directly (`command-center/ai/operating-prompt.md` + `tool-schemas.json`) — the model calls the Wi-Fi tools and narrates in plain English.

Everything stays on your machine.
