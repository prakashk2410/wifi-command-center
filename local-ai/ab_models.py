#!/usr/bin/env python3
"""
A/B: abliterated qwen3-agent vs qwen3-coder on FIRST-PASS web-build quality (hardened brief, NO repair).
Metric = webcheck defect count on the first generation. Decision rule (from research): switch the coding
driver to the coder only if it beats the abliterated model by >= 1 fewer defect/site averaged, OR a clearly
higher first-pass-clean rate. Runs all specs for one model before switching (avoids reloading 18GB each time).
Run AFTER `ollama pull qwen3-coder:30b`.  Usage: python3 ab_models.py
"""
import json, urllib.request, sys, re, subprocess, os, time, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from webgen import BRIEF, extract  # reuse the exact hardened brief + extractor
HOST = "http://127.0.0.1:11434"
WEBCHECK = os.path.join(HERE, "webcheck.py")

MODELS = [
    {"name": "qwen3-agent",     "opts": {"temperature": 0.6, "top_p": 0.95, "top_k": 20, "num_ctx": 16384}},
    {"name": "qwen3-coder:30b", "opts": {"temperature": 0.7, "top_p": 0.8, "top_k": 20, "repeat_penalty": 1.05, "num_ctx": 16384}},
]
SPECS = [
    {"id": "habit", "brief": "Build a landing page for 'Streak', a habit-tracking app. Dark theme. Sticky header with wordmark + nav (Features, Pricing, Download); a hero with a tagline and a call-to-action; a Features section with 3 feature cards in a responsive grid; a Download section with two store buttons; a footer. All buttons work, accessible, responsive."},
    {"id": "menu",  "brief": "Build a one-page site for 'Olive & Thyme', a small restaurant. Warm dark theme. Header with name + nav (Menu, Hours, Contact); a hero; a Menu section with 6 dishes (name, description, price) in a responsive grid; an Hours section; a Contact section with address and a reservation button; footer. Working controls, accessible, responsive."},
    {"id": "blog",  "brief": "Build a blog index page for 'DevNotes'. Dark theme. Header with name + nav (Home, Tags, About); a hero with the blog title; a Posts section listing 4 post cards (title, date, 1-line excerpt, Read more link) in a responsive grid; a footer. Real links, accessible, responsive."},
]

def model_installed(name):
    try:
        req = urllib.request.Request(HOST + "/api/tags")
        tags = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        names = [m["name"] for m in tags.get("models", [])]
        return any(n == name or n.split(":")[0] == name.split(":")[0] for n in names)
    except Exception:
        return False

def gen(model, opts, task, timeout=900):
    body = {"model": model, "messages": [{"role": "system", "content": BRIEF}, {"role": "user", "content": task}],
            "stream": False, "options": opts}
    req = urllib.request.Request(HOST + "/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    ec, ed = d.get("eval_count", 0) or 0, d.get("eval_duration", 0) or 1
    return extract(d.get("message", {}).get("content", "") or ""), round(ec / (ed / 1e9), 1), round(time.time() - t0, 1)

def defects(html):
    d = tempfile.mkdtemp(prefix="ab_")
    with open(os.path.join(d, "index.html"), "w") as f: f.write(html)
    p = subprocess.run([sys.executable, WEBCHECK, "index.html"], cwd=d, capture_output=True, text=True)
    if p.returncode == 0: return 0, ""
    out = p.stdout.strip()
    m = re.search(r'\((\d+)\)', out)
    return (int(m.group(1)) if m else 1), "; ".join(l.strip(" -") for l in out.splitlines()[1:])

def main():
    print("== A/B first-pass defect count (hardened brief, no repair) ==\n")
    results = {}
    for m in MODELS:
        if not model_installed(m["name"]):
            print(f"!! {m['name']} not installed — skipping.\n"); continue
        print(f"--- {m['name']} ---")
        rows = []
        for s in SPECS:
            try:
                html, ts, wall = gen(m["name"], m["opts"], s["brief"])
                n, detail = defects(html)
            except Exception as e:
                n, detail, ts, wall = -1, f"gen error: {e}", 0, 0
            rows.append((s["id"], n, ts, wall, detail))
            print(f"  {s['id']:<7} defects={n:<2} {ts} tok/s {wall}s" + (f"  [{detail}]" if detail else ""))
        results[m["name"]] = rows
        print()
    # summary
    print("== SUMMARY (mean first-pass defects, lower=better) ==")
    means = {}
    for name, rows in results.items():
        valid = [n for _, n, _, _, _ in rows if n >= 0]
        clean = sum(1 for n in valid if n == 0)
        mean = round(sum(valid) / len(valid), 2) if valid else None
        means[name] = mean
        print(f"  {name:<16} mean={mean}  clean={clean}/{len(valid)}")
    if len(means) == 2:
        a = means.get("qwen3-agent"); c = means.get("qwen3-coder:30b")
        if a is not None and c is not None:
            print("\n== DECISION (rule: switch to coder only if >= 1 fewer defect/site) ==")
            if c <= a - 1:
                print(f"  -> SWITCH coding driver to qwen3-coder ({c} vs {a}, >=1 better).")
            else:
                print(f"  -> KEEP qwen3-agent ({a} vs coder {c}; not >=1 better). Coder stays available for jobs where it helps.")

if __name__ == "__main__":
    main()
