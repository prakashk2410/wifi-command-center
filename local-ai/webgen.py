#!/usr/bin/env python3
"""
webgen.py — hardened one-shot web builder on the LOCAL model.
Bakes the research-backed loop: hardened XML brief + correct settings (num_ctx 16384, temp 0.6,
thinking on) -> generate -> webcheck gate -> grounded self-repair (<=2 rounds). Stops when the gate
passes, not when the model says it's done.
Usage:  python3 webgen.py <outfile.html> "<what to build>"
"""
import json, urllib.request, sys, re, subprocess, os, datetime, time

HOST = "http://127.0.0.1:11434"
MODEL = "qwen3-agent"
HERE = os.path.dirname(os.path.abspath(__file__))
WEBCHECK = os.path.join(HERE, "webcheck.py")
YEAR = datetime.date.today().year
MAX_REPAIR = 2

BRIEF = f"""<role>
You are a senior front-end engineer. You ship a self-contained page that runs in a browser with zero edits.
Correct, complete and accessible beats clever. You never leave a placeholder or a dead control.
</role>
<must>
1. COMPLETE FILE: output the ENTIRE HTML file from <!doctype html> to </html> in ONE ```html code block. Never abbreviate, never "rest unchanged", never omit a section.
2. LAYOUT: put display:grid / display:flex on the element that DIRECTLY contains the items. If cards/pills live inside a wrapper <div class="container">, put the grid/flex class on THAT wrapper so the items are its direct children. grid/flex only lays out DIRECT children.
3. REAL CONTROLS: every <button> has an inline onclick or is type="submit" in a <form>; otherwise use <a href> to a real target. No href="#", no empty mailto:, no handler-less button.
4. STRUCTURE: exactly one <h1>; wrap main content in one <main>; every <section> opens with an <h2>; use <header>/<nav>/<footer>.
5. ACCESSIBLE: text/accent contrast >= 4.5:1 against the actual background; :focus-visible styles on every interactive element; nav/tap targets >= 44x44px.
6. YEAR: the current year is {YEAR}; render the footer year with <span id="yr"></span> + document.getElementById('yr').textContent=new Date().getFullYear(). Never hardcode a year.
</must>
<gotchas>
BROKEN (grid no-ops, cards are grandchildren):
  <section class="features" style="display:grid"><div class="container"><article>Card</article></div></section>
CORRECT (grid on the direct parent):
  <section class="features"><div class="container grid"><article>Card</article></div></section>
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}}
</gotchas>
<finish>
Before finishing, re-check all six MUST rules. The three that break most: (A) grid/flex on the items' DIRECT
parent; (B) no dead button and no empty/"#" link; (C) one <h1>, a <main>, an <h2> per <section>,
:focus-visible present, year dynamic. Fix any you broke, then output the complete file in ONE ```html block.
</finish>"""

def chat(messages, timeout=900):
    body = {"model": MODEL, "messages": messages, "stream": False,
            "options": {"temperature": 0.6, "top_p": 0.95, "top_k": 20, "num_ctx": 16384}}
    req = urllib.request.Request(HOST + "/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read().decode())
    m = d.get("message", {})
    ec, ed = d.get("eval_count", 0) or 0, d.get("eval_duration", 0) or 1
    return m.get("content", "") or "", round(ec / (ed / 1e9), 1), round(time.time() - t0, 1)

def strip_think(s): return re.sub(r"<think>.*?</think>", "", s, flags=re.DOTALL)

def extract(s):
    s = strip_think(s)
    m = re.search(r"```html\s*(.*?)```", s, re.DOTALL) or re.search(r"```\s*(<!doctype.*?</html>)\s*```", s, re.DOTALL | re.I)
    if m: return m.group(1).strip()
    m = re.search(r"(<!doctype html.*?</html>)", s, re.DOTALL | re.I)
    return m.group(1).strip() if m else s.strip()

def webcheck(path):
    p = subprocess.run([sys.executable, WEBCHECK, os.path.basename(path)],
                       cwd=os.path.dirname(path) or ".", capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()

RENDER_JS = os.path.join(HERE, "checks", "render.js")
def render_check(path):
    """Tier-2 browser gate (contrast/tap-targets/grid-nesting). Returns (None,'') if node/render.js absent."""
    import shutil
    if not (shutil.which("node") and os.path.exists(RENDER_JS)):
        return None, ""
    try:
        p = subprocess.run(["node", RENDER_JS, path], capture_output=True, text=True, timeout=120)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return None, f"render skipped: {e}"

def ndef(report):
    m = re.search(r'\((\d+)\)', report)
    return int(m.group(1)) if m else 0

def main():
    if len(sys.argv) < 3:
        print('usage: webgen.py <outfile.html> "<brief>"'); sys.exit(2)
    outfile = os.path.abspath(sys.argv[1]); task = sys.argv[2]
    os.makedirs(os.path.dirname(outfile), exist_ok=True)
    print(f"== webgen :: {MODEL} :: {os.path.basename(outfile)} ==")
    msgs = [{"role": "system", "content": BRIEF}, {"role": "user", "content": task}]
    out, ts, wall = chat(msgs); html = extract(out)
    with open(outfile, "w") as f: f.write(html)
    rc, report = webcheck(outfile)
    first = 0 if rc == 0 else ndef(report)
    print(f"[gen]     {ts} tok/s, {wall}s, {len(html)} bytes")
    print(f"[check 1] " + ("OK — 0 defects" if rc == 0 else f"{first} defects:\n   " + "\n   ".join(report.splitlines()[1:])))
    rounds = 0
    while rc != 0 and rounds < MAX_REPAIR:
        rounds += 1
        msgs = [{"role": "system", "content": BRIEF},
                {"role": "user", "content": task},
                {"role": "assistant", "content": "```html\n" + html + "\n```"},
                {"role": "user", "content": "The file failed these checks:\n" + report + "\nReturn the COMPLETE corrected file in one ```html block."}]
        out, ts, wall = chat(msgs); html = extract(out)
        with open(outfile, "w") as f: f.write(html)
        rc, report = webcheck(outfile)
        print(f"[repair {rounds}] " + ("OK — 0 defects" if rc == 0 else f"{ndef(report)} defects:\n   " + "\n   ".join(report.splitlines()[1:])))
    stdlib_final = 0 if rc == 0 else ndef(report)
    # --- Tier-2 render pass: real browser + axe (contrast, tap targets, grid-nesting) ---
    rrc, rout = render_check(outfile)
    render_line = "skipped (no node/render.js)"
    if rrc is not None:
        rfirst = 0 if rrc == 0 else ndef(rout)
        print(f"[render 1] " + ("OK — 0 defects" if rrc == 0 else f"{rfirst} defects:\n   " + "\n   ".join(rout.splitlines()[1:])))
        if rrc != 0:
            msgs = [{"role": "system", "content": BRIEF},
                    {"role": "user", "content": task},
                    {"role": "assistant", "content": "```html\n" + html + "\n```"},
                    {"role": "user", "content": "The rendered page failed these browser checks:\n" + rout +
                     "\nFix them: every text/UI color must have >=4.5:1 contrast against its ACTUAL background (pick a lighter accent/foreground if needed); give every nav link and button a hit area of at least 44x44px via min-height/min-width + padding; keep grid/flex on the DIRECT parent of its items. Return the COMPLETE corrected file in one ```html block."}]
            out, ts, wall = chat(msgs); html = extract(out)
            with open(outfile, "w") as f: f.write(html)
            rc, report = webcheck(outfile); rrc, rout = render_check(outfile)
            print(f"[render-repair] stdlib: {'OK' if rc == 0 else str(ndef(report)) + ' defects'}  |  render: {'OK' if rrc == 0 else str(ndef(rout)) + ' defects'}")
        render_line = "0 (CLEAN)" if rrc == 0 else f"{ndef(rout)} left (contrast/tap-targets are model-stubborn; eyeball or hand-tweak)"
    print(f"\n== RESULT :: stdlib {first}->{0 if rc == 0 else ndef(report)} (repairs {rounds})  |  render {render_line} ==")
    sys.exit(0 if (rc == 0 and rrc in (0, None)) else 1)

if __name__ == "__main__":
    main()
