#!/usr/bin/env python3
# webcheck.py - stdlib-only web gate (no node/npx/axe). Python 3.9+.
# Exit 1 with short actionable lines on any defect; exit 0 on clean.
# Scope: files passed as args, else top-level *.html in CWD, excluding *.before.* and *.bak.
import sys, re, glob, datetime, os
from html.parser import HTMLParser
YEAR = datetime.date.today().year
args = [a for a in sys.argv[1:]]
if args:
    files = args
else:
    files = [f for f in glob.glob('*.html') if '.before.' not in f and not f.endswith('.bak')]
errs = []
class P(HTMLParser):
    def __init__(s):
        super().__init__(); s.h1=0; s.has_main=False; s.sec_heading=0
        s._sec=[]; s.buttons=[]; s._form=0; s.hash_links=0; s.empty_mailto=0
    def handle_starttag(s,t,a):
        a=dict(a)
        if t=='h1': s.h1+=1
        if t=='main': s.has_main=True
        if t=='form': s._form+=1
        if t=='section': s._sec.append(False)
        if t in('h2','h3') and s._sec and not s._sec[-1]: s._sec[-1]=True
        if t=='button' and 'onclick' not in a and a.get('type')!='submit' and s._form==0:
            s.buttons.append(a.get('class',a.get('id','<button>')))
        if t=='a':
            h=a.get('href','').strip()
            if h in('#','','javascript:void(0)'): s.hash_links+=1
            if h=='mailto:' or h=='mailto:>': s.empty_mailto+=1
    def handle_endtag(s,t):
        if t=='form' and s._form>0: s._form-=1
        if t=='section' and s._sec and not s._sec.pop(): s.sec_heading+=1
for f in files:
    try: html=open(f,encoding='utf-8').read()
    except Exception as e: errs.append(f'{f}: cannot read ({e})'); continue
    p=P()
    try: p.feed(html)
    except Exception as e: errs.append(f'{f}: parse error ({e})')
    if p.h1!=1: errs.append(f'{f}: found {p.h1} <h1> (need exactly 1)')
    if not p.has_main: errs.append(f'{f}: no <main> landmark')
    if p.sec_heading: errs.append(f'{f}: {p.sec_heading} <section> without an <h2>')
    for b in p.buttons: errs.append(f"{f}: dead <button> '{b}' (no onclick/type=submit/form)")
    if p.hash_links: errs.append(f'{f}: {p.hash_links} dead link href="#"/empty/javascript:void(0)')
    if p.empty_mailto or re.search(r'mailto:[\"\'\s>]', html): errs.append(f'{f}: empty mailto: link')
    for m in re.finditer(r'(?:©|&copy;|copyright)\D{0,15}(19|20)\d{2}', html, re.I):
        yr=int(m.group(0)[-4:])
        if yr!=YEAR: errs.append(f'{f}: stale year {yr} (now {YEAR}); render with new Date().getFullYear()')
    css=' '.join(re.findall(r'<style[^>]*>(.*?)</style>', html, re.S))
    for c in glob.glob('*.css'):
        try: css+=' '+open(c,encoding='utf-8').read()
        except Exception: pass
    if ('<style' in html or glob.glob('*.css')) and ':focus-visible' not in css:
        errs.append(f'{f}: no :focus-visible styles')
if errs:
    print('WEBCHECK FAILED ('+str(len(errs))+'):'); [print('  - '+e) for e in errs]; sys.exit(1)
print('WEBCHECK OK ('+str(len(files))+' file(s))'); sys.exit(0)
