// Tier-2 render gate — catches what the stdlib webcheck cannot: color contrast + landmarks (axe-core),
// grid/flex applied to the wrong element (the cards are grandchildren), and <44px tap targets.
// Usage:  node render.js <url-or-file>      exit 1 on any defect, 0 on clean.
const path = require('path');
const { chromium } = require('playwright');
const { AxeBuilder } = require('@axe-core/playwright');

(async () => {
  const target = process.argv[2];
  if (!target) { console.error('usage: node render.js <url|file.html>'); process.exit(2); }
  const url = target.startsWith('http') ? target : 'file://' + path.resolve(target);
  const errs = [];
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({ viewport: { width: 1200, height: 900 } });
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'networkidle', timeout: 20000 });

    // (1) axe-core: contrast, landmarks, names, etc.
    const res = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
    for (const v of res.violations) errs.push(`axe[${v.impact}] ${v.id}: ${v.help} (${v.nodes.length} node${v.nodes.length > 1 ? 's' : ''})`);

    // (2) grid/flex on the wrong element — items are grandchildren of the grid/flex box
    const gridBugs = await page.evaluate(() => {
      const out = [];
      for (const el of document.querySelectorAll('body *')) {
        const d = getComputedStyle(el).display;
        if (d !== 'grid' && d !== 'flex') continue;
        const kids = [...el.children];
        if (kids.length === 1) {
          const only = kids[0];
          if (/container|wrapper|inner|row|content|grid|flex/i.test(only.className || '') && only.children.length > 1) {
            out.push(`<${el.tagName.toLowerCase()} class="${el.className}"> is display:${d} but its ONLY child .${(only.className || '').split(' ')[0]} holds ${only.children.length} items — the grid/flex lays out the wrapper, not the items (they're grandchildren).`);
          }
        }
      }
      return out;
    });
    errs.push(...gridBugs);

    // (3) tap targets < 44px on primary interactive elements
    const small = await page.evaluate(() => {
      const out = [];
      for (const el of document.querySelectorAll('nav a, header a, button, .btn, [role=button]')) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.height > 0 && (r.width < 44 || r.height < 44)) {
          out.push(`tap target <${el.tagName.toLowerCase()}> "${(el.textContent || '').trim().slice(0, 24)}" is ${Math.round(r.width)}x${Math.round(r.height)}px (< 44px)`);
        }
      }
      return out;
    });
    errs.push(...small);
  } catch (e) {
    errs.push('render error: ' + e.message);
  } finally {
    await browser.close();
  }

  if (errs.length) { console.log(`RENDERCHECK FAILED (${errs.length}):`); errs.forEach(e => console.log('  - ' + e)); process.exit(1); }
  console.log('RENDERCHECK OK'); process.exit(0);
})();
