/* =====================================================================
   WI-FI COMMAND CENTER — front-end controller  (vanilla JS, no build)
   ---------------------------------------------------------------------
   Talks to the local backend (FastAPI/Flask) at http://localhost:8787
   and streams the live log over ws://localhost:8787/ws.

   SAFETY MODEL (enforced server-side, mirrored in this UI):
     - Every attack is gated by the authorized-targets allowlist.
     - Buttons that attack require a LOCKED target that is marked OK.
     - Rogue-AP is a DETECTOR only. No credential-capture page exists.

   BACKEND API CONTRACT this UI expects (next build phase implements it):
     GET    /api/health                      -> { ok:true }
     GET    /api/doctor                       -> { vm, wlan0, monitor, injection, band, aps }
     POST   /api/doctor/checks                -> re-run checks, returns same shape
     POST   /api/doctor/reset   {hard:bool}   -> soft (fix-adapter.sh) / hard USB re-attach
     POST   /api/scan                         -> { targets:[{bssid,ch,pwr,clients,essid}] }   (wifi-scan.sh)
     GET    /api/authorized                   -> { list:["AA:BB:..",..] }
     POST   /api/authorize      {bssid,essid} -> add to allowlist
     POST   /api/authorize/all  {confirm,bssids[]} -> authorize current scan
     DELETE /api/authorize      {bssid}       -> de-authorize
     POST   /api/attack/recon   {bssid}
     POST   /api/attack/spoof   {mode:"random"|"restore"}      (own adapter MAC)
     POST   /api/attack/rogue                                  (evil-twin DETECT)
     POST   /api/attack/deauth  {bssid,mode:"one"|"all",seconds}
     POST   /api/attack/stop
     POST   /api/attack/capture {bssid,ch}                     (grab.sh)
     POST   /api/attack/pmkid   {bssid}
     POST   /api/attack/wps     {bssid}
     POST   /api/crack          {level:1|2|3,bssid?}           (crack-mac.sh)
     POST   /api/ai/chat        {message}      -> { reply }    (proxies Ollama /v1)
     WS     /ws                                -> log line stream
   All POST bodies are JSON. The backend is the source of truth for the
   allowlist; this UI only mirrors it.
   ===================================================================== */

'use strict';

const CONFIG = {
  BASE: location.origin.startsWith('http') && location.port === '8787'
        ? location.origin : 'http://localhost:8787',
  get WS(){ return this.BASE.replace(/^http/, 'ws') + '/ws'; },
  DOCTOR_POLL_MS: 30000,
  FETCH_TIMEOUT_MS: 20000,
  SLOW_TIMEOUT_MS: 600000,   // scan ~45s · capture ~75s · AI ~90s · crack can run minutes — give them room
  MAX_LOG_LINES: 600,
};

/* ------------------------------------------------------------------ state */
const state = {
  online: false,
  sim: false,                 // running on fake/offline demo data
  targets: [],                // [{bssid,ch,pwr,clients,essid}]
  authorized: new Set(),      // normalized BSSIDs
  selected: null,             // bssid string
  deauthArmed: false,
  logPaused: false,
  logFilter: '',
  ws: null,
  wsRetry: 0,
  wsPending: null,            // { action, resolve, reject, timer } for an in-flight WS run
};

/* ------------------------------------------------------------------ tiny DOM utils */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const el = (tag, cls, txt) => { const n = document.createElement(tag); if (cls) n.className = cls; if (txt != null) n.textContent = txt; return n; };
const norm = b => (b || '').toUpperCase().trim();
const now  = () => { const d = new Date(); return d.toTimeString().slice(0, 8); };
// Backend doctor fields are status STRINGS ('ok'/'fail'/'skip'/'unknown'); treat only 'ok'
// (or a literal true) as healthy, so 'fail' can never render as UP/green.
const dok  = v => v === true || v === 'ok';
// Infer a log level from a backend log line's prefix/keywords (lines are plain strings).
function inferLevel(line){
  const s = String(line);
  if (/GATE=REFUSED|BLOCKED|\[!\]|\berror\b|\bfailed\b|refus/i.test(s)) return 'err';
  if (/\[\+\]|CRACKED|captured|healthy|recovered|\bsaved\b/i.test(s))   return 'ok';
  if (/\[AI/i.test(s))                                                  return 'ai';
  if (/\bwarn|note:|possible|elapsed\b/i.test(s))                       return 'warn';
  return 'info';
}

/* ------------------------------------------------------------------ toast */
let toastEl, toastT;
function toast(msg, kind){
  if (!toastEl){ toastEl = el('div'); toastEl.id = 'toast'; document.body.appendChild(toastEl); }
  toastEl.className = kind ? kind : '';
  toastEl.textContent = msg;
  requestAnimationFrame(() => toastEl.classList.add('show'));
  clearTimeout(toastT);
  toastT = setTimeout(() => toastEl.classList.remove('show'), 2600);
}

/* ------------------------------------------------------------------ log */
const logBox = $('#log');
function logLine(message, level){
  const line = el('div', 'ln lv-' + (level || 'info'));
  line.appendChild(el('span', 't', now()));
  line.appendChild(el('span', 'm', String(message)));
  if (state.logFilter && !String(message).toLowerCase().includes(state.logFilter)) line.style.display = 'none';
  logBox.appendChild(line);
  while (logBox.childElementCount > CONFIG.MAX_LOG_LINES) logBox.removeChild(logBox.firstChild);
  if (!state.logPaused) logBox.scrollTop = logBox.scrollHeight;
}
function logCmd(c){ logLine(c, 'cmd'); }

/* ------------------------------------------------------------------ fetch helper */
async function api(path, { method = 'GET', body, timeoutMs } = {}){
  // slow radio/AI/crack ops get a long ceiling; fast polls (health/doctor/allowlist) stay snappy
  const SLOW = /\/scan|\/attack\/|\/crack|\/ai\/|\/doctor\/(checks|reset)/.test(path);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs || (SLOW ? CONFIG.SLOW_TIMEOUT_MS : CONFIG.FETCH_TIMEOUT_MS));
  try{
    const res = await fetch(CONFIG.BASE + path, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let data; try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
    if (!res.ok) throw new Error(data && data.error ? data.error : ('HTTP ' + res.status));
    setOnline(true);
    return data;
  } catch (err){
    if (err.name === 'AbortError') throw new Error('timeout');
    setOnline(false);
    throw err;
  } finally { clearTimeout(timer); }
}

/* ------------------------------------------------------------------ connection pill */
const connPill = $('#conn');
function setOnline(on){
  if (on === state.online && !state.sim) return;
  state.online = on;
  if (on){
    state.sim = false;
    connPill.className = 'conn on';  connPill.textContent = '● LINK UP';
  } else {
    connPill.className = 'conn off'; connPill.textContent = '● BACKEND OFFLINE';
  }
}
function setSim(){
  state.sim = true; state.online = false;
  connPill.className = 'conn sim'; connPill.textContent = '◐ SIMULATION (offline)';
}

/* ================================================================== DOCTOR */
const CHIP_TEXT = { vm:'VM', wlan0:'wlan0', monitor:'MON', injection:'INJ', band:'BAND', aps:'APs' };
function chip(k){ return $(`.chip[data-k="${k}"]`); }
function setChip(k, cls, val){
  const c = chip(k); if (!c) return;
  c.className = 'chip ' + cls;
  const i = c.querySelector('i'); if (i) i.textContent = val;
}
function renderDoctor(d){
  setChip('vm',      dok(d.vm)    ? 'ok' : 'bad', dok(d.vm)    ? 'UP'  : 'DOWN');
  setChip('wlan0',   dok(d.wlan0) ? 'ok' : 'bad', dok(d.wlan0) ? 'YES' : 'GONE');
  setChip('monitor', dok(d.monitor) ? 'ok' : 'bad', dok(d.monitor) ? 'ON' : 'OFF');
  // injection is never tested read-only (would require transmitting): ok / unknown / fail.
  const injUnknown = (d.injection == null || d.injection === 'skip' || d.injection === 'unknown');
  setChip('injection', dok(d.injection) ? 'ok' : 'warnc',
          dok(d.injection) ? 'OK' : (injUnknown ? '??' : 'FAIL'));
  setChip('band', 'warnc', d.band || '2.4G');
  const apsNum = Number(d.aps);
  const known  = (d.aps != null && d.aps !== '?' && !Number.isNaN(apsNum));
  setChip('aps', !known ? 'unknown' : (apsNum > 0 ? 'ok' : 'warnc'), known ? String(apsNum) : '—');
}
async function runDoctor(rerun, quiet){
  // quiet = background poll: refresh the chips only, don't spam the LIVE LOG while you read/click.
  // (The periodic poll also SKIPS entirely while a task is in-flight — see boot().)
  if (!quiet) logCmd(rerun ? 'adapter-doctor --run-checks' : 'adapter-doctor --status');
  try{
    const d = await api('/api/doctor' + (rerun ? '/checks' : ''), { method: rerun ? 'POST' : 'GET' });
    renderDoctor(d);
    const line = `doctor: VM ${dok(d.vm)?'up':'DOWN'} · wlan0 ${dok(d.wlan0)?'present':'ABSENT'} · monitor ${dok(d.monitor)?'on':'off'} · injection ${dok(d.injection)?'ok':'?'} · band ${d.band||'2.4G'} · APs ${d.aps??'?'}`;
    const lvl = (dok(d.vm) && dok(d.wlan0) && dok(d.monitor)) ? 'ok' : 'warn';
    if (!quiet){
      if (Array.isArray(d.logs)) d.logs.forEach(l => logLine(l, inferLevel(l)));
      logLine(line, lvl);
    } else if (line !== state.lastDoctorLine){
      logLine(line, lvl);  // background poll logs ONLY when the status actually changes
    }
    state.lastDoctorLine = line;
  } catch (err){
    if (state.sim) return quiet ? undefined : simDoctor();
    if (!quiet) logLine('doctor unreachable: ' + err.message + '  — is the backend up on :8787?', 'err');
    ['vm','wlan0','monitor','injection','band','aps'].forEach(k => setChip(k, 'unknown', '…'));
  }
}
async function resetAdapter(hard){
  logCmd(hard ? 'hard-reset  (utmctl usb disconnect/connect 2357:010C)' : 'fix-adapter.sh  (soft monitor reset)');
  logLine(hard ? 'Hard reset: re-attaching USB adapter to the VM…' : 'Soft reset: ip link down → set monitor → up (never modprobe)…', 'warn');
  try{
    const d = await api('/api/doctor/reset', { method: 'POST', body: { hard: !!hard } });
    if (d && typeof d === 'object' && 'monitor' in d) renderDoctor(d);
    logLine('reset complete — re-running checks.', 'ok');
    runDoctor(false);
  } catch (err){
    if (state.sim){ logLine('[SIM] reset simulated — adapter back to monitor mode.', 'sim'); return; }
    logLine('reset failed: ' + err.message, 'err');
  }
}

/* ================================================================== SCAN / TARGETS */
const tbody = $('#targets-tbody');
function pwrGlyph(p){                       // -30 strong … -90 weak
  const n = Number(p);
  if (!isFinite(n) || n === 0) return '·';
  if (n > -45) return '▁▂▃▄▅';
  if (n > -60) return '▁▂▃▄';
  if (n > -70) return '▁▂▃';
  if (n > -80) return '▁▂';
  return '▁';
}
function renderTargets(){
  tbody.textContent = '';
  if (!state.targets.length){
    const tr = el('tr', 'empty-row');
    const td = el('td'); td.colSpan = 8;
    td.append('No scan yet — hit ', (() => { const b = el('b', null, '▷ SCAN'); return b; })(), ' to light it up.');
    tr.appendChild(td); tbody.appendChild(tr);
    $('#target-count').textContent = 'APs 0';
    return;
  }
  state.targets.forEach((t, i) => {
    const authed = state.authorized.has(norm(t.bssid));
    const tr = el('tr'); tr.dataset.bssid = norm(t.bssid);
    if (norm(t.bssid) === norm(state.selected)) tr.classList.add('sel');

    tr.appendChild(el('td', 'c-idx', String(i + 1)));
    tr.appendChild(el('td', 'c-bssid', t.bssid));
    tr.appendChild(el('td', 'c-ch', t.ch != null ? String(t.ch) : '—'));

    const pwr = el('td', 'c-pwr');
    pwr.appendChild(el('span', 'pwr-bar', pwrGlyph(t.pwr)));
    pwr.append(' ' + (t.pwr != null ? t.pwr : ''));
    tr.appendChild(pwr);

    const cli = el('td', 'c-cli');
    const cn = Number(t.clients) || 0;
    cli.appendChild(el('span', cn > 0 ? 'cli-hot' : 'cli-zero', String(cn)));
    tr.appendChild(cli);

    const ess = el('td', 'c-essid essid-cell');
    if (!t.essid || t.essid === '<hidden>') ess.appendChild(el('span', 'hidden-ssid', '<hidden>'));
    else ess.textContent = t.essid;
    ess.title = t.essid || '<hidden>';
    tr.appendChild(ess);

    const auth = el('td', 'c-auth');
    auth.appendChild(el('span', 'auth-badge ' + (authed ? 'ok' : 'no'), authed ? 'OK' : '--'));
    tr.appendChild(auth);

    const act = el('td', 'c-act');
    const ab = el('button', 'btn tiny row-auth ' + (authed ? 'ghost' : 'warn'), authed ? '✓ auth' : '＋ auth');
    ab.title = authed ? 'De-authorize this BSSID' : 'Add this BSSID to the allowlist';
    ab.addEventListener('click', (e) => { e.stopPropagation(); authed ? deauthorize(t) : authorize(t); });
    act.appendChild(ab);
    tr.appendChild(act);

    tr.addEventListener('click', () => selectTarget(norm(t.bssid)));
    tbody.appendChild(tr);
  });
  $('#target-count').textContent = 'APs ' + state.targets.length;
}
function selectTarget(bssid){
  state.selected = bssid;
  const t = state.targets.find(x => norm(x.bssid) === norm(bssid));
  $('#sel-bssid').textContent = t ? t.bssid : bssid;
  $('#sel-essid').textContent = t && t.essid && t.essid !== '<hidden>' ? ('· ' + t.essid) : '';
  const authed = state.authorized.has(norm(bssid));
  const sa = $('#sel-auth');
  sa.textContent = authed ? 'AUTHORIZED' : 'NOT AUTHORIZED';
  sa.className = 'sel-auth ' + (authed ? 'ok' : 'no');
  $$('#targets-tbody tr').forEach(tr => tr.classList.toggle('sel', tr.dataset.bssid === norm(bssid)));
  refreshAttackButtons();
}
async function scan(){
  logCmd('wifi-scan.sh   (channel-locked 2.4GHz sweep)');
  $('#scan-btn').disabled = true; $('#scan-btn').textContent = '▣ SCANNING…';
  try{
    // Prefer the WebSocket so each channel's "[scan] listening ch N…" streams LIVE; the final
    // {type:result} frame carries the parsed APs. Fall back to the one-shot HTTP endpoint.
    let aps;
    try{
      const res = await wsRun('scan');
      aps = res.aps || res.targets || [];
    } catch (e){
      if (e && /ws-not-open/.test(e.message)){
        const d = await api('/api/scan', { method: 'POST' });
        if (Array.isArray(d.logs)) d.logs.forEach(l => logLine(l, inferLevel(l)));
        aps = d.targets || [];
      } else { throw e; }
    }
    state.targets = aps.map(t => ({
      bssid: t.bssid, ch: (t.ch ?? t.channel), pwr: (t.pwr ?? t.power),
      clients: t.clients, essid: t.essid,
    }));
    logLine(`scan done — ${state.targets.length} AP(s) on 2.4GHz.`, 'ok');
    await syncAuthorized();
    renderTargets();
  } catch (err){
    logLine('scan failed: ' + err.message, 'err');
    if (!state.online) toast('Backend offline — try ⟟ DEMO DATA to preview the console.', 'warn');
  } finally {
    $('#scan-btn').disabled = false; $('#scan-btn').textContent = '▷ SCAN';
  }
}

/* ---------------- allowlist ---------------- */
async function syncAuthorized(){
  try{
    const d = await api('/api/authorized');
    state.authorized = new Set((d.list || []).map(norm));
    updateAuthCount();
  } catch { /* keep current mirror */ }
}
function updateAuthCount(){ $('#auth-count').textContent = 'AUTH ' + state.authorized.size; }
async function authorize(t){
  const b = norm(t.bssid);
  try{
    await api('/api/authorize', { method: 'POST', body: { bssid: b, essid: t.essid || '' } });
    state.authorized.add(b);
    logLine(`authorized ${t.bssid} ${t.essid ? '(' + t.essid + ')' : ''} → allowlist`, 'ok');
  } catch (err){
    if (state.sim){ state.authorized.add(b); logLine(`[SIM] authorized ${t.bssid}`, 'sim'); }
    else { logLine('authorize failed: ' + err.message, 'err'); return; }
  }
  updateAuthCount(); renderTargets(); if (state.selected) selectTarget(state.selected);
}
async function deauthorize(t){
  const b = norm(t.bssid);
  try{
    await api('/api/authorize', { method: 'DELETE', body: { bssid: b } });
    state.authorized.delete(b);
    logLine(`de-authorized ${t.bssid} — removed from allowlist`, 'warn');
  } catch (err){
    if (state.sim){ state.authorized.delete(b); logLine(`[SIM] de-authorized ${t.bssid}`, 'sim'); }
    else { logLine('de-authorize failed: ' + err.message, 'err'); return; }
  }
  updateAuthCount(); renderTargets(); if (state.selected) selectTarget(state.selected);
}
async function authorizeAll(){
  if (!state.targets.length){ toast('Scan first — nothing to authorize.', 'warn'); return; }
  const ok = confirm(
    'AUTHORIZE ALL SCANNED\n\n' +
    `Mark all ${state.targets.length} scanned AP(s) authorized for THIS session?\n\n` +
    'Use this only in a sanctioned environment where you have written permission ' +
    'for every access point present. This is logged.');
  if (!ok) return;
  const bssids = state.targets.map(t => norm(t.bssid));
  try{
    await api('/api/authorize/all', { method: 'POST', body: { confirm: true, bssids } });
    bssids.forEach(b => state.authorized.add(b));
    logLine(`AUTHORIZE-ALL confirmed — ${bssids.length} AP(s) marked authorized for this session.`, 'warn');
  } catch (err){
    if (state.sim){ bssids.forEach(b => state.authorized.add(b)); logLine(`[SIM] authorize-all: ${bssids.length} AP(s)`, 'sim'); }
    else { logLine('authorize-all failed: ' + err.message, 'err'); return; }
  }
  updateAuthCount(); renderTargets(); if (state.selected) selectTarget(state.selected);
}

/* ================================================================== GATE */
function requireTarget(){
  if (!state.selected){ toast('Lock a target first — click a row.', 'warn'); logLine('blocked: no target locked.', 'warn'); return null; }
  return state.selected;
}
function requireAuthorized(){
  const b = requireTarget(); if (!b) return null;
  if (!state.authorized.has(norm(b))){
    toast('Target is NOT authorized. Allowlist gate refuses it.', 'err');
    logLine(`BLOCKED by allowlist gate: ${b} is not authorized. Add it first (＋ auth).`, 'err');
    return null;
  }
  return b;
}
function refreshAttackButtons(){
  const hasT = !!state.selected;
  const authed = hasT && state.authorized.has(norm(state.selected));
  $$('[data-need-target]').forEach(b => b.classList.toggle('locked', !hasT));
  $$('[data-need-auth]').forEach(b => b.classList.toggle('locked', !authed));
}

/* ================================================================== ATTACK MODULES */
async function post(path, body, label){
  logCmd(label);
  try{
    const d = await api(path, { method: 'POST', body });
    // HTTP actions return {ok, logs:[...], result:{...}} — render the streamed lines.
    const logs = (d && Array.isArray(d.logs)) ? d.logs : null;
    if (logs && logs.length) logs.forEach(l => logLine(l, inferLevel(l)));
    else if (d && d.message)  logLine(d.message, d.level || 'ok');
    else                      logLine(label.split(' ')[0] + ' done.', 'ok');
    return d;
  } catch (err){
    if (state.sim) throw err;         // sim handlers decide
    logLine(label.split(' ')[0] + ' failed: ' + err.message, 'err');
    return null;
  }
}
/* A — recon (passive; needs a target but not authorization) */
async function aRecon(){
  const b = requireTarget(); if (!b) return;
  const t = state.targets.find(x => norm(x.bssid) === norm(b));
  const params = { bssid: b }; if (t && t.ch) params.channel = Number(t.ch);
  const r = await runStreamed('recon', params, '/api/attack/recon', { bssid: b, ch: t ? t.ch : undefined }, `recon ${b}`);
  if (r && typeof r.client_count === 'number') logLine(`recon done — ${r.client_count} associated client(s).`, 'ok');
  if (!r && state.sim) simRecon(b);
}
/* B — spoof OWN adapter MAC */
async function bSpoof(mode){
  const r = await runStreamed('spoof', { mode }, '/api/attack/spoof', { mode }, `adapter-mac --${mode}  (own radio)`);
  if (r && r.mac) logLine(`adapter MAC ${mode === 'random' ? 'randomized' : 'restored'} → ${r.mac}  (re-run SCAN; monitor may have dropped)`, 'ok');
  if (!r && state.sim) logLine(`[SIM] adapter MAC ${mode === 'random' ? 'randomized → DE:AD:BE:xx:xx:xx' : 'restored to hardware default'}.`, 'sim');
}
/* C — rogue-AP DETECT (passive, blue-team) */
async function cRogue(){
  const r = await runStreamed('rogue_detect', {}, '/api/attack/rogue', {}, 'rogue-ap --detect  (evil-twin scan, blue-team)');
  if (r && Array.isArray(r.findings)) logLine(`rogue-detect done — ${r.findings.length} possible twin(s) flagged.`, r.findings.length ? 'warn' : 'ok');
  if (!r && state.sim) simRogue();
}
function rogueConcept(){
  logLine('ROGUE-AP CONCEPT: a detector watches for two BSSIDs broadcasting the same ESSID, sudden deauth floods, and signal/OUI mismatches — the fingerprint of an evil-twin.', 'ai');
  logLine('By design this tool has NO fake-login / captive-portal that captures real passwords. Detection is the stronger (and lawful) defensive story.', 'ai');
}
/* D — deauth (DISRUPTIVE; authorized only) */
let deauthTimer = null;
async function dDeauth(mode){
  const b = requireAuthorized(); if (!b) return;
  const seconds = Number($('#deauth-secs').value) || 20;
  armStop(true);
  logLine(`DEAUTH ${mode === 'all' ? 'BROADCAST (all clients)' : 'TARGETED (one client)'} on ${b} for ${seconds}s — authorized target.`, 'warn');
  const t = state.targets.find(x => norm(x.bssid) === norm(b));
  const wsMode = (mode === 'all') ? 'broadcast' : 'targeted';
  const params = { bssid: b, mode: wsMode, duration: seconds }; if (t && t.ch) params.channel = Number(t.ch);
  const r = await runStreamed('deauth', params, '/api/attack/deauth', { bssid: b, mode, seconds }, `aireplay-ng --deauth ${wsMode} ${b} (${seconds}s)`);
  if (!r && state.sim) simDeauth(b, mode, seconds);
  clearTimeout(deauthTimer);
  deauthTimer = setTimeout(() => { armStop(false); logLine('deauth window elapsed — frames stopped.', 'ok'); }, seconds * 1000);
}
async function stopAll(){
  clearTimeout(deauthTimer); armStop(false);
  logCmd('attack --stop-all');
  try{ await api('/api/attack/stop', { method: 'POST' }); logLine('STOP — all running attacks halted.', 'ok'); }
  catch { if (state.sim) logLine('[SIM] STOP — simulated attacks halted.', 'sim'); else logLine('stop signal sent (backend offline).', 'warn'); }
}
function armStop(on){ state.deauthArmed = on; $('#d-stop').classList.toggle('armed', on); }
/* E — key-crack */
async function eCapture(){
  const b = requireAuthorized(); if (!b) return;
  const t = state.targets.find(x => norm(x.bssid) === norm(b));
  if (t && Number(t.clients) === 0) logLine('note: target shows 0 clients — a handshake needs a connected device (try PMKID instead).', 'warn');
  const params = { bssid: b }; if (t && t.ch) params.channel = Number(t.ch);
  const r = await runStreamed('capture_handshake', params, '/api/attack/capture',
                              { bssid: b, ch: t ? t.ch : undefined }, `grab.sh ${b} ${t && t.ch ? t.ch : ''}`);
  if (r && r.status === 'HANDSHAKE_CAPTURED') logLine('handshake captured ✓ — hit ▸ CRACK ON MAC GPU.', 'ok');
  else if (!r && state.sim) simCapture(b);
}
async function ePmkid(){
  const b = requireAuthorized(); if (!b) return;
  const t = state.targets.find(x => norm(x.bssid) === norm(b));
  const params = { bssid: b }; if (t && t.ch) params.channel = Number(t.ch);
  const r = await runStreamed('pmkid', params, '/api/attack/pmkid', { bssid: b, ch: t ? t.ch : undefined }, `pmkid/eapol ${b}`);
  if (r && r.captured) logLine(`captured ${r.pmkid_count || 0} PMKID + ${Math.max(0,(r.hash_count||0)-(r.pmkid_count||0))} EAPOL — hit ▸ CRACK.`, 'ok');
  if (!r && state.sim) simPmkid(b);
}
async function eWps(){
  const b = requireAuthorized(); if (!b) return;
  const t = state.targets.find(x => norm(x.bssid) === norm(b));
  const params = { bssid: b }; if (t && t.ch) params.channel = Number(t.ch);
  const r = await runStreamed('wps', params, '/api/attack/wps', { bssid: b, ch: t ? t.ch : undefined }, `wps-probe ${b}`);
  if (r && r.wps_enabled === false) logLine('WPS not enabled on this AP — nothing to attack (that is the secure config).', 'ok');
  else if (r && r.found) logLine('WPS secret recovered — DISABLE WPS now.', 'warn');
  if (!r && state.sim) logLine(`[SIM] WPS probe ${b}: external registrar locked (good hygiene).`, 'sim');
}
async function eTriage(){
  const b = requireAuthorized(); if (!b) return;
  const r = await runStreamed('triage', { bssid: b }, '/api/attack/triage', { bssid: b }, `triage ${b}`);
  if (r && r.usable === false) logLine('triage: no usable handshake in this capture — recapture (client connected) or try PMKID.', 'warn');
  else if (r && r.usable) logLine(`triage: ${r.hashes} hash line(s) across ${(r.networks||[]).length} network(s)${r.has_target===false?' — your target is NOT in this file!':' ✓'}`, r.has_target===false?'warn':'ok');
}
const TIER_EST = { 1: '~seconds to 10 min', 2: 'up to ~15 hours', 3: 'deep — hours to a day+' };
async function eCrack(){
  const b = requireAuthorized(); if (!b) return;
  const startLevel = Number($('#crack-level').value) || 1;
  const mask = ($('#crack-mask').value || '').trim();
  // Approval-gated: run ONE tier, and only climb to the next (slower) tier if YOU say yes.
  for (let level = startLevel; level <= 3; level++){
    logLine(`GPU crack — Tier ${level} (${TIER_EST[level]})${(level===startLevel && mask)?` · mask ${mask}`:''}. Mac Metal ~185k H/s.`, 'warn');
    const body = { bssid: b, level, mask: (level===startLevel ? mask : ''), single: true };
    const r = await runStreamed('crack', body, '/api/crack', body, `crack t${level} ${b}`, 1800000);
    if (r && r.cracked && r.password){ logLine(`CRACKED ✓  ${r.essid || ''} → ${r.password}  (saved to vault)`, 'ok'); loadKeys(); return; }
    if (r && r.mismatch){ logLine(`⚠ recovered key is for ${r.found_essid} (${r.found_bssid}), NOT your target — stale/contaminated capture, not saved. Run ⌕ Triage.`, 'warn'); return; }
    if (r && r.no_target_handshake){ logLine('no handshake for the selected target in that capture — recapture the RIGHT AP (client connected).', 'warn'); return; }
    if (r && r.empty_capture){ logLine('no usable handshake in the capture — recapture with a client, or try PMKID.', 'warn'); return; }
    if (!r){ if (state.sim) simCrack(b, level); return; }   // offline/sim or stopped — don't auto-escalate
    if (level >= 3){ logLine('Not cracked through Tier 3 — very likely a strong/random key. That IS the finding: report it secure (WPS off + long random PSK beat every tier).', 'ok'); return; }
    const next = level + 1;
    if (!confirm(`Tier ${level} didn't find it.\n\nTry Tier ${next}?  Estimated time: ${TIER_EST[next]}.\n\nOK = run it   ·   Cancel = stop here.`)){
      logLine(`Stopped after Tier ${level} — your call. Restart at a higher tier anytime from the LVL selector.`, 'info');
      return;
    }
  }
}

/* ================================================================== AI CHAT */
const chatLog = $('#chat-log');
function addMsg(who, text, cls){
  const m = el('div', 'msg ' + (who === 'me' ? 'me' : 'ai'));
  m.appendChild(el('span', 'who', who));
  m.appendChild(el('span', 'bubble ' + (cls || ''), text));
  chatLog.appendChild(m);
  chatLog.scrollTop = chatLog.scrollHeight;
  return m;
}
async function sendChat(ev){
  ev.preventDefault();
  const input = $('#chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  addMsg('me', msg);
  input.value = '';
  const thinking = addMsg('ai', 'thinking', 'think');
  thinking.querySelector('.bubble').textContent = '';
  try{
    const d = await api('/api/ai/chat', { method: 'POST', body: { message: msg } });
    thinking.querySelector('.bubble').classList.remove('think');
    thinking.querySelector('.bubble').textContent = (d && d.reply) ? d.reply : '(no reply)';
  } catch (err){
    thinking.querySelector('.bubble').classList.remove('think');
    if (state.sim || !state.online){ thinking.querySelector('.bubble').textContent = simAIReply(msg); localIntent(msg); }
    else thinking.querySelector('.bubble').textContent = 'AI link error: ' + err.message + ' — is Ollama up (:11434, qwen3-agent)?';
  }
}
/* light local intent mapping — only used when the backend AI is unavailable,
   so "talk to it" still drives the gated buttons during an offline preview. */
function localIntent(msg){
  const m = msg.toLowerCase();
  const numMatch = m.match(/#?\s*(\d{1,2})/);
  if (numMatch){ const i = Number(numMatch[1]) - 1; if (state.targets[i]) selectTarget(norm(state.targets[i].bssid)); }
  if (/\bscan\b/.test(m)) return scan();
  if (/\bdoctor|health|adapter\b/.test(m)) return runDoctor(true);
  if (/\bstop\b/.test(m)) return stopAll();
  if (/\brecon|enumerate\b/.test(m)) return aRecon();
  if (/\bpmkid\b/.test(m)) return ePmkid();
  if (/\bcapture|handshake\b/.test(m)) return eCapture();
  if (/\bcrack\b/.test(m)) return eCrack();
  if (/\bdeauth|kick\b/.test(m)) return dDeauth(/all|broadcast/.test(m) ? 'all' : 'one');
}

/* ================================================================== WEBSOCKET */
const wsDot = $('#ws-dot');
function connectWS(){
  try{ state.ws = new WebSocket(CONFIG.WS); }
  catch { scheduleWS(); return; }
  state.ws.onopen = () => { wsDot.className = 'ws-dot on'; state.wsRetry = 0; logLine('live log stream connected (ws).', 'ok'); setOnline(true); };
  state.ws.onclose = () => { wsDot.className = 'ws-dot off'; scheduleWS(); };
  state.ws.onerror = () => { try { state.ws.close(); } catch {} };
  state.ws.onmessage = (e) => {
    let o = null;
    try { o = JSON.parse(e.data); } catch { logLine(e.data, 'info'); return; }
    const t = o && o.type;
    // --- completion of a streamed run: resolve/reject the pending promise ---
    if (t === 'result'){
      const p = state.wsPending;
      if (p){ clearTimeout(p.timer); state.wsPending = null; p.resolve(o.result || {}); }
      return;
    }
    if (t === 'error'){
      const p = state.wsPending;
      if (p){ clearTimeout(p.timer); state.wsPending = null; p.reject(new Error(o.message || 'error')); }
      else logLine('error: ' + (o.message || 'unknown'), 'err');
      return;
    }
    if (t === 'ai_done'){
      const p = state.wsPending;
      if (p){ clearTimeout(p.timer); state.wsPending = null; p.resolve(o); }
      return;
    }
    if (t === 'ai'){ if (o.text) logLine('[AI] ' + o.text, 'ai'); return; }
    // --- default: a streamed log line ({type:'log', line} or a legacy plain frame) ---
    const text = o.line ?? o.m ?? o.message ?? e.data;
    const level = o.level || o.lv || 'info';
    const map = { INFO:'info', OK:'ok', SUCCESS:'ok', WARN:'warn', WARNING:'warn', ERR:'err', ERROR:'err', CMD:'cmd', AI:'ai' };
    logLine(text, map[String(level).toUpperCase()] || (['info','ok','warn','err','cmd','ai','sim'].includes(level) ? level : 'info'));
  };
}
function scheduleWS(){
  if (state.sim) return;
  state.wsRetry = Math.min(state.wsRetry + 1, 6);
  const delay = 1000 * state.wsRetry;
  setTimeout(() => { if (!state.sim) connectWS(); }, delay);
}

/* Run a long action over the WebSocket so its output streams LIVE into the log; resolve with
   the final result object. Rejects 'ws-not-open' (caller can fall back to HTTP) or 'busy'. */
function wsRun(action, params = {}, timeoutMs = CONFIG.SLOW_TIMEOUT_MS){
  return new Promise((resolve, reject) => {
    const ws = state.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN){ reject(new Error('ws-not-open')); return; }
    if (state.wsPending){ reject(new Error('busy — a task is already running; STOP it first.')); return; }
    const timer = setTimeout(() => {
      if (state.wsPending){ state.wsPending = null; reject(new Error('timeout')); }
    }, timeoutMs);
    state.wsPending = { action, resolve, reject, timer };
    try { ws.send(JSON.stringify({ type:'run', action, params })); }
    catch (err){ clearTimeout(timer); state.wsPending = null; reject(err); }
  });
}

/* Prefer the live WS stream for a long action; fall back to the one-shot HTTP route (whose
   returned logs we render after the fact). Returns the action's result object (or null). */
async function runStreamed(action, params, httpPath, httpBody, label, timeoutMs){
  logCmd(label);
  try{
    return await wsRun(action, params, timeoutMs);     // logs already streamed live
  } catch (e){
    if (e && /ws-not-open|busy/.test(e.message)){
      const d = await api(httpPath, { method:'POST', body: httpBody });
      const logs = (d && Array.isArray(d.logs)) ? d.logs : null;
      if (logs && logs.length) logs.forEach(l => logLine(l, inferLevel(l)));
      return (d && d.result) ? d.result : d;
    }
    logLine(label.split(' ')[0] + ' failed: ' + e.message, 'err');
    return null;
  }
}

/* ================================================================== SIMULATION (offline demo)
   Clearly fake. BSSIDs use the reserved 00:00:5E documentation OUI; names say DEMO.
   Everything is tagged [SIM] / magenta so it can never be mistaken for a real result. */
const DEMO = [
  { bssid:'00:00:5E:00:53:A1', ch:6,  pwr:-41, clients:3, essid:'DEMO-Home-2G' },
  { bssid:'00:00:5E:00:53:B7', ch:11, pwr:-58, clients:1, essid:'DEMO-Office' },
  { bssid:'00:00:5E:00:53:C2', ch:1,  pwr:-67, clients:0, essid:'DEMO-Guest' },
  { bssid:'00:00:5E:00:53:D9', ch:6,  pwr:-72, clients:2, essid:'<hidden>' },
  { bssid:'00:00:5E:00:53:E4', ch:9,  pwr:-80, clients:0, essid:'DEMO-IoT-Cam' },
];
function enterSim(){
  setSim();
  logLine('———  SIMULATION MODE  ———  backend on :8787 not reachable. Showing fake sample data so you can tour the console.', 'sim');
  simDoctor();
}
function loadDemo(){
  if (!state.sim) enterSim();
  state.targets = DEMO.map(x => ({ ...x }));
  renderTargets();
  logLine(`[SIM] loaded ${DEMO.length} fake APs (00:00:5E documentation OUI). Nothing here is real.`, 'sim');
  toast('Demo data loaded (simulation).', 'warn');
}
function simDoctor(){ renderDoctor({ vm:true, wlan0:true, monitor:true, injection:true, band:'2.4G', aps:DEMO.length }); }
function simRecon(b){
  logLine(`[SIM] recon ${b}: vendor TP-LINK · WPA2-PSK (CCMP) · PMF off · 3 clients · uptime ~4d`, 'sim');
}
function simRogue(){
  logLine('[SIM] rogue-ap detect: scanning ESSIDs for duplicate BSSIDs…', 'sim');
  setTimeout(() => logLine('[SIM] ⚠ twin suspected: "DEMO-Home-2G" seen on 00:00:5E:00:53:A1 AND 00:00:5E:00:53:FF (new OUI + deauth burst).', 'sim'), 700);
}
function simDeauth(b, mode, s){
  logLine(`[SIM] aireplay-ng deauth ${mode} → ${b} … sending frames for ${s}s`, 'sim');
  setTimeout(() => logLine('[SIM] client 00:00:5E:00:53:17 dropped & reconnecting (4-way handshake incoming).', 'sim'), 900);
}
function simCapture(b){
  logLine(`[SIM] grab.sh ${b}: locking channel, deauthing a client…`, 'sim');
  setTimeout(() => logLine('[SIM] ✓ WPA2 4-way handshake captured → /tmp/cap-01.cap', 'sim'), 1200);
}
function simPmkid(b){
  logLine(`[SIM] hcxdumptool ${b}: requesting PMKID (clientless)…`, 'sim');
  setTimeout(() => logLine('[SIM] ✓ PMKID retrieved → ready for GPU crack.', 'sim'), 1100);
}
function simCrack(b, lvl){
  logLine(`[SIM] crack-mac.sh level ${lvl} on Mac GPU (Metal ~185k H/s)…`, 'sim');
  setTimeout(() => logLine('[SIM] tier 1: weakpins.txt … rockyou.txt … 8-digit mask …', 'sim'), 600);
  setTimeout(() => logLine('[SIM] ✓ CRACKED demo net — PASSWORD: "password123"  (fake, demo only)', 'sim'), 1700);
}
function simAIReply(msg){
  const m = msg.toLowerCase();
  if (/scan/.test(m)) return '[SIM] Running a channel-locked 2.4GHz sweep. I only drive the gated modules — authorize a target before any capture or deauth.';
  if (/crack/.test(m)) return '[SIM] I will capture the handshake on the authorized target, then crack on the Mac GPU tiered smallest→largest. Pick a level 1–3.';
  if (/deauth|kick/.test(m)) return '[SIM] Deauth is disruptive and authorized-only. It is bounded and has a big STOP. PMF/802.11w targets will shrug it off.';
  if (/rogue|evil/.test(m)) return '[SIM] Rogue-AP here is a DETECTOR — it spots evil-twins. There is no password-capturing fake page, by design.';
  return '[SIM] Offline preview. Start the backend on :8787 (and Ollama qwen3-agent on :11434) for real answers. I map plain English to the gated buttons.';
}

/* ================================================================== WIRE-UP */
function bind(){
  // doctor
  $('#btn-doctor').addEventListener('click', () => runDoctor(true));
  $('#btn-reset').addEventListener('click', () => resetAdapter(false));
  $('#btn-reset-hard').addEventListener('click', () => resetAdapter(true));
  // targets
  $('#scan-btn').addEventListener('click', scan);
  $('#authall-btn').addEventListener('click', authorizeAll);
  $('#demo-btn').addEventListener('click', loadDemo);
  // attacks
  $('#a-recon').addEventListener('click', aRecon);
  $('#a-rescan').addEventListener('click', scan);
  $('#b-spoof-rand').addEventListener('click', () => bSpoof('random'));
  $('#b-spoof-restore').addEventListener('click', () => bSpoof('restore'));
  $('#c-rogue').addEventListener('click', cRogue);
  $('#c-rogue-info').addEventListener('click', rogueConcept);
  $('#d-deauth-one').addEventListener('click', () => dDeauth('one'));
  $('#d-deauth-all').addEventListener('click', () => dDeauth('all'));
  $('#d-stop').addEventListener('click', stopAll);
  $('#e-capture').addEventListener('click', eCapture);
  $('#e-pmkid').addEventListener('click', ePmkid);
  $('#e-wps').addEventListener('click', eWps);
  $('#e-triage').addEventListener('click', eTriage);
  $('#e-crack').addEventListener('click', eCrack);
  $('#mask-preset').addEventListener('change', (e) => {
    if (e.target.value){ $('#crack-mask').value = e.target.value; logLine(`mask pattern set: ${e.target.value} — hit ▶ CRACK to run it first.`, 'info'); }
  });
  // saved keys (vault)
  $('#keys-refresh').addEventListener('click', loadKeys);
  $('#keys-clear').addEventListener('click', clearVault);
  // chat
  $('#chat-form').addEventListener('submit', sendChat);
  // log controls
  $('#log-pause').addEventListener('click', (e) => {
    state.logPaused = !state.logPaused;
    e.currentTarget.textContent = state.logPaused ? '▶ RESUME' : '⏸ PAUSE';
    if (!state.logPaused) logBox.scrollTop = logBox.scrollHeight;
  });
  $('#log-clear').addEventListener('click', () => { logBox.textContent = ''; logLine('log cleared.', 'info'); });
  $('#log-filter').addEventListener('input', (e) => {
    state.logFilter = e.target.value.toLowerCase();
    $$('#log .ln').forEach(ln => {
      const txt = ln.querySelector('.m').textContent.toLowerCase();
      ln.style.display = (!state.logFilter || txt.includes(state.logFilter)) ? '' : 'none';
    });
  });
  // keyboard: 1-9 selects a scanned row when not typing
  document.addEventListener('keydown', (e) => {
    if (/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) return;
    if (e.key >= '1' && e.key <= '9'){ const i = Number(e.key) - 1; if (state.targets[i]) selectTarget(norm(state.targets[i].bssid)); }
  });
  $('#api-base').textContent = CONFIG.BASE;
}

/* ================================================================== SAVED KEYS (vault) */
async function loadKeys(){
  const tb = $('#keys-tbody'); if (!tb) return;
  let rows = [];
  try { const d = await api('/api/passwords'); rows = (d && d.passwords) || []; }
  catch { return; }                 // backend offline — leave the panel untouched
  $('#keys-count').textContent = 'KEYS ' + rows.length;
  tb.textContent = '';
  if (!rows.length){
    const tr = el('tr', 'empty-row');
    const td = el('td', '', 'No keys saved yet — crack an authorized target and its password lands here (network + password, never the hash).');
    td.colSpan = 6; tr.appendChild(td); tb.appendChild(tr);
    return;
  }
  rows.forEach((r, i) => {
    const tr = el('tr', 'key-row');
    tr.appendChild(el('td', 'c-idx', String(i + 1)));
    tr.appendChild(el('td', 'key-essid', r.essid || '<hidden>'));
    tr.appendChild(el('td', 'c-bssid', r.bssid || ''));
    const pw = el('td', 'key-pw'); pw.textContent = r.password || ''; tr.appendChild(pw);
    tr.appendChild(el('td', 'key-when dim', (r.time || '').replace('T', ' ')));
    const act = el('td', 'c-act');
    const copy = el('button', 'btn tiny ghost', '⧉ copy');
    copy.addEventListener('click', () => {
      try { navigator.clipboard && navigator.clipboard.writeText(r.password || ''); } catch {}
      logLine('copied password for ' + (r.essid || r.bssid), 'ok');
    });
    act.appendChild(copy); tr.appendChild(act);
    tb.appendChild(tr);
  });
}
async function clearVault(){
  if (!confirm('Erase ALL saved passwords from the vault? This cannot be undone.')) return;
  try { await api('/api/passwords/clear', { method: 'POST' }); logLine('vault cleared.', 'warn'); }
  catch (e){ logLine('could not clear vault: ' + e.message, 'err'); }
  loadKeys();
}

/* ------------------------------------------------------------------ boot */
async function boot(){
  bind();
  refreshAttackButtons();
  logLine('Wi-Fi Command Center UI loaded. Controller=Mac · Radio=Kali · Crack=Mac GPU.', 'ok');
  logLine('Probing backend on ' + CONFIG.BASE + ' …', 'info');
  let healthy = false;
  try{ await api('/api/health'); healthy = true; }
  catch { try{ await api('/api/doctor'); healthy = true; } catch { healthy = false; } }
  if (healthy){
    logLine('backend online — pulling status & allowlist.', 'ok');
    await syncAuthorized();
    await runDoctor(false);
    await loadKeys();
    connectWS();
    setInterval(() => { if (state.online && !state.wsPending) runDoctor(false, true); }, CONFIG.DOCTOR_POLL_MS);
  } else {
    enterSim();
    toast('Backend not found on :8787 — simulation mode. Hit ⟟ DEMO DATA.', 'warn');
  }
  updateAuthCount();
}
document.addEventListener('DOMContentLoaded', boot);
