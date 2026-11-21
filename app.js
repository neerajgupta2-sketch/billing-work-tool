// Billing Work Tool -- static page. All data arrives encrypted; it is unlocked in this browser
// with the tool password. Nothing here can change any consumer account (that is done only in CC&B).
(function () {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => (s === null || s === undefined ? '' : String(s)).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const N = (v, d = 0) => { const n = +v; return v === '' || v === null || v === undefined || isNaN(n) ? '—' : n.toLocaleString('en-IN', { minimumFractionDigits: d, maximumFractionDigits: d }); };
  const P = (v, d = 1) => (v === '' || v === null || isNaN(+v) ? '—' : (+v).toFixed(d) + '%');
  const pctCls = (v) => (+v < 60 ? 'bad' : +v < 85 ? 'warn' : 'good');
  const shortSub = (s) => String(s || '').replace(/_\d+$/, '');
  function toast(m, ms = 2500) { const t = $('toast'); t.textContent = m; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), ms); }

  // ------------------------------------------------------------ crypto + data
  let META = null, KEYS = null, ROLE = '';
  const groupOf = (name) => (name === 'mr' || name === 'list-issues' || name === 'list-unbilled' || name === 'list-atrdone' || name === 'list-cleared' ? 'mr' : name === 'reports' ? 'rep' : name === 'commercial' ? 'com' : 'ext');
  const can = (g) => !!(KEYS && KEYS[g]);
  const cacheName = 'bwt-data';
  function b64(s) { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); }
  async function derive(pw, meta) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(meta.salt), iterations: meta.iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function decryptBytes(key, bytes) {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12)));
  }
  async function keyWorks(key, meta) { try { const t = await decryptBytes(key, b64(meta.check)); return new TextDecoder().decode(t) === 'billing-work-tool-ok'; } catch (e) { return false; } }
  // Remember the unlocked key on this device (stored non-extractable in IndexedDB, never the password)
  function idb() { return new Promise((res, rej) => { const r = indexedDB.open('bwt', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
  async function idbGet(k) { try { const d = await idb(); return await new Promise((res) => { const q = d.transaction('k').objectStore('k').get(k); q.onsuccess = () => res(q.result); q.onerror = () => res(null); }); } catch (e) { return null; } }
  async function idbSet(k, v) { try { const d = await idb(); await new Promise((res) => { const tx = d.transaction('k', 'readwrite'); tx.objectStore('k').put(v, k); tx.oncomplete = res; tx.onerror = res; }); } catch (e) {} }
  async function idbDel(k) { try { const d = await idb(); await new Promise((res) => { const tx = d.transaction('k', 'readwrite'); tx.objectStore('k').delete(k); tx.oncomplete = res; tx.onerror = res; }); } catch (e) {} }

  const MEM = {};
  async function load(name) {
    if (MEM[name]) return MEM[name];
    const url = `data/${name}.bin?v=${encodeURIComponent(META.builtAt)}`;
    let bytes = null;
    try { const c = await caches.open(cacheName); const hit = await c.match(url); if (hit) bytes = new Uint8Array(await hit.arrayBuffer()); } catch (e) {}
    if (!bytes) {
      const r = await fetch(url); if (!r.ok) throw new Error('Could not download ' + name);
      const buf = await r.arrayBuffer(); bytes = new Uint8Array(buf);
      try { const c = await caches.open(cacheName); await c.put(url, new Response(buf)); } catch (e) {}
    }
    const gz = await decryptBytes(KEYS[groupOf(name)], bytes);
    const json = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream('gzip'))).json();
    MEM[name] = json;
    return json;
  }
  async function pruneCache() { // drop older days' files
    try { const c = await caches.open(cacheName); for (const req of await c.keys()) if (!req.url.includes('v=' + encodeURIComponent(META.builtAt))) c.delete(req); } catch (e) {}
  }
  const rowsOf = (t) => t.rows.map((r) => Object.fromEntries(t.cols.map((c, i) => [c, r[i]])));

  // ------------------------------------------------------------ start / login
  async function start() {
    try { META = await fetch('data/meta.json?t=' + Date.now(), { cache: 'no-store' }).then((r) => r.json()); }
    catch (e) { $('view').innerHTML = '<div class="empty">Could not reach the data. Check your internet connection and reload.</div>'; return; }
    const saved = await idbGet('login');
    if (saved && saved.salt === META.salt && saved.keys && saved.keys.mr && (await keyWorks(saved.keys.mr, META))) { KEYS = saved.keys; ROLE = saved.role; return boot(); }
    loginView();
  }
  const ROLE_NAME = { admin: 'AE / EE (Admin)', je: 'JE / TG2', clerk: 'Billing Clerk', mr: 'Meter Reader / Supervisor' };
  // The password decides the login: it opens exactly one of the published keyrings.
  async function unlock(pw) {
    const key = await derive(pw, META);
    for (const role of META.roles || []) {
      try {
        const r = await fetch(`data/keyring-${role}.bin?v=${encodeURIComponent(META.builtAt)}`, { cache: 'no-store' }); if (!r.ok) continue;
        const ring = JSON.parse(new TextDecoder().decode(await decryptBytes(key, new Uint8Array(await r.arrayBuffer()))));
        const keys = {};
        for (const [g, k] of Object.entries(ring.keys)) keys[g] = await crypto.subtle.importKey('raw', b64(k), { name: 'AES-GCM' }, false, ['decrypt']);
        return { role: ring.role, keys };
      } catch (e) { /* not this login */ }
    }
    return null;
  }
  function loginView() {
    $('tabs').style.display = 'none'; $('sub').textContent = 'EUDC Jhansi';
    $('view').innerHTML = `<div class="login card"><h2>Billing Work Tool</h2><p class="muted">EUDC Jhansi · DIV233511 · DIV233512. Enter the password given to you — it opens your own login (Admin, JE/TG2, Billing Clerk or Meter Reader). This phone will remember it.</p>
      <input type="password" id="pw" placeholder="Password" autocomplete="current-password"><button class="btn primary block" id="go" style="margin-top:10px">Open</button></div>`;
    const go = async () => {
      const pw = $('pw').value; if (!pw) return;
      $('go').disabled = true; $('go').textContent = 'Unlocking…';
      const u = await unlock(pw);
      if (u) { KEYS = u.keys; ROLE = u.role; await idbSet('login', { keys: u.keys, role: u.role, salt: META.salt }); toast('Logged in as ' + (ROLE_NAME[ROLE] || ROLE)); boot(); }
      else { toast('Wrong password'); $('go').disabled = false; $('go').textContent = 'Open'; }
    };
    $('go').onclick = go; $('pw').onkeydown = (e) => { if (e.key === 'Enter') go(); };
  }

  // ------------------------------------------------------------ app shell
  let REP = null, MRD = null, COM = null; const S = { tab: 'dash', div: '' };
  const ALL_TABS = [['my', 'My Work'], ['dash', 'Dashboard'], ['mr', 'Meter Reader'], ['subwise', 'Substation-Wise'], ['commercial', 'Commercial'], ['quality', 'Billing Quality'], ['repeat', 'Repeat Cases'], ['smart', 'Smart Meter'], ['atr', 'ATR Progress'], ['unbilled', 'Unbilled Cases'], ['defective', 'Defective Bills'], ['mastererr', 'Master Errors'], ['search', 'Search']];
  const ROLE_TABS = {
    admin: ['dash', 'my', 'mr', 'subwise', 'commercial', 'quality', 'repeat', 'smart', 'atr', 'unbilled', 'defective', 'mastererr', 'search'],
    je: ['my', 'dash', 'mr', 'subwise', 'quality', 'repeat', 'smart', 'atr', 'unbilled', 'defective', 'mastererr', 'search'],
    clerk: ['my', 'dash', 'mr', 'quality', 'repeat', 'atr', 'unbilled', 'defective', 'mastererr', 'search'],
    mr: ['my', 'mr', 'subwise', 'defective', 'unbilled'],
  };
  let TABS = ALL_TABS;
  const LOAD_ORDER = ['ABOVE 50KW', 'BTW 10 TO 49 KW', 'BTW 5 TO 9 KW', 'BELOW 5KW'];
  const AGE = [['0-1 Month', 0, 1], ['1-3 Months', 1, 3], ['3-6 Months', 3, 6], ['6-12 Months', 6, 12], ['12+ Months', 12, Infinity]];
  const ageOf = (m) => { if (m === '' || m === null || m === undefined) return 'Unknown'; const b = AGE.find((x) => +m >= x[1] && +m < x[2]); return b ? b[0] : '12+ Months'; };
  const lrOf = (l) => (l === '' || l === null || l === undefined ? 'OTHERS/BLANK' : +l > 50 ? 'ABOVE 50KW' : +l >= 10 ? 'BTW 10 TO 49 KW' : +l >= 5 ? 'BTW 5 TO 9 KW' : 'BELOW 5KW');
  const baseOf = (r) => { const rr = String(r.rr || '').trim().toUpperCase(), bb = String(r.bb || '').trim().toUpperCase(); return rr === 'RDF' ? 'RDF' : rr === 'IDF' ? 'IDF' : bb === 'CEIL' ? 'CDF' : bb === 'MU' ? 'MU' : bb === 'PROV' ? 'PROV' : 'UM'; };
  const U = (v) => String(v || '').trim().toUpperCase();
  const ddmmyyyy = (iso) => { const d = new Date(iso); return isNaN(d) ? '' : `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}/${d.getFullYear()}`; };

  async function boot() {
    $('view').innerHTML = '<div class="spinner"></div>';
    TABS = (ROLE_TABS[ROLE] || ROLE_TABS.admin).map((k) => ALL_TABS.find((t) => t[0] === k));
    MRD = await load('mr');
    REP = can('rep') ? await load('reports') : { reportDate: MRD.reportDate, reports: { knownSubs: MRD.knownSubs } };
    COM = can('com') ? await load('commercial') : null;
    S.tab = TABS[0][0];
    pruneCache();
    const d = new Date(REP.reportDate);
    $('sub').textContent = `Data of ${d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })} · ${ROLE_NAME[ROLE] || ''}`;
    $('tabs').style.display = 'flex';
    $('div').onchange = () => { S.div = $('div').value; S.drill = null; render(); };
    if (!boot.done) {
      boot.done = true;
      window.addEventListener('hashchange', () => { if (!KEYS) return; const t = location.hash.slice(1); if (t === 'list' && S.drill) { S.tab = 'list'; render(); } else if (TABS.some((x) => x[0] === t)) { S.tab = t; render(); } });
      $('view').addEventListener('click', onViewClick);
      $('view').addEventListener('change', (e) => { if (e.target.id === 'subsel') { S.sub = e.target.value; render(); } if (e.target.id === 'metype') { ME = { type: e.target.value, name: '' }; saveMe(); render(); } if (e.target.id === 'mename') { ME.name = e.target.value; saveMe(); render(); } });
    }
    const t = location.hash.slice(1); if (TABS.some((x) => x[0] === t)) S.tab = t;
    render();
  }
  function tabs() { $('tabs').innerHTML = TABS.map(([k, l]) => `<button class="${S.tab === k ? 'on' : ''}" onclick="location.hash='${k}'">${l}</button>`).join('') + `<button onclick="BWT.lock()">🔒 Lock</button>`; }
  function render() {
    tabs();
    const f = { my: viewMy, atr: viewATR, repeat: viewRepeat, dash: viewDash, mr: viewMR, subwise: viewSubwise, commercial: viewCommercial, quality: viewQuality, smart: viewSmart, unbilled: () => viewCases('unbilled'), defective: () => viewCases('defective'), mastererr: () => viewCases('mastererr'), search: viewSearch, list: viewDrill }[S.tab] || { dash: viewDash, my: viewMy }[TABS[0][0]];
    $('view').innerHTML = '<div class="spinner"></div>';
    Promise.resolve().then(f).catch((e) => { console.error(e); $('view').innerHTML = `<div class="empty">${esc(e.message)}</div>`; });
    window.scrollTo(0, 0);
  }
  const rep = (k) => { const src = k.startsWith('commercial/') ? (COM || { reports: {} }).reports : REP.reports; return (S.div && src['div:' + S.div] && src['div:' + S.div][k]) || src[k]; };

  // ------------------------------------------------------------ report building blocks
  // A number cell that opens its consumer list when tapped
  const canOpen = (sp) => (['billed', 'notfed', 'repeat'].includes(sp.st) ? can('ext') : true);
  const ck = (n, spec, cls = '') => (n && canOpen(spec) ? `<td class="ck ${cls}" data-d="${encodeURIComponent(JSON.stringify(spec))}">${N(n)}</td>` : `<td class="${cls}">${N(n || 0)}</td>`);
  const pc = (v) => `<td class="${v === null || isNaN(v) ? '' : pctCls(v * 100)}">${v === null || isNaN(v) ? '—' : P(v * 100)}</td>`;
  // A report card. `title` is used as the heading of the shared image.
  // every report can be folded with its +/- button; the phone remembers which ones are folded
  let FOLD = new Set(); try { FOLD = new Set(JSON.parse(localStorage.getItem('bwt-fold') || '[]')); } catch (e) { /* none */ }
  const saveFold = () => { try { localStorage.setItem('bwt-fold', JSON.stringify([...FOLD])); } catch (e) { /* private mode */ } };
  const card = (title, inner, note = '') => `<div class="card rep ${FOLD.has(title) ? 'col' : ''}" data-title="${esc(title)}"><div class="rh"><button class="tg" aria-label="Open or close this report">${FOLD.has(title) ? '+' : '−'}</button><h3>${esc(title)}</h3><button class="btn sm imgbtn">📷 Image</button></div><div class="cb">${note ? `<p class="muted">${note}</p>` : ''}<div class="wrap">${inner}</div></div></div>`;
  const tabTools = (name) => `<div class="row" style="margin-bottom:10px"><button class="btn sm primary allimg" data-name="${esc(name)}">📷 All reports on this page as one image</button><button class="btn sm" data-fold="open">+ Open all</button><button class="btn sm" data-fold="close">− Close all</button><span class="muted">Tap a number to see its consumers. Tap a column heading to sort. + / − opens or closes a report.</span></div>`;

  // Tap a column heading to sort that report (tap again to reverse). Total rows stay where they are.
  function sortTable(th) {
    const table = th.closest('table'); const head = table.tHead; if (!head || (th.colSpan || 1) > 1) return;
    // work out which column this heading sits over (headings can span rows / columns)
    const grid = []; let col = -1;
    [...head.rows].forEach((tr, ri) => { grid[ri] = grid[ri] || []; let c = 0; [...tr.cells].forEach((cell) => { while (grid[ri][c]) c++; for (let y = 0; y < (cell.rowSpan || 1); y++) for (let x = 0; x < (cell.colSpan || 1); x++) { (grid[ri + y] = grid[ri + y] || [])[c + x] = cell; } if (cell === th) col = c; c += cell.colSpan || 1; }); });
    if (col < 0) return;
    const dir = th.dataset.dir === 'd' ? 'a' : 'd';
    head.querySelectorAll('th').forEach((x) => { delete x.dataset.dir; });
    th.dataset.dir = dir;
    const val = (tr) => { const c = tr.cells[col]; const t = c ? c.textContent.trim() : ''; const dm = t.match(/^(\d{2})\/(\d{2})\/(\d{4})$/); if (dm) return +(dm[3] + dm[2] + dm[1]); const n = parseFloat(t.replace(/[,%₹]/g, '')); return t === '—' || t === '' ? -Infinity : isNaN(n) || /[A-Za-z]/.test(t.replace(/KW|MW|MU/gi, '').slice(0, 1)) ? t.toUpperCase() : n; };
    for (const body of table.tBodies) {
      const kids = new Map(); let lastP = null; for (const r of [...body.rows]) { if (r.classList.contains('sub')) { if (lastP) kids.get(lastP).push(r); } else { lastP = r; kids.set(r, []); } }
      const rows = [...body.rows].filter((r) => !r.classList.contains('sub')); const movable = rows.filter((r) => !r.classList.contains('tot'));
      const sorted = movable.slice().sort((x, y) => { const a = val(x), b = val(y); const r = typeof a === 'number' && typeof b === 'number' ? a - b : String(a).localeCompare(String(b), 'en', { numeric: true }); return dir === 'a' ? r : -r; });
      let i = 0; const out = rows.map((r) => (r.classList.contains('tot') ? r : sorted[i++]));
      out.forEach((r) => { body.appendChild(r); (kids.get(r) || []).forEach((k) => body.appendChild(k)); });
    }
  }
  function onViewClick(e) {
    const tp = e.target.closest('button[data-top]'); if (tp) { openDrill({ st: 'unbilled', top: +tp.dataset.top, ...meSpec() }); return; }
    if (e.target.id === 'l5') { S.noL5 = e.target.checked; const y = window.scrollY; render(); setTimeout(() => window.scrollTo(0, y), 60); return; }
    const th = e.target.closest('table.t thead th');
    if (th) { sortTable(th); return; }
    const c = e.target.closest('.ck');
    if (c) { openDrill(JSON.parse(decodeURIComponent(c.dataset.d))); return; }
    const tg = e.target.closest('.rh .tg, .rh h3');
    if (tg) { const c2 = tg.closest('.rep'); const t = c2.dataset.title; const shut = c2.classList.toggle('col'); c2.querySelector('.tg').textContent = shut ? '+' : '−'; if (shut) FOLD.add(t); else FOLD.delete(t); saveFold(); return; }
    const fa = e.target.closest('button[data-fold]');
    if (fa) { const shut = fa.dataset.fold === 'close'; $('view').querySelectorAll('.rep').forEach((c2) => { c2.classList.toggle('col', shut); c2.querySelector('.tg').textContent = shut ? '+' : '−'; if (shut) FOLD.add(c2.dataset.title); else FOLD.delete(c2.dataset.title); }); saveFold(); return; }
    const ex = e.target.closest('td.exp');
    if (ex) { const tr = ex.closest('tr'); const open = tr.classList.toggle('open'); ex.querySelector('.pm').textContent = open ? '−' : '+'; let n = tr.nextElementSibling; while (n && n.classList.contains('sub')) { n.hidden = !open; n = n.nextElementSibling; } return; }
    const ib = e.target.closest('.imgbtn');
    if (ib) { shareImage([ib.closest('.rep')]); return; }
    const all = e.target.closest('.allimg');
    if (all) { shareImage([...$('view').querySelectorAll('.rep:not(.col)')], all.dataset.name); }
  }

  // ------------------------------------------------------------ image (for WhatsApp)
  const libs = {};
  function lib(name) { return (libs[name] = libs[name] || new Promise((res, rej) => { const s = document.createElement('script'); s.src = `lib-${name}.js`; s.onload = res; s.onerror = () => rej(new Error('Could not load ' + name)); document.head.appendChild(s); })); }
  async function shareImage(cards, pageName) {
    if (!cards.length) return;
    toast('Making image…', 8000);
    await lib('html2canvas');
    const box = document.createElement('div');
    box.style.cssText = 'position:fixed;left:-99999px;top:0;background:#fff;padding:16px;font-family:Arial,sans-serif;width:max-content;';
    const dt = ddmmyyyy(REP.reportDate);
    for (const cardEl of cards) {
      const h = document.createElement('div');
      h.style.cssText = 'font-weight:bold;font-size:15px;margin:0 0 8px;color:#111;';
      h.textContent = `EUDC JHANSI ${cardEl.dataset.title.toUpperCase()}${S.div ? ' (' + S.div + ')' : ''} DT ${dt}`;
      box.appendChild(h);
      cardEl.querySelectorAll('table').forEach((t) => {
        const c = t.cloneNode(true);
        c.querySelectorAll('tr[hidden]').forEach((x) => x.remove());
        c.style.cssText = 'border-collapse:collapse;font-family:Arial,sans-serif;font-size:12px;margin-bottom:18px;';
        c.querySelectorAll('td,th').forEach((x) => { x.style.cssText += ';border:1px solid #444;padding:5px 9px;color:#111;background:#fff;white-space:nowrap;position:static;text-decoration:none;cursor:default;'; });
        c.querySelectorAll('th').forEach((x) => { x.style.background = '#e8e8e8'; x.style.fontWeight = 'bold'; });
        c.querySelectorAll('th.gs').forEach((x) => { x.style.background = '#d6e6fb'; });
        c.querySelectorAll('th.gn').forEach((x) => { x.style.background = '#fde3c4'; });
        c.querySelectorAll('th.ga').forEach((x) => { x.style.background = '#dcefd9'; });
        c.querySelectorAll('tr.tot td').forEach((x) => { x.style.background = '#f5e6c8'; x.style.fontWeight = 'bold'; });
        box.appendChild(c);
      });
    }
    document.body.appendChild(box);
    try {
      const canvas = await html2canvas(box, { backgroundColor: '#ffffff', scale: Math.min(2, 16000 / Math.max(box.offsetHeight, 1)) });
      const blob = await new Promise((r) => canvas.toBlob(r, 'image/png'));
      const name = `${(pageName || cards[0].dataset.title).replace(/[^\w]+/g, '_')}_${REP.reportDate}.png`;
      const file = new File([blob], name, { type: 'image/png' });
      if (navigator.canShare && navigator.canShare({ files: [file] })) { try { await navigator.share({ files: [file] }); toast('Shared'); return; } catch (e) { if (e.name === 'AbortError') return; } }
      saveBlob(blob, name); toast('Image downloaded');
    } catch (e) { toast('Image failed: ' + e.message, 4000); }
    finally { box.remove(); }
  }
  function saveBlob(blob, name) { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 8000); }

  // ------------------------------------------------------------ DASHBOARD (same order as the Billing Operations App)
  function crossTab(rows, dim, firstHead) {
    const sum = (k) => rows.reduce((x, r) => x + (r[k] || 0), 0);
    const body = rows.map((r) => `<tr><td>${esc(r.key)}</td>
      <td>${N(r.smartTotal)}</td>${ck(r.smartBilled, { st: 'billed', dim, val: r.key, mt: 'Smart' })}${ck(r.smartUnbilled, { st: 'unbilled', dim, val: r.key, mt: 'Smart' })}${pc(r.smartBilledPct)}
      <td>${N(r.nonSmartTotal)}</td>${ck(r.nonSmartBilled, { st: 'billed', dim, val: r.key, mt: 'Non-Smart' })}${ck(r.nonSmartUnbilled, { st: 'unbilled', dim, val: r.key, mt: 'Non-Smart' })}${pc(r.nonSmartBilledPct)}
      <td>${N(r.total)}</td>${ck(r.billedTotal, { st: 'billed', dim, val: r.key })}${ck(r.unbilledTotal, { st: 'unbilled', dim, val: r.key })}${pc(r.totalBilledPct)}</tr>`).join('');
    const t = { st: sum('smartTotal'), sb: sum('smartBilled'), su: sum('smartUnbilled'), nt: sum('nonSmartTotal'), nb: sum('nonSmartBilled'), nu: sum('nonSmartUnbilled'), tt: sum('total'), tb: sum('billedTotal'), tu: sum('unbilledTotal') };
    return `<table class="t"><thead><tr><th rowspan="2">${firstHead}</th><th colspan="4" class="gs">Smart Meter</th><th colspan="4" class="gn">Non-Smart Meter</th><th colspan="4" class="ga">All Meter</th></tr>
      <tr>${['gs', 'gn', 'ga'].map((g) => `<th class="${g}">Total</th><th class="${g}">Billed</th><th class="${g}">Unbilled</th><th class="${g}">Billed %</th>`).join('')}</tr></thead><tbody>${body}
      <tr class="tot"><td>Grand Total</td><td>${N(t.st)}</td>${ck(t.sb, { st: 'billed', mt: 'Smart' })}${ck(t.su, { st: 'unbilled', mt: 'Smart' })}${pc(t.st ? t.sb / t.st : null)}
      <td>${N(t.nt)}</td>${ck(t.nb, { st: 'billed', mt: 'Non-Smart' })}${ck(t.nu, { st: 'unbilled', mt: 'Non-Smart' })}${pc(t.nt ? t.nb / t.nt : null)}
      <td>${N(t.tt)}</td>${ck(t.tb, { st: 'billed' })}${ck(t.tu, { st: 'unbilled' })}${pc(t.tt ? t.tb / t.tt : null)}</tr></tbody></table>`;
  }
  const defCells = (r, sp) => ['RDF', 'CDF', 'IDF'].map((t) => ck(r[t.toLowerCase()] || 0, { st: 'defective', pend: 1, dt: t, ...sp })).join('') + ck(r.oth || 0, { st: 'defective', pend: 1, dto: 1, ...sp }) + ck(r.defPending || 0, { st: 'defective', pend: 1, ...sp });
  const sumDef = (rows, totKey) => { const o = { rdf: 0, cdf: 0, idf: 0, oth: 0, defPending: 0 }; rows.forEach((r) => { o.rdf += r.rdf || 0; o.cdf += r.cdf || 0; o.idf += r.idf || 0; o.oth += r.oth || 0; o.defPending += r[totKey] || 0; }); return o; };
  // day-wise billed, by load range (5-9 KW split by who bills it)
  function dailyLoadTable() {
    const rows = (REP.reports.daily || []).filter((r) => r.div === (S.div || '')).slice().sort((a, b) => b.date.localeCompare(a.date));
    const COLS = [['lB5', 'Below 5 KW', { lb: 'BELOW 5KW' }, ''], ['l59S', '5 to 9 KW — SBM', { lb: 'BTW 5 TO 9 KW', seg: 'SBM' }, 'gn'], ['l59M', '5 to 9 KW — MRI', { lb: 'BTW 5 TO 9 KW', seg: 'MRI' }, 'gn'], ['l59O', '5 to 9 KW — Smart & others', { lb: 'BTW 5 TO 9 KW', seg: 'OTH' }, 'gn'], ['l10', '10 to 49 KW', { lb: 'BTW 10 TO 49 KW' }, ''], ['l50', 'Above 50 KW', { lb: 'ABOVE 50KW' }, ''], ['lOB', 'Others / blank', { lb: 'OTHERS/BLANK' }, '']];
    if (!rows.length || rows[0].lB5 === undefined) return '<div class="empty">Available after the next publish</div>';
    const tot = { total: 0 }; COLS.forEach(([k]) => { tot[k] = rows.reduce((x, r) => x + (r[k] || 0), 0); }); tot.total = rows.reduce((x, r) => x + r.total, 0);
    const cells = (r, bd) => COLS.map(([k, , sp]) => ck(r[k] || 0, { st: 'billed', ...sp, bd })).join('') + ck(r.total, { st: 'billed', bd });
    return `<table class="t"><thead><tr><th>Bill Date</th>${COLS.map(([, h, , c]) => `<th class="${c}">${h}</th>`).join('')}<th class="ga">Total Billed</th></tr></thead><tbody>
      <tr class="tot"><td>Total (this month's report)</td>${cells(tot)}</tr>
      ${rows.slice(0, 31).map((r) => `<tr><td>${esc(r.date ? ddmmyyyy(r.date) : '(no date)')}</td>${cells(r, r.date || '-')}</tr>`).join('')}</tbody></table>`;
  }
  // unbilled cases by months pending
  const MOB = [['m1', 'Up to 1 month'], ['m2', '2 months'], ['m3', '3 to 5 months'], ['m6', '6 to 11 months'], ['m12', '1 year & more'], ['mu', 'No last bill date']];
  const mobOf = (r) => (r.mo === '' || r.mo === null || r.mo === undefined ? 'mu' : +r.mo <= 1 ? 'm1' : +r.mo === 2 ? 'm2' : +r.mo <= 5 ? 'm3' : +r.mo <= 11 ? 'm6' : 'm12');
  const mobCells = (r, sp) => MOB.map(([k]) => ck(r[k] || 0, { st: 'unbilled', mob: k, ...sp })).join('') + ck((r.unbNS || 0) + (r.unbS || 0), { st: 'unbilled', ...sp });
  const mobHead = MOB.map(([k, h]) => `<th class="${k === 'm12' || k === 'm6' ? 'gn' : ''}">${h}</th>`).join('') + '<th class="ga">Total unbilled</th>';
  const mobSum = (rows) => { const o = { unbNS: 0, unbS: 0 }; rows.forEach((r) => { o.unbNS += r.unbNS || 0; o.unbS += r.unbS || 0; MOB.forEach(([k]) => { o[k] = (o[k] || 0) + (r[k] || 0); }); }); return o; };
  function dailyTable() {
    const rows = (REP.reports.daily || []).filter((r) => r.div === (S.div || '')).slice().sort((a, b) => b.date.localeCompare(a.date));
    const keys = ['smart', 'nonSmart', 'total', 'MU', 'PROV', 'IDF', 'RDF', 'CDF', 'UM'];
    const tot = Object.fromEntries(keys.map((k) => [k, rows.reduce((x, r) => x + r[k], 0)]));
    const cells = (r, bd) => `${ck(r.smart, { st: 'billed', mt: 'Smart', bd })}${ck(r.nonSmart, { st: 'billed', mt: 'Non-Smart', bd })}${ck(r.total, { st: 'billed', bd })}` + ['MU', 'PROV', 'IDF', 'RDF', 'CDF', 'UM'].map((b) => ck(r[b], { st: 'billed', base: b, bd })).join('');
    return `<table class="t"><thead><tr><th>Bill Date</th><th class="gs">Smart Billed</th><th class="gn">Non-Smart Billed</th><th class="ga">Total Billed</th><th>MU</th><th>PROV</th><th>IDF</th><th>RDF</th><th>CDF</th><th>UM</th></tr></thead><tbody>
      <tr class="tot"><td>Total (this month's report)</td>${cells(tot)}</tr>
      ${rows.slice(0, 31).map((r) => `<tr><td>${esc(r.date ? ddmmyyyy(r.date) : '(no date)')}</td>${cells(r, r.date || '-')}</tr>`).join('')}</tbody></table>`;
  }
  function simpleSubTable(rows, extra = {}, totExtra = {}) {
    const s = { t: 0, b: 0, u: 0 }; rows.forEach((r) => { s.t += r.total; s.b += r.billed; s.u += r.unbilled; });
    return `<table class="t"><thead><tr><th>Substation</th><th>Total</th><th>Billed</th><th>Unbilled</th><th>Billed %</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${esc(r.substation)}</td><td>${N(r.total)}</td>${ck(r.billed, { st: 'billed', dim: 'substation', val: r.substation, mt: 'Non-Smart', ...extra })}${ck(r.unbilled, { st: 'unbilled', dim: 'substation', val: r.substation, mt: 'Non-Smart', ...extra })}${pc(r.billedPct)}</tr>`).join('')}
      <tr class="tot"><td>Grand Total</td><td>${N(s.t)}</td>${ck(s.b, { st: 'billed', mt: 'Non-Smart', ...extra, ...totExtra })}${ck(s.u, { st: 'unbilled', mt: 'Non-Smart', ...extra, ...totExtra })}${pc(s.t ? s.b / s.t : null)}</tr></tbody></table>`;
  }
  function provSummary(rows, dim, head, order) {
    rows = rows.slice(); if (order) rows.sort((a, b) => (order.indexOf(a.key) + 99) % 99 - (order.indexOf(b.key) + 99) % 99); else rows.sort((a, b) => b.total - a.total);
    const s = { p: 0, u: 0, t: 0 }; rows.forEach((r) => { s.p += r.provBilled; s.u += r.unbilled; s.t += r.total; });
    return `<table class="t"><thead><tr><th>${head}</th><th>Prov Billed</th><th>Unbilled</th><th>Total</th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${esc(r.key)}</td>${ck(r.provBilled, { st: 'provbilled', dim, val: r.key })}${ck(r.unbilled, { st: 'unbilled', dim, val: r.key, fmt: 'detailed' })}<td>${N(r.total)}</td></tr>`).join('')}
      <tr class="tot"><td>Grand Total</td>${ck(s.p, { st: 'provbilled' })}${ck(s.u, { st: 'unbilled', fmt: 'detailed' })}<td>${N(s.t)}</td></tr></tbody></table>`;
  }
  async function viewDash() {
    const s = rep('summary') || {}, nf = rep('smart-meter/not-fed') || {};
    const tr = REP.reports.trends || [];
    const a = tr[tr.length - 2], b = tr[tr.length - 1];
    const chg = a && b ? (b.billed / (b.billed + b.unbilled) - a.billed / (a.billed + a.unbilled)) * 100 : null;
    const bp = s.totalConnections ? (s.totalBilled / s.totalConnections) * 100 : 0;
    const dly = (REP.reports.daily || []).filter((r) => r.div === (S.div || ''));
    const dsum = (k) => dly.reduce((x, r) => x + r[k], 0);
    const mr = rep('company/mr-report') || []; const ms = { r: 0, c: 0, t: 0 }; mr.forEach((r) => { ms.r += r.rdf; ms.c += r.cdf; ms.t += r.total; });
    const cl = rep('defective/clerk-progress') || [];
    const jw = rep('x/je-work') || [], cw = rep('x/clerk-work') || [];
    const pu = rep('billing-quality/prov-unbilled-summary') || { byLoad: [], byCategory: [], bySubstation: [] };
    const subNS = rep('company/substation-nonsmart') || [];
    if (S.noL5 === undefined) S.noL5 = ![1, 4, 7, 10].includes(new Date(REP.reportDate).getMonth() + 1);
    const noL5 = S.noL5;
    const known = new Set(REP.reports.knownSubs || []);
    $('view').innerHTML = `
      <div class="tiles">
        <div class="tile"><div class="l">Connections</div><div class="v">${N(s.totalConnections)}</div><div class="s">${S.div || 'both divisions'}</div></div>
        <div class="tile"><div class="l">Billed</div><div class="v ${pctCls(bp)}">${P(bp, 2)}</div><div class="s">${N(s.totalBilled)}${chg !== null && !S.div ? ` · <span class="${chg >= 0 ? 'good' : 'bad'}">${chg >= 0 ? '▲' : '▼'} ${Math.abs(chg).toFixed(2)} pts</span>` : ''}</div></div>
        <div class="tile"><div class="l">Smart billed</div><div class="v">${N(dsum('smart'))}</div><div class="s">Non-smart billed ${N(dsum('nonSmart'))}</div></div>
        <div class="tile"><div class="l">RDF / CDF / IDF bills</div><div class="v">${N(dsum('RDF'))} / ${N(dsum('CDF'))} / ${N(dsum('IDF'))}</div><div class="s">PROV ${N(dsum('PROV'))}</div></div>
        <div class="tile"><div class="l">Unbilled</div><div class="v bad">${N(s.totalUnbilled)}</div><div class="s">defective pending ${N(s.totalPendingDefective)}</div></div>
        <div class="tile"><div class="l">Smart meters not fed</div><div class="v">${N(nf.totalNotFed)}</div><div class="s">of ${N(nf.totalInstalled)} installed</div></div>
      </div>
      ${tabTools('Dashboard')}
      ${movementCard()}
      ${card('Daily Billed Summary', dailyTable(), 'Bills in the latest billed report, by bill date. RDF / IDF are by meter-read remark, CDF = ceiling bills, UM = others.')}
      ${card('Daily Billed Summary — Load-Wise', dailyLoadTable(), '5 to 9 KW is split into non-smart billed by SBM, non-smart billed by MRI, and smart meters.')}
      ${card('Load-Wise', crossTab(rep('company/load-wise') || [], 'load', 'Load Range'))}
      ${card('Category-Wise', crossTab(rep('company/category-wise') || [], 'category', 'Category'))}
      <div class="card dl" id="l5box"><label style="display:flex;gap:8px;align-items:center;font-weight:600"><input type="checkbox" id="l5" ${noL5 ? 'checked' : ''} style="width:20px;height:20px"> Non-Smart 5-9KW report: leave out LMV-5</label><p class="muted" style="margin:6px 0 0">LMV-5 is billed quarterly (QB cycle) — bills come only in Jan, Apr, Jul and Oct. Untick to include them.</p></div>
      ${(rep(noL5 ? 'x/5to9-no-lmv5' : 'company/nonsmart-5to9-by-firm') || []).map((f) => card(`Non-Smart 5-9KW Billing — ${f.firm}${noL5 ? ' (excluding LMV-5)' : ''}`, simpleSubTable(f.rows, { firm: f.firm, lb: 'BTW 5 TO 9 KW', ...(noL5 ? { xcat: 'LMV5' } : {}) }))).join('')}
      ${card('Substation-Wise (Non-Smart Only)', simpleSubTable(subNS.filter((r) => known.has(r.substation)), {}, { ks: 1 }), 'Only the 16 known substations.')}
      ${card('PROV Billed + Unbilled — Load Range Wise', provSummary(pu.byLoad, 'load', 'Load Range', LOAD_ORDER))}
      ${card('PROV Billed + Unbilled — Category Wise', provSummary(pu.byCategory, 'category', 'Category'))}
      ${card('PROV Billed + Unbilled — Substation Wise', provSummary(pu.bySubstation, 'substation', 'Substation'))}
      ${card('JE-Wise Site Work', `<table class="t"><thead><tr><th rowspan="2">JE</th><th rowspan="2">Substations</th><th colspan="2" class="gn">Unbilled</th><th colspan="5" class="ga">Defective bills pending</th></tr><tr><th class="gn">Non-Smart</th><th class="gn">Smart</th><th class="ga">RDF</th><th class="ga">CDF</th><th class="ga">IDF</th><th class="ga">Other</th><th class="ga">Total</th></tr></thead><tbody>
        ${jw.map((r) => `<tr><td class="exp" style="text-align:left"><span class="pm">+</span> ${esc(r.je)}</td><td style="text-align:left;white-space:normal;min-width:150px">${esc(r.subs.map(shortSub).join(', '))}</td>${ck(r.unbNS, { st: 'unbilled', je: r.je, mt: 'Non-Smart' })}${ck(r.unbS, { st: 'unbilled', je: r.je, mt: 'Smart' })}${defCells(r, { je: r.je })}</tr>`
          + (r.bySub || []).map((x) => { const sp = { je: r.je, dim: 'substation', val: x.substation }; return `<tr class="sub" hidden><td></td><td style="text-align:left">↳ ${esc(x.substation)}</td>${ck(x.unbNS, { st: 'unbilled', mt: 'Non-Smart', ...sp })}${ck(x.unbS, { st: 'unbilled', mt: 'Smart', ...sp })}${defCells(x, sp)}</tr>`; }).join('')).join('')}
        <tr class="tot"><td colspan="2">Grand Total</td>${ck(jw.reduce((x, r) => x + r.unbNS, 0), { st: 'unbilled', mt: 'Non-Smart' })}${ck(jw.reduce((x, r) => x + r.unbS, 0), { st: 'unbilled', mt: 'Smart' })}${defCells(sumDef(jw, 'defPending'), {})}</tr></tbody></table>`, 'Tap + beside a JE to see the substation-wise break-up. JE of each substation is as per Work Assignment.xlsx on the office PC. A bill with two defects is counted under both, so the break-up can add to more than the total.')}
      ${card('JE-Wise Unbilled — Months Pending', jw.length && jw.some((r) => MOB.some(([k]) => r[k] !== undefined)) ? `<table class="t"><thead><tr><th>JE</th><th>Substation</th>${mobHead}</tr></thead><tbody>
        ${jw.map((r) => `<tr><td class="exp" style="text-align:left"><span class="pm">+</span> ${esc(r.je)}</td><td style="text-align:left">All ${r.subs.length} substations</td>${mobCells(r, { je: r.je })}</tr>`
          + (r.bySub || []).map((x) => `<tr class="sub" hidden><td></td><td style="text-align:left">↳ ${esc(x.substation)}</td>${mobCells(x, { je: r.je, dim: 'substation', val: x.substation })}</tr>`).join('')).join('')}
        <tr class="tot"><td colspan="2">Grand Total</td>${mobCells(mobSum(jw), {})}</tr></tbody></table>` : '<div class="empty">Available after the next publish</div>', 'Smart and non-smart together. Months are counted from the last bill date; "Up to 1 month" is the current cycle, not yet billed this month. Tap + for substations.')}
      ${card('Clerk-Wise Work', `<table class="t"><thead><tr><th rowspan="2">Billing Clerk</th><th colspan="2" class="gn">Unbilled</th><th colspan="5" class="ga">Defective bills pending</th></tr><tr><th class="gn">Non-Smart</th><th class="gn">Smart</th><th class="ga">RDF</th><th class="ga">CDF</th><th class="ga">IDF</th><th class="ga">Other</th><th class="ga">Total</th></tr></thead><tbody>
        ${cw.map((r) => `<tr><td style="text-align:left">${esc(r.clerk)}</td>${ck(r.unbNS, { st: 'unbilled', clerk: r.clerk, mt: 'Non-Smart' })}${ck(r.unbS, { st: 'unbilled', clerk: r.clerk, mt: 'Smart' })}${defCells({ ...r, defPending: r.total - r.resolved }, { clerk: r.clerk })}</tr>`).join('')}
        <tr class="tot"><td>Grand Total</td>${ck(cw.reduce((x, r) => x + r.unbNS, 0), { st: 'unbilled', mt: 'Non-Smart' })}${ck(cw.reduce((x, r) => x + r.unbS, 0), { st: 'unbilled', mt: 'Smart' })}${defCells(sumDef(cw.map((r) => ({ ...r, defPending: r.total - r.resolved })), 'defPending'), {})}</tr></tbody></table>`, 'Clerk by category / load as per Work Assignment.xlsx on the office PC.')}
      ${card('Clerk-Wise Unbilled — Months Pending', cw.some((r) => MOB.some(([k]) => r[k] !== undefined)) ? `<table class="t"><thead><tr><th>Billing Clerk</th>${mobHead}</tr></thead><tbody>
        ${cw.map((r) => `<tr><td style="text-align:left">${esc(r.clerk)}</td>${mobCells(r, { clerk: r.clerk })}</tr>`).join('')}
        <tr class="tot"><td>Grand Total</td>${mobCells(mobSum(cw), {})}</tr></tbody></table>` : '<div class="empty">Available after the next publish</div>', 'Smart and non-smart together.')}
      ${card('Defective Bills — Correction Progress', `<table class="t"><thead><tr><th>Billing Clerk</th><th>Total Assigned</th><th>Resolved</th><th>Pending</th><th>Progress</th></tr></thead><tbody>
        ${cl.map((r) => `<tr><td>${esc(r.clerk)}</td>${ck(r.total, { st: 'defective', clerk: r.clerk })}<td>${N(r.resolved)}</td>${ck(r.pending, { st: 'defective', clerk: r.clerk, pend: 1 })}<td>${P(r.total ? (r.resolved / r.total) * 100 : 0, 0)}</td></tr>`).join('')}</tbody></table>`)}
      <p class="muted">Report date ${esc(REP.reportDate)} · master ${esc(REP.masterFile || '—')} · updated ${new Date(REP.builtAt).toLocaleString('en-IN')}</p>`;
  }

  // ------------------------------------------------------------ COMMERCIAL
  async function viewCommercial() {
    const heads = ['Total No', 'Total Load(MW)', 'Billed No', 'Billed Energy(MU)', 'Curr. Assess. (Lacs)', 'Paid Count', 'Paid Amt (Lacs)', 'Total Assess. (Lacs)', 'Turn Up %', 'ABR'];
    const row = (r, cls = '', sp = null) => `<tr class="${cls}"><td>${esc(r.key)}</td><td>${N(r.totalNo)}</td><td>${N(r.totalLoad, 2)}</td>${sp ? ck(r.billedNo, sp) : `<td>${N(r.billedNo)}</td>`}<td>${N(r.billedEnergyMU, 2)}</td><td>${N(r.currentAssessmentLacs, 2)}</td><td>${N(r.paidCount)}</td><td>${N(r.paidAmountLacs, 2)}</td><td>${N(r.totalAssessmentLacs, 2)}</td><td>${P(r.turnUpPct, 2)}</td><td>${N(r.abr, 2)}</td></tr>`;
    const total = (rows) => { const t = { key: 'Grand Total' }; for (const k of ['totalNo', 'totalLoad', 'billedNo', 'billedEnergyMU', 'currentAssessmentLacs', 'paidCount', 'paidAmountLacs', 'totalAssessmentLacs']) t[k] = rows.reduce((x, r) => x + (+r[k] || 0), 0); t.turnUpPct = t.billedNo ? (t.paidCount / t.billedNo) * 100 : 0; t.abr = t.billedEnergyMU ? t.currentAssessmentLacs / (t.billedEnergyMU * 10) : 0; return t; };
    const tb = (rows, head, dim) => `<table class="t"><thead><tr><th>${head}</th>${heads.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => row(r, '', { st: 'billed', dim, val: r.key })).join('')}${row(total(rows), 'tot', { st: 'billed' })}</tbody></table>`;
    $('view').innerHTML = tabTools('Commercial') + card('Category-Wise Billing Details', tb(rep('commercial/category-wise') || [], 'Category', 'category')) + card('Substation-Wise Billing Details', tb(rep('commercial/substation-wise') || [], 'Substation', 'substation'), 'Only the 16 known substations are shown individually; the rest are under "Unknown Substation".');
  }

  // ------------------------------------------------------------ METER READER + SUBSTATION-WISE (non-smart bills)
  const dm = (iso) => (iso ? `${iso.slice(8, 10)}/${iso.slice(5, 7)}` : 'No date');
  const mrName = (ag) => (MRD.mrs[ag] || [])[0] || '';
  function cube() { const c = MRD.cols; return MRD.rows.map((r) => Object.fromEntries(c.map((k, i) => [k, r[i]]))).filter((r) => !S.div || r.d === S.div); }
  // group cube rows by a key -> { key, n, rdf, cdf, idf, prov, by: {date: {n, rdf, cdf}} }
  function groupCube(rows, keyOf) {
    const g = {};
    for (const r of rows) {
      const k = keyOf(r); const o = (g[k] = g[k] || { key: k, n: 0, rdf: 0, cdf: 0, idf: 0, prov: 0, by: {}, subs: new Set() });
      o.n += r.n; o.rdf += r.rdf; o.cdf += r.cdf; o.idf += r.idf; o.prov += r.prov; o.subs.add(r.s);
      const d = (o.by[r.bd] = o.by[r.bd] || { n: 0, rdf: 0, cdf: 0 }); d.n += r.n; d.rdf += r.rdf; d.cdf += r.cdf;
    }
    return Object.values(g).sort((a, b) => b.n - a.n);
  }
  const datesOf = (rows) => [...new Set(rows.map((r) => r.bd))].sort((a, b) => b.localeCompare(a));
  const pctOf = (a, b) => (b ? `<td>${(a / b * 100).toFixed(1)}%</td>` : '<td>—</td>');
  // matrix: one row per group, one column per bill date (newest first)
  function dateMatrix(groups, dates, firstHead, firstCells, cellSpec, opts = {}) {
    const tot = { n: 0, rdf: 0, cdf: 0, by: {} };
    groups.forEach((g) => { tot.n += g.n; tot.rdf += g.rdf; tot.cdf += g.cdf; dates.forEach((d) => { tot.by[d] = (tot.by[d] || 0) + ((g.by[d] || {}).n || 0); }); });
    const span = firstHead.length;
    return `<table class="t"><thead><tr>${firstHead.map((h) => `<th>${h}</th>`).join('')}<th class="ga">Total</th>${dates.map((d) => `<th>${dm(d)}</th>`).join('')}${opts.defects ? '<th class="gn">RDF</th><th class="gn">CDF</th>' : ''}</tr></thead><tbody>
      ${groups.map((g) => `<tr>${firstCells(g)}${ck(g.n, cellSpec(g))}${dates.map((d) => ck((g.by[d] || {}).n || 0, { ...cellSpec(g), bd: d || '-' })).join('')}${opts.defects ? ck(g.rdf, { ...opts.defSpec(g), dt: 'RDF' }) + ck(g.cdf, { ...opts.defSpec(g), dt: 'CDF' }) : ''}</tr>`).join('')}
      <tr class="tot"><td colspan="${span}">Grand Total</td>${ck(tot.n, opts.totSpec || { st: 'billed', mt: 'Non-Smart' })}${dates.map((d) => ck(tot.by[d], { ...(opts.totSpec || { st: 'billed', mt: 'Non-Smart' }), bd: d || '-' })).join('')}${opts.defects ? ck(tot.rdf, { ...(opts.totDef || { st: 'defective', mt: 'Non-Smart' }), dt: 'RDF' }) + ck(tot.cdf, { ...(opts.totDef || { st: 'defective', mt: 'Non-Smart' }), dt: 'CDF' }) : ''}</tr></tbody></table>`;
  }
  const agCells = (g) => `<td>${esc(g.key || '(blank)')}</td><td style="text-align:left">${esc(mrName(g.key))}</td>`;
  const agSpec = (g) => ({ st: 'billed', mt: 'Non-Smart', agent: g.key || '(blank)' });
  const agDef = (g) => ({ st: 'defective', mt: 'Non-Smart', agent: g.key || '(blank)' });

  async function viewMR() {
    const rows = cube(); const mrsG = groupCube(rows, (r) => r.ag); const dates = datesOf(rows); const latest = dates.find((d) => d) || '';
    const T = { n: 0, day: 0, rdf: 0, cdf: 0, man: 0, pro: 0, ocr: 0, tb: 0 };
    const sum = mrsG.map((g) => { const m = MRD.mrs[g.key] || []; const day = (g.by[latest] || {}).n || 0; T.n += g.n; T.day += day; T.rdf += g.rdf; T.cdf += g.cdf; T.man += m[2] || 0; T.pro += m[3] || 0; T.ocr += m[4] || 0; T.tb += m[5] || 0;
      return `<tr>${agCells(g)}<td>${esc(m[1] || '')}</td>${ck(day, { ...agSpec(g), bd: latest })}${ck(g.n, agSpec(g))}${pctOf(m[4], m[5])}${pctOf(m[3], m[5])}${pctOf(m[2], m[5])}${ck(g.rdf, { ...agDef(g), dt: 'RDF' })}${ck(g.cdf, { ...agDef(g), dt: 'CDF' })}${pctOf(g.rdf + g.cdf, g.n)}</tr>`; }).join('');
    // progressive (running) total up to each date
    const asc = dates.filter((d) => d).slice().reverse();
    const prog = `<table class="t"><thead><tr><th>MR ID</th><th>Name</th>${dates.filter((d) => d).map((d) => `<th>${dm(d)}</th>`).join('')}</tr></thead><tbody>
      ${mrsG.map((g) => { let run = (g.by[''] || {}).n || 0; const at = {}; asc.forEach((d) => { run += (g.by[d] || {}).n || 0; at[d] = run; }); return `<tr>${agCells(g)}${dates.filter((d) => d).map((d) => `<td>${N(at[d])}</td>`).join('')}</tr>`; }).join('')}
      ${(() => { let run = 0; const at = {}; asc.forEach((d) => { run += mrsG.reduce((x, g) => x + ((g.by[d] || {}).n || 0), 0); at[d] = run; }); return `<tr class="tot"><td colspan="2">Grand Total</td>${dates.filter((d) => d).map((d) => `<td>${N(at[d])}</td>`).join('')}</tr>`; })()}</tbody></table>`;
    // daily RDF / CDF: only the dates that have any
    const dd = dates.filter((d) => mrsG.some((g) => (g.by[d] || {}).rdf || (g.by[d] || {}).cdf));
    const defG = mrsG.filter((g) => g.rdf || g.cdf).sort((a, b) => b.rdf + b.cdf - (a.rdf + a.cdf));
    const defT = (d, k) => defG.reduce((x, g) => x + ((g.by[d] || {})[k] || 0), 0);
    const defTable = `<table class="t"><thead><tr><th rowspan="2">MR ID</th><th rowspan="2">Name</th><th colspan="2" class="ga">Total</th>${dd.map((d) => `<th colspan="2">${dm(d)}</th>`).join('')}</tr><tr><th class="ga">RDF</th><th class="ga">CDF</th>${dd.map(() => '<th>RDF</th><th>CDF</th>').join('')}</tr></thead><tbody>
      ${defG.map((g) => `<tr>${agCells(g)}${ck(g.rdf, { ...agDef(g), dt: 'RDF' })}${ck(g.cdf, { ...agDef(g), dt: 'CDF' })}${dd.map((d) => ck((g.by[d] || {}).rdf || 0, { ...agDef(g), dt: 'RDF', bd: d || '-' }) + ck((g.by[d] || {}).cdf || 0, { ...agDef(g), dt: 'CDF', bd: d || '-' })).join('')}</tr>`).join('')}
      <tr class="tot"><td colspan="2">Grand Total</td>${ck(T.rdf, { st: 'defective', mt: 'Non-Smart', dt: 'RDF' })}${ck(T.cdf, { st: 'defective', mt: 'Non-Smart', dt: 'CDF' })}${dd.map((d) => ck(defT(d, 'rdf'), { st: 'defective', mt: 'Non-Smart', dt: 'RDF', bd: d || '-' }) + ck(defT(d, 'cdf'), { st: 'defective', mt: 'Non-Smart', dt: 'CDF', bd: d || '-' })).join('')}</tr></tbody></table>`;
    const up = MRD.mrUploaded ? ddmmyyyy(MRD.mrUploaded.slice(0, 10)) : '';
    $('view').innerHTML = tabTools('Meter Reader')
      + card('Meter Reader — Billing Summary', `<table class="t"><thead><tr><th>MR ID</th><th>Name</th><th>Mobile No</th><th class="gs">Billed on ${dm(latest)}</th><th class="ga">Progressive Total</th><th>OCR %</th><th>Probe %</th><th>Manual %</th><th class="gn">RDF</th><th class="gn">CDF</th><th class="gn">RDF+CDF %</th></tr></thead><tbody>${sum}
        <tr class="tot"><td colspan="3">Grand Total</td>${ck(T.day, { st: 'billed', mt: 'Non-Smart', bd: latest })}${ck(T.n, { st: 'billed', mt: 'Non-Smart' })}${pctOf(T.ocr, T.tb)}${pctOf(T.pro, T.tb)}${pctOf(T.man, T.tb)}${ck(T.rdf, { st: 'defective', mt: 'Non-Smart', dt: 'RDF' })}${ck(T.cdf, { st: 'defective', mt: 'Non-Smart', dt: 'CDF' })}${pctOf(T.rdf + T.cdf, T.n)}</tr></tbody></table>`,
        `Non-smart bills of this month's billed report, by the meter reader's login ID. OCR / Probe / Manual % come from the meter reader report loaded in the Billing Operations App${up ? ' on ' + up : ''}${Object.keys(MRD.mrs).length ? '' : ' — <b>not loaded yet, so these columns and the names are blank</b>'}; they are the reader's overall figures, not day-wise.`)
      + mrTargetCards()
      + card('Meter Reader — Daily Billed', dateMatrix(mrsG, dates, ['MR ID', 'Name'], agCells, agSpec), 'Bills made on each bill date, newest date first.')
      + card('Meter Reader — Daily RDF / CDF', defG.length ? defTable : '<div class="empty">No RDF / CDF bills</div>', 'Only dates and meter readers having RDF or CDF bills are shown.');
  }

  async function viewSubwise() {
    const rows = cube(); const dates = datesOf(rows); const known = KNOWN();
    const subsG = groupCube(rows, (r) => r.s);
    const names = subsG.map((g) => g.key);
    if (S.sub === undefined || (S.sub && !names.includes(S.sub))) S.sub = names.find((n) => known.has(n)) || names[0] || '';
    const subSpec = (g) => ({ st: 'billed', mt: 'Non-Smart', dim: 'substation', val: g.key });
    const one = (sname) => { const rs = rows.filter((r) => r.s === sname); const g = groupCube(rs, (r) => r.ag); const base = { dim: 'substation', val: sname };
      return card(`${shortSub(sname)} — Meter Reader Daily Billing`, dateMatrix(g, datesOf(rs), ['MR ID', 'Name'], agCells, (x) => ({ ...agSpec(x), ...base }), { defects: 1, defSpec: (x) => ({ ...agDef(x), ...base }), totSpec: { st: 'billed', mt: 'Non-Smart', ...base }, totDef: { st: 'defective', mt: 'Non-Smart', ...base } })); };
    $('view').innerHTML = tabTools('Substation-Wise')
      + card('Substation-Wise Daily Billing (Non-Smart)', dateMatrix(subsG, dates, ['Substation'], (g) => `<td>${esc(g.key)}</td>`, subSpec, { defects: 1, defSpec: (g) => ({ st: 'defective', mt: 'Non-Smart', dim: 'substation', val: g.key }) }), 'Non-smart bills made on each bill date, newest date first.')
      + `<div class="card dl"><label style="font-weight:600">Meter readers billing in substation</label><select id="subsel" style="margin-top:6px"><option value="">All substations (one report each)</option>${names.map((n) => `<option value="${esc(n)}" ${S.sub === n ? 'selected' : ''}>${esc(n)}</option>`).join('')}</select></div>`
      + (S.sub ? one(S.sub) : names.map(one).join(''))
      + subRequirementCard();
  }

  // ------------------------------------------------------------ FIELD ATR (kept in the Google Sheet behind the ATR link)
  const ATR = { map: {}, at: 0, seeded: false };
  const akOf = (r) => (r.now ? (r.now === 'UNBILLED' ? 'unbilled' : 'defective') : r._kind ? (r._kind === 'UNBILLED' ? 'unbilled' : 'defective') : r.k ? r.k : r.mo !== undefined && r.isd === undefined ? 'unbilled' : 'defective');
  const atrOf = (r) => ATR.map[r.a + '|' + akOf(r)];
  const atrText = (r) => { const x = atrOf(r); return x ? `${x.atr}${x.rem ? ' - ' + x.rem : ''} (${x.by || '—'}, ${dm(String(x.ts).slice(0, 10))})` : ''; };
  const atrPut = (k, atr, rem, by, ts, ph) => { if (String(ts).slice(0, 7) < REP.reportDate.slice(0, 7)) return; const o = ATR.map[k]; if (!o || String(ts) >= String(o.ts)) ATR.map[k] = { atr, rem, by, ts: String(ts), ph: ph || '' }; };
  async function atrRefresh(force) {
    if (!ATR.seeded) { ATR.seeded = true; for (const [k, atr, rem, by, ts, ph] of MRD.atrSnap || []) atrPut(k, atr, rem, by, ts, ph); }
    if (!MRD.atr || (!force && Date.now() - ATR.at < 60000)) return;
    try {
      const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 6000);
      const r = await fetch(`${MRD.atr.url}?action=list&key=${encodeURIComponent(MRD.atr.key)}`, { signal: ctl.signal }); clearTimeout(tm);
      const j = await r.json();
      if (j.ok) { for (const x of j.rows || []) atrPut(String(x.acct).replace(/^0+/, '') + '|' + x.kind, x.atr || '', x.remark || '', x.by || '', x.ts || '', x.photo || ''); ATR.at = Date.now(); }
    } catch (e) { /* offline or slow: keep what we have */ }
  }
  // a photo is shrunk on the phone (long side 1280 px, JPEG) before it is sent, so it uploads quickly on mobile data
  async function shrinkPhoto(file) {
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = () => rej(new Error('not a photo')); im.src = url; });
      const k = Math.min(1, 1280 / Math.max(img.width, img.height)); const c = document.createElement('canvas'); c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      return c.toDataURL('image/jpeg', 0.7).split(',')[1];
    } finally { URL.revokeObjectURL(url); }
  }
  async function atrSave(acct, kind, atr, remark, photo) {
    const by = ME.name || ROLE_NAME[ROLE] || ROLE;
    const r = await fetch(MRD.atr.url, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ key: MRD.atr.key, rows: [{ acct, kind, atr, remark, by, role: ROLE, photo: photo || '' }] }) });
    const j = await r.json(); if (!j.ok) throw new Error(j.error || 'not saved');
    const old = ATR.map[acct + '|' + kind];
    ATR.map[acct + '|' + kind] = { atr, rem: remark, by, ts: new Date().toISOString(), ph: (j.photos && j.photos[0]) || (photo ? '' : (old && old.ph) || '') };
    return j;
  }

  // ------------------------------------------------------------ WHO IS USING THIS PHONE ("My work")
  let ME = {}; try { ME = JSON.parse(localStorage.getItem('bwt-me') || '{}') || {}; } catch (e) { ME = {}; }
  const saveMe = () => { try { localStorage.setItem('bwt-me', JSON.stringify(ME)); } catch (e) { /* private mode */ } };
  const meSpec = () => (ME.type === 'je' ? { je: ME.name } : ME.type === 'clerk' ? { clerk: ME.name } : {});
  // priority of an unbilled case: bigger load, longer unbilled, bigger dues first (max 100)
  function prio(r) {
    const l = +r.l || 0, mo = r.mo === '' || r.mo === undefined ? null : +r.mo, o = +r.o || 0;
    const lp = l > 50 ? 40 : l >= 10 ? 30 : l >= 5 ? 20 : l >= 2 ? 8 : 4;
    const mp = mo === null ? 10 : mo >= 12 ? 30 : mo >= 6 ? 25 : mo >= 3 ? 18 : mo >= 2 ? 12 : mo >= 1 ? 6 : 0;
    const op = o >= 100000 ? 30 : o >= 25000 ? 22 : o >= 5000 ? 12 : o > 0 ? 4 : 0;
    return lp + mp + op;
  }
  function mrStats() {
    const rows = cube(); const g = groupCube(rows, (r) => r.ag); const dates = datesOf(rows).filter((d) => d); const latest = dates[0] || REP.reportDate;
    const rd = new Date(REP.reportDate); const dim = new Date(rd.getFullYear(), rd.getMonth() + 1, 0).getDate(); const elapsed = Math.max(1, +latest.slice(8, 10)); const left = Math.max(0, dim - elapsed);
    const list = g.filter((x) => x.key).map((x) => { const days = Object.keys(x.by).filter((d) => d && x.by[d].n).length; const target = (MRD.targets || {})[x.key] || 0;
      return { key: x.key, name: mrName(x.key), n: x.n, rdf: x.rdf, cdf: x.cdf, by: x.by, days, avg: days ? x.n / days : 0, day: (x.by[latest] || {}).n || 0, target, ach: target ? x.n / target * 100 : null, proj: Math.round(x.n / elapsed * dim), req: target && left ? Math.max(0, Math.ceil((target - x.n) / left)) : null }; });
    list.slice().sort((a, b) => b.avg - a.avg).forEach((x, i) => { x.rank = i + 1; });
    return { list, dates, latest, dim, elapsed, left };
  }
  const numTd = (v, d = 0) => `<td>${v === null || v === undefined ? '—' : N(v, d)}</td>`;
  function mrTargetCards() {
    const st = mrStats(); const L = st.list.slice().sort((a, b) => a.rank - b.rank);
    const row = (x) => `<tr><td>${x.rank}</td><td>${esc(x.key)}</td><td style="text-align:left">${esc(x.name)}</td>${ck(x.n, { st: 'billed', mt: 'Non-Smart', agent: x.key })}<td>${x.days}</td>${numTd(x.avg, 1)}${numTd(x.target || null)}<td class="${x.ach === null ? '' : x.ach >= 100 ? 'good' : x.ach >= 70 ? '' : 'bad'}">${x.ach === null ? '—' : x.ach.toFixed(0) + '%'}</td>${numTd(x.proj)}${numTd(x.req)}</tr>`;
    const head = '<thead><tr><th>Rank</th><th>MR ID</th><th>Name</th><th class="ga">Billed</th><th>Days worked</th><th>Avg / day</th><th class="gn">Monthly target</th><th class="gn">Achieved %</th><th class="gs">Projected month end</th><th class="gs">Required / day</th></tr></thead>';
    const hasT = Object.keys(MRD.targets || {}).length;
    return card('Meter Reader — Target, Projection & Ranking', `<table class="t">${head}<tbody>${L.map(row).join('')}</tbody></table>`, `Rank is by average bills per working day. Projection = bills so far ÷ ${st.elapsed} days × ${st.dim} days. ${hasT ? '' : '<b>No targets entered yet</b> — type each reader\'s monthly target in the MR TARGET sheet of Work Assignment.xlsx on the office PC.'}`)
      + card('Bottom 10 Meter Readers (average bills per working day)', `<table class="t">${head}<tbody>${L.slice(-10).reverse().map(row).join('')}</tbody></table>`);
  }
  function subRequirementCard() {
    if (!can('rep')) return '';
    const st = mrStats(); const known = KNOWN(); const rows = (rep('company/substation-nonsmart') || []).filter((r) => known.has(r.substation));
    const T = { total: 0, billed: 0, unbilled: 0 };
    const line = (r, cls, lab, sp) => { const avg = r.billed / st.elapsed; const proj = r.total ? Math.min(100, (r.billed + avg * st.left) / r.total * 100) : 0;
      return `<tr class="${cls}"><td style="text-align:left">${esc(lab)}</td><td>${N(r.total)}</td>${ck(r.billed, { st: 'billed', mt: 'Non-Smart', ...sp })}${ck(r.unbilled, { st: 'unbilled', mt: 'Non-Smart', ...sp })}${pc(r.total ? r.billed / r.total * 100 : 0)}${numTd(avg, 0)}<td>${st.left}</td>${numTd(st.left ? Math.ceil(r.unbilled / st.left) : r.unbilled)}${pc(proj)}</tr>`; };
    rows.forEach((r) => { T.total += r.total; T.billed += r.billed; T.unbilled += r.unbilled; });
    return card('Substation — Billing Progress & Daily Requirement (Non-Smart)', `<table class="t"><thead><tr><th>Substation</th><th>Total</th><th>Billed</th><th>Unbilled</th><th>Billed %</th><th class="gs">Avg billed / day</th><th class="gn">Days left</th><th class="gn">Required / day</th><th class="ga">Projected % at month end</th></tr></thead><tbody>
      ${rows.map((r) => line(r, '', r.substation, { dim: 'substation', val: r.substation })).join('')}${line(T, 'tot', 'Grand Total', { ks: 1 })}</tbody></table>`, `Required / day = unbilled ÷ days left in the month. Projection assumes billing continues at the average of the first ${st.elapsed} days.`);
  }
  function movementCard(extra = {}, title = '') {
    const mv = rep('x/movement'); if (!mv || !can('rep')) return '';
    const J = MRD.je || {}; let rows = mv.rows; if (extra.je) rows = rows.filter((r) => (J[r.substation] || 'No JE') === extra.je);
    const T = { prevUnb: 0, cleared: 0, added: 0, nowUnb: 0, newDef: 0 }; rows.forEach((r) => { for (const k in T) T[k] += r[k]; });
    const line = (r, cls, lab, sp) => `<tr class="${cls}"><td style="text-align:left">${esc(lab)}</td><td>${N(r.prevUnb)}</td>${ck(r.cleared, { st: 'cleared', ...sp })}${ck(r.added, { st: 'unbilled', nw: 1, ...sp })}${ck(r.nowUnb, { st: 'unbilled', ...sp })}${ck(r.newDef, { st: 'defective', nw: 1, ...sp })}</tr>`;
    return card(title || `What Changed Since ${ddmmyyyy(mv.prev)}`, `<table class="t"><thead><tr><th>Substation</th><th>Unbilled on ${dm(mv.prev)}</th><th class="ga">Cleared</th><th class="gn">Newly unbilled</th><th>Unbilled now</th><th class="gn">New defective bills</th></tr></thead><tbody>
      ${rows.map((r) => line(r, '', r.substation, { dim: 'substation', val: r.substation })).join('')}${line(T, 'tot', 'Grand Total', extra.je ? { je: extra.je } : {})}</tbody></table>`, 'Cleared = was unbilled in the earlier report and is not in today\'s unbilled list.');
  }

  async function viewMy() {
    const types = ROLE === 'admin' ? [['je', 'JE'], ['clerk', 'Billing clerk'], ['mr', 'Meter reader']] : ROLE === 'je' ? [['je', 'JE']] : ROLE === 'clerk' ? [['clerk', 'Billing clerk']] : [['mr', 'Meter reader']];
    if (!types.some((t) => t[0] === ME.type)) { ME = { type: types[0][0], name: '' }; }
    const unb = (await getRows('unbilled')).filter((r) => !S.div || r.d === S.div); const iss = (await getRows('issues')).filter((r) => +r.isd && (!S.div || r.d === S.div));
    await atrRefresh();
    const names = ME.type === 'je' ? [...new Set(Object.values(MRD.je || {}))].sort() : ME.type === 'clerk' ? [...new Set(unb.map((r) => r.cl).concat(iss.map((r) => r.cl)))].filter(Boolean).sort() : Object.keys(MRD.mrs).concat(cube().map((r) => r.ag)).filter((v, i, a) => v && a.indexOf(v) === i).sort();
    if (ME.name && !names.includes(ME.name)) ME.name = '';
    const pick = `<div class="card dl"><label style="font-weight:600">${ROLE === 'admin' ? 'See the work of' : 'Who are you?'}</label><div class="row" style="margin-top:6px">${types.length > 1 ? `<select id="metype">${types.map(([k, l]) => `<option value="${k}" ${ME.type === k ? 'selected' : ''}>${l}</option>`).join('')}</select>` : ''}
      <select id="mename" class="grow"><option value="">Choose ${types.find((t) => t[0] === ME.type)[1]}…</option>${names.map((n) => `<option value="${esc(n)}" ${ME.name === n ? 'selected' : ''}>${esc(n)}${ME.type === 'mr' && mrName(n) ? ' — ' + esc(mrName(n)) : ''}</option>`).join('')}</select></div><p class="muted" style="margin:6px 0 0">This phone remembers the choice. Lists and ATR entries will carry this name.</p></div>`;
    if (!ME.name) { $('view').innerHTML = pick + '<div class="empty">Choose a name to see the work.</div>'; return; }
    if (ME.type === 'mr') {
      const st = mrStats(); const x = st.list.find((m) => m.key === ME.name);
      if (!x) { $('view').innerHTML = pick + '<div class="empty">No non-smart bills by this meter reader in this month\'s report.</div>'; return; }
      let run = 0; const days = st.dates.slice().reverse().map((d) => { const b = x.by[d] || { n: 0, rdf: 0, cdf: 0 }; run += b.n; return { d, ...b, run }; }).reverse();
      const kv = (k, v) => `<tr><td style="text-align:left">${k}</td>${v}</tr>`;
      $('view').innerHTML = pick + tabTools('My Work')
        + card(`My Billing — ${x.key} ${x.name}`, `<table class="t"><thead><tr><th>Item</th><th>Value</th></tr></thead><tbody>
          ${kv('Billed on ' + dm(st.latest), ck(x.day, { st: 'billed', mt: 'Non-Smart', agent: x.key, bd: st.latest }))}${kv('Progressive total', ck(x.n, { st: 'billed', mt: 'Non-Smart', agent: x.key }))}${kv('Days worked', `<td>${x.days}</td>`)}${kv('Average per working day', numTd(x.avg, 1))}
          ${kv('Monthly target', numTd(x.target || null))}${kv('Achieved', `<td>${x.ach === null ? '—' : x.ach.toFixed(0) + '%'}</td>`)}${kv('Projected month end', numTd(x.proj))}${kv('Required per day to meet target', numTd(x.req))}${kv('Rank (of ' + st.list.length + ')', `<td>${x.rank}</td>`)}
          ${kv('RDF bills', ck(x.rdf, { st: 'defective', mt: 'Non-Smart', agent: x.key, dt: 'RDF' }))}${kv('CDF bills', ck(x.cdf, { st: 'defective', mt: 'Non-Smart', agent: x.key, dt: 'CDF' }))}</tbody></table>`)
        + card(`My Daily Billing — ${x.key}`, `<table class="t"><thead><tr><th>Bill date</th><th>Billed</th><th>Progressive</th><th class="gn">RDF</th><th class="gn">CDF</th></tr></thead><tbody>${days.map((d) => `<tr><td>${ddmmyyyy(d.d)}</td>${ck(d.n, { st: 'billed', mt: 'Non-Smart', agent: x.key, bd: d.d })}<td>${N(d.run)}</td>${ck(d.rdf, { st: 'defective', mt: 'Non-Smart', agent: x.key, dt: 'RDF', bd: d.d })}${ck(d.cdf, { st: 'defective', mt: 'Non-Smart', agent: x.key, dt: 'CDF', bd: d.d })}</tr>`).join('')}</tbody></table>`);
      return;
    }
    const sp = meSpec(); const mine = (r) => (ME.type === 'je' ? (r.je || 'No JE') === ME.name : r.cl === ME.name);
    const u = unb.filter(mine), d = iss.filter(mine); const uA = u.filter((r) => atrOf(r)).length; const dPend = d.filter((r) => r.rv !== 'Resolved');
    const done = (await getRows('atrdone')).filter((r) => (!S.div || r.d === S.div) && mine(r));
    const clr = can('rep') && rep('x/movement') ? (await getRows('cleared')).filter((r) => (!S.div || r.d === S.div) && mine(r)).length : null;
    const kv = (k, v) => `<tr><td style="text-align:left">${k}</td>${v}</tr>`;
    const top = u.filter((r) => !atrOf(r)).map((r) => ({ r, p: prio(r) })).sort((a, b) => b.p - a.p).slice(0, 10);
    $('view').innerHTML = pick + tabTools('My Work')
      + card(`My Work — ${ME.name}`, `<table class="t"><thead><tr><th>Item</th><th>Consumers</th></tr></thead><tbody>
        ${kv('Unbilled — non-smart', ck(u.filter((r) => r.ty !== 'Smart').length, { st: 'unbilled', mt: 'Non-Smart', ...sp }))}${kv('Unbilled — smart', ck(u.filter((r) => r.ty === 'Smart').length, { st: 'unbilled', mt: 'Smart', ...sp }))}
        ${kv('Unbilled — ATR not given yet', ck(u.length - uA, { st: 'unbilled', atr: 'none', ...sp }))}${kv('Unbilled — ATR given, still unbilled', ck(uA, { st: 'unbilled', atr: 'given', ...sp }))}
        ${kv('Billed / corrected after my ATR', ck(done.length, { st: 'atrdone', ...sp }))}${kv('Defective bills pending', ck(dPend.length, { st: 'defective', pend: 1, ...sp }))}
        ${kv('Defective bills pending — ATR not given', ck(dPend.filter((r) => !atrOf(r)).length, { st: 'defective', pend: 1, atr: 'none', ...sp }))}
        ${clr === null ? '' : kv('Cleared since ' + dm(rep('x/movement').prev), ck(clr, { st: 'cleared', ...sp })) + kv('Newly unbilled since ' + dm(rep('x/movement').prev), ck(u.filter((r) => +r.nw).length, { st: 'unbilled', nw: 1, ...sp }))}</tbody></table>`, MRD.atr ? '' : 'ATR entry from the phone is not switched on yet (office PC: Set ATR Link.bat).')
      + card(`Top Priority Unbilled Cases — ${ME.name}`, `<div class="row" style="margin-bottom:8px">${[25, 50, 100].map((n) => `<button class="btn sm primary" data-top="${n}">Open top ${n} list</button>`).join('')}</div><table class="t"><thead><tr><th>Priority</th><th>Acct ID</th><th>Name</th><th>Substation</th><th>Category</th><th>Load (KW)</th><th>Months unbilled</th><th>Outstanding</th></tr></thead><tbody>
        ${top.map(({ r, p }) => `<tr><td>${p}</td><td>${esc(r.a)}</td><td style="text-align:left">${esc(r.n)}</td><td style="text-align:left">${esc(shortSub(r.s))}</td><td>${esc(r.t)}</td><td>${esc(r.l)}</td><td>${esc(r.mo)}</td><td>${r.o === '' || r.o === undefined ? '—' : N(r.o)}</td></tr>`).join('')}</tbody></table>`, 'Priority (out of 100) = load + months unbilled + outstanding dues. Cases that already have an ATR this month are left out.')
      + (ME.type === 'je' ? movementCard({ je: ME.name }, `What Changed Since ${rep('x/movement') ? ddmmyyyy(rep('x/movement').prev) : ''} — ${ME.name}`) : '');
  }

  async function viewATR() {
    const unb = (await getRows('unbilled')).filter((r) => !S.div || r.d === S.div); const iss = (await getRows('issues')).filter((r) => +r.isd && r.rv !== 'Resolved' && (!S.div || r.d === S.div));
    const done = (await getRows('atrdone')).filter((r) => !S.div || r.d === S.div);
    await atrRefresh(true);
    const old = (r) => { const x = atrOf(r); return x && (Date.now() - new Date(x.ts).getTime()) > 3 * 86400000; };
    const grp = (rows, keyOf) => { const g = {}; for (const r of rows) { const k = keyOf(r); const o = (g[k] = g[k] || { key: k, n: 0, a: 0, old: 0 }); o.n++; if (atrOf(r)) o.a++; if (old(r)) o.old++; } return g; };
    const J = grp(unb, (r) => r.je || 'No JE'), C = grp(iss, (r) => r.cl || 'Unassigned'); const dj = {}, dc = {};
    for (const r of done) { if (r.k === 'unbilled') dj[r.je || 'No JE'] = (dj[r.je || 'No JE'] || 0) + 1; else dc[r.cl || 'Unassigned'] = (dc[r.cl || 'Unassigned'] || 0) + 1; }
    const tot = (G, dn) => Object.values(G).reduce((t, o) => ({ n: t.n + o.n, a: t.a + o.a, old: t.old + o.old, dn: t.dn + (dn[o.key] || 0) }), { n: 0, a: 0, old: 0, dn: 0 });
    const tj = tot(J, dj), tc = tot(C, dc);
    const reasons = {}; for (const r of unb) { const x = atrOf(r); if (x) (reasons[x.atr] = reasons[x.atr] || { u: 0, d: 0 }).u++; } for (const r of iss) { const x = atrOf(r); if (x) (reasons[x.atr] = reasons[x.atr] || { u: 0, d: 0 }).d++; }
    $('view').innerHTML = tabTools('ATR Progress')
      + (MRD.atr ? '' : '<div class="card dl"><b>ATR entry from the phone is not switched on yet.</b><p class="muted" style="margin:6px 0 0">On the office PC run <b>Set ATR Link.bat</b> once and follow its steps. Until then all cases show as "ATR not given".</p></div>')
      + card('Unbilled Cases — ATR Progress (JE-Wise)', `<table class="t"><thead><tr><th>JE</th><th>Unbilled</th><th class="ga">ATR given</th><th class="gn">ATR not given</th><th class="gn">ATR 3+ days old, still unbilled</th><th class="gs">Billed after ATR</th></tr></thead><tbody>
        ${Object.values(J).sort((a, b) => a.key.localeCompare(b.key)).map((o) => `<tr><td style="text-align:left">${esc(o.key)}</td>${ck(o.n, { st: 'unbilled', je: o.key })}${ck(o.a, { st: 'unbilled', je: o.key, atr: 'given' })}${ck(o.n - o.a, { st: 'unbilled', je: o.key, atr: 'none' })}${ck(o.old, { st: 'unbilled', je: o.key, atr: 'given', old: 3 })}${ck(dj[o.key] || 0, { st: 'atrdone', k: 'unbilled', je: o.key })}</tr>`).join('')}
        <tr class="tot"><td>Grand Total</td>${ck(tj.n, { st: 'unbilled' })}${ck(tj.a, { st: 'unbilled', atr: 'given' })}${ck(tj.n - tj.a, { st: 'unbilled', atr: 'none' })}${ck(tj.old, { st: 'unbilled', atr: 'given', old: 3 })}${ck(done.filter((r) => r.k === 'unbilled').length, { st: 'atrdone', k: 'unbilled' })}</tr></tbody></table>`, 'ATR counts are of this bill month. "Billed after ATR" is checked against the billed report — an ATR alone does not count as done.')
      + card('Defective Bills Pending — ATR Progress (Clerk-Wise)', `<table class="t"><thead><tr><th>Billing Clerk</th><th>Pending</th><th class="ga">ATR given</th><th class="gn">ATR not given</th><th class="gs">Corrected after ATR</th></tr></thead><tbody>
        ${Object.values(C).sort((a, b) => b.n - a.n).map((o) => `<tr><td style="text-align:left">${esc(o.key)}</td>${ck(o.n, { st: 'defective', pend: 1, clerk: o.key })}${ck(o.a, { st: 'defective', pend: 1, clerk: o.key, atr: 'given' })}${ck(o.n - o.a, { st: 'defective', pend: 1, clerk: o.key, atr: 'none' })}${ck(dc[o.key] || 0, { st: 'atrdone', k: 'defective', clerk: o.key })}</tr>`).join('')}
        <tr class="tot"><td>Grand Total</td>${ck(tc.n, { st: 'defective', pend: 1 })}${ck(tc.a, { st: 'defective', pend: 1, atr: 'given' })}${ck(tc.n - tc.a, { st: 'defective', pend: 1, atr: 'none' })}${ck(done.filter((r) => r.k === 'defective').length, { st: 'atrdone', k: 'defective' })}</tr></tbody></table>`)
      + card('ATR Reason-Wise (cases still pending)', Object.keys(reasons).length ? `<table class="t"><thead><tr><th>ATR</th><th>Unbilled cases</th><th>Defective bills</th></tr></thead><tbody>${Object.entries(reasons).sort((a, b) => b[1].u + b[1].d - a[1].u - a[1].d).map(([k, v]) => `<tr><td style="text-align:left">${esc(k)}</td>${ck(v.u, { st: 'unbilled', atrv: k })}${ck(v.d, { st: 'defective', pend: 1, atrv: k })}</tr>`).join('')}</tbody></table>` : '<div class="empty">No ATR entered this month yet</div>');
  }

  async function viewRepeat() {
    const R2 = rep('x/repeat') || { months: [], byRun: [], bySub: [], byMR: [] }; const J = MRD.je || {};
    const NOW = ['UNBILLED', 'PROV', 'IDF', 'RDF', 'CDF']; const sum = (o) => NOW.reduce((t, k) => t + (o[k] || 0), 0);
    const T = {}; NOW.forEach((k) => { T[k] = R2.byRun.reduce((t, o) => t + o[k], 0); });
    const mn = (ym) => new Date(ym + '-01').toLocaleDateString('en-IN', { month: 'short', year: '2-digit' });
    $('view').innerHTML = tabTools('Repeat Cases')
      + card('Repeat Cases — Months Running', `<table class="t"><thead><tr><th>Months running (incl. this month)</th><th class="gn">Unbilled now</th><th>PROV billed</th><th>IDF</th><th>RDF</th><th>CDF</th><th class="ga">Total</th></tr></thead><tbody>
        ${R2.byRun.map((o) => `<tr><td>${o.run}</td>${NOW.map((k) => ck(o[k], { st: 'repeat', run: o.run, now: k })).join('')}${ck(sum(o), { st: 'repeat', run: o.run })}</tr>`).join('')}
        <tr class="tot"><td>Grand Total</td>${NOW.map((k) => ck(T[k], { st: 'repeat', now: k })).join('')}${ck(sum(T), { st: 'repeat' })}</tr></tbody></table>`,
        `Consumers not billed properly this month AND in the month(s) just before, without a break. History used: ${R2.months.map(mn).join(', ') || 'none loaded'}. In the list, U = unbilled, P = provisional, D = defective (IDF / RDF / ASS / CEIL). LMV-5 is left out (quarterly billing). These need a meter change or other permanent action, not one more visit.`)
      + card('Repeat Cases — Substation-Wise', `<table class="t"><thead><tr><th>Substation</th><th>JE</th><th>2 months</th><th>3 months</th><th class="gn">4+ months</th><th class="ga">Total</th></tr></thead><tbody>
        ${R2.bySub.map((o) => `<tr><td style="text-align:left">${esc(o.substation)}</td><td style="text-align:left">${esc(J[o.substation] || '')}</td>${ck(o.m2, { st: 'repeat', run: '2', dim: 'substation', val: o.substation })}${ck(o.m3, { st: 'repeat', run: '3', dim: 'substation', val: o.substation })}${ck(o.m4, { st: 'repeat', run: '4+', dim: 'substation', val: o.substation })}${ck(o.m2 + o.m3 + o.m4, { st: 'repeat', dim: 'substation', val: o.substation })}</tr>`).join('')}
        <tr class="tot"><td colspan="2">Grand Total</td>${ck(R2.bySub.reduce((t, o) => t + o.m2, 0), { st: 'repeat', run: '2' })}${ck(R2.bySub.reduce((t, o) => t + o.m3, 0), { st: 'repeat', run: '3' })}${ck(R2.bySub.reduce((t, o) => t + o.m4, 0), { st: 'repeat', run: '4+' })}${ck(R2.bySub.reduce((t, o) => t + o.m2 + o.m3 + o.m4, 0), { st: 'repeat' })}</tr></tbody></table>`)
      + card('Meter Readers — Repeat Defective Bills', R2.byMR.length ? `<table class="t"><thead><tr><th>MR ID</th><th>Name</th><th>PROV</th><th>IDF</th><th>RDF</th><th>CDF</th><th class="ga">Total</th></tr></thead><tbody>
        ${R2.byMR.map((o) => `<tr><td>${esc(o.agent)}</td><td style="text-align:left">${esc(o.name || mrName(o.agent))}</td>${['PROV', 'IDF', 'RDF', 'CDF'].map((k) => ck(o[k], { st: 'repeat', agent: o.agent, now: k })).join('')}${ck(o.PROV + o.IDF + o.RDF + o.CDF, { st: 'repeat', agent: o.agent, notu: 1 })}</tr>`).join('')}</tbody></table>` : '<div class="empty">None</div>', 'Bills made this month as PROV / IDF / RDF / CDF on consumers who were also not billed properly last month.');
  }

  // ------------------------------------------------------------ BILLING QUALITY
  const BB = [['idf', 'IDF'], ['rdf', 'RDF'], ['cdf', 'CDF'], ['mu', 'MU'], ['prov', 'PROV'], ['um', 'UM']];
  function billBasisTable(rows, dim, head) {
    const blk = (b, val, mt) => BB.map(([k, L]) => ck(b[k], { st: 'billed', ...(val !== undefined ? { dim, val } : {}), ...(mt ? { mt } : {}), base: L })).join('') + ck(b.total, { st: 'billed', ...(val !== undefined ? { dim, val } : {}), ...(mt ? { mt } : {}) });
    const z = () => ({ idf: 0, rdf: 0, cdf: 0, mu: 0, prov: 0, um: 0, total: 0 });
    const g = { smart: z(), nonSmart: z(), all: z() };
    rows.forEach((r) => ['smart', 'nonSmart', 'all'].forEach((m) => Object.keys(g[m]).forEach((k) => { g[m][k] += (r[m] || {})[k] || 0; })));
    const sub = ['gs', 'gn', 'ga'].map((c) => BB.map(([, L]) => `<th class="${c}">${L}</th>`).join('') + `<th class="${c}">Total</th>`).join('');
    return `<table class="t"><thead><tr><th rowspan="2">${head}</th><th colspan="7" class="gs">Smart Meter</th><th colspan="7" class="gn">Non-Smart Meter</th><th colspan="7" class="ga">All Meter</th></tr><tr>${sub}</tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${esc(r.key)}</td>${blk(r.smart, r.key, 'Smart')}${blk(r.nonSmart, r.key, 'Non-Smart')}${blk(r.all, r.key, '')}</tr>`).join('')}
      <tr class="tot"><td>Grand Total</td>${blk(g.smart, undefined, 'Smart')}${blk(g.nonSmart, undefined, 'Non-Smart')}${blk(g.all, undefined, '')}</tr></tbody></table>`;
  }
  function ageingTable(data, dim, head, st) {
    const B = data.bucketLabels || [];
    const g = Object.fromEntries(B.map((b) => [b, 0])); let gt = 0;
    data.rows.forEach((r) => { B.forEach((b) => { g[b] += r[b] || 0; }); gt += r.total; });
    const sp = (extra) => ({ st, ...extra });
    return `<table class="t"><thead><tr><th>${head}</th>${B.map((b) => `<th>${b}</th>`).join('')}<th>Total</th></tr></thead><tbody>
      ${data.rows.map((r) => `<tr><td>${esc(r.key)}</td>${B.map((b) => ck(r[b] || 0, sp({ dim, val: r.key, age: b }))).join('')}${ck(r.total, sp({ dim, val: r.key }))}</tr>`).join('')}
      <tr class="tot"><td>Grand Total</td>${B.map((b) => ck(g[b], sp({ age: b }))).join('')}${ck(gt, sp({}))}</tr></tbody></table>`;
  }
  async function viewQuality() {
    const inf = rep('billing-quality/load-wise-inflated') || { rows: [], categoryList: [] };
    const cats = inf.categoryList.filter((c) => inf.rows.some((r) => r.categories[c]));
    const gc = cats.map((c) => inf.rows.reduce((x, r) => x + (r.categories[c] || 0), 0));
    const infT = `<table class="t"><thead><tr><th>Load Range</th>${cats.map((c) => `<th>${c}</th>`).join('')}<th>Total</th></tr></thead><tbody>
      ${inf.rows.map((r) => `<tr><td>${esc(r.key)}</td>${cats.map((c) => ck(r.categories[c] || 0, { st: 'billed', inf: 1, dim: 'load', val: r.key, cat: c })).join('')}${ck(r.total, { st: 'billed', inf: 1, dim: 'load', val: r.key })}</tr>`).join('')}
      <tr class="tot"><td>Grand Total</td>${gc.map((v, i) => ck(v, { st: 'billed', inf: 1, cat: cats[i] })).join('')}${ck(gc.reduce((x, y) => x + y, 0), { st: 'billed', inf: 1 })}</tr></tbody></table>`;
    const e = { rows: [], bucketLabels: [] };
    $('view').innerHTML = tabTools('Billing Quality')
      + card('Load-Wise Bill Basis Report', billBasisTable(rep('billing-quality/load-wise-bill-basis') || [], 'load', 'Load Range'))
      + card('Category-Wise Bill Basis Report', billBasisTable(rep('billing-quality/category-wise-bill-basis') || [], 'category', 'Category'))
      + card('Load-Wise Inflated Bill Report', infT)
      + card('PROV Billed + Unbilled — Ageing, Load-Wise', ageingTable(rep('billing-quality/prov-unbilled-ageing/load') || e, 'load', 'Load Range', 'provunb'), 'Months since last proper (MU) bill.')
      + card('PROV Billed + Unbilled — Ageing, Category-Wise', ageingTable(rep('billing-quality/prov-unbilled-ageing/category') || e, 'category', 'Category', 'provunb'))
      + card('PROV Billed + Unbilled — Ageing, Substation-Wise', ageingTable(rep('billing-quality/prov-unbilled-ageing/substation') || e, 'substation', 'Substation', 'provunb'));
  }

  // ------------------------------------------------------------ SMART METER
  async function viewSmart() {
    const ag = rep('smart-meter/not-fed-ageing') || { rows: [], totalNotFed: 0 };
    const sa = rep('smart-meter/not-fed-substation-ageing') || { rows: [], bucketLabels: [] };
    const er = rep('smart-meter/unbilled-error-breakdown') || { rows: [], totalUnbilledSmart: 0 };
    $('view').innerHTML = tabTools('Smart Meter')
      + card('Smart Meter Not Fed — Month-Wise (Ageing)', `<table class="t"><thead><tr><th>Ageing</th><th>Count</th></tr></thead><tbody>${ag.rows.map((r) => `<tr><td>${esc(r.key)}</td>${ck(r.count, { st: 'notfed', age: r.key })}</tr>`).join('')}<tr class="tot"><td>Grand Total</td>${ck(ag.totalNotFed, { st: 'notfed' })}</tr></tbody></table>`, 'Months from installation date to today, for meters installed but not in the billed or unbilled reports.')
      + card('Smart Meter Not Fed — Substation-Wise (with Ageing)', ageingTable(sa, 'substation', 'Substation', 'notfed'))
      + card('Smart Meter Not Billed — Error Breakdown', `<table class="t"><thead><tr><th>Error / Reason</th><th>Count</th></tr></thead><tbody>${er.rows.map((r) => `<tr><td>${esc(r.key)}</td>${ck(r.count, { st: 'smarterr', err: r.key })}</tr>`).join('')}<tr class="tot"><td>Grand Total</td>${ck(er.totalUnbilledSmart || er.rows.reduce((x, r) => x + r.count, 0), { st: 'smarterr' })}</tr></tbody></table>`, 'Unbilled smart-meter consumers by CM 225 reason. "READ NOT SHARED" = no exception logged.');
  }

  // ------------------------------------------------------------ consumer data
  const DATA = {};
  async function getRows(kind) {
    if (DATA[kind]) return DATA[kind];
    const file = { unbilled: 'list-unbilled', issues: 'list-issues', notfed: 'list-notfed', mastererr: 'list-mastererr', cleared: 'list-cleared', atrdone: 'list-atrdone', repeat: 'list-repeat' }[kind];
    const J = MRD.je || {}; return (DATA[kind] = rowsOf(await load(file)).map((r) => { r.je = J[r.s] || ''; return r; }));
  }
  async function getBilled(sub) {
    const shards = (REP.reports.billedShards || []).filter((x) => !sub || sub.includes(x.s));
    let out = [], i = 0;
    for (const sh of shards) {
      if (!DATA['b:' + sh.f]) { if (shards.length > 1) toast(`Loading billed consumers… ${++i}/${shards.length}`, 20000); DATA['b:' + sh.f] = rowsOf(await load(sh.f)).map((r) => { const m = MRD.mrs[r.ag]; if (m) { r.mrn = m[0]; r.mrm = m[1]; } r.je = (MRD.je || {})[r.s] || ''; return r; }); }
      out = out.concat(DATA['b:' + sh.f]);
    }
    if (shards.length > 1) toast('Loaded', 600);
    return out;
  }
  const KNOWN = () => new Set(REP.reports.knownSubs || []);
  function matcher(sp) {
    const known = KNOWN(); const dts = sp.dt ? sp.dt.split(',') : null;
    return (r) => {
      if (S.div && r.d !== S.div) return false;
      if (sp.dim === 'load' && lrOf(r.l) !== sp.val) return false;
      if (sp.dim === 'category' && U(r.t) !== U(sp.val)) return false;
      if (sp.dim === 'substation') { if (sp.val === 'OTHERS/BLANK' || sp.val === 'Unknown Substation') { if (known.has(r.s)) return false; } else if (sp.val === 'Unknown') { if (r.s) return false; } else if (r.s !== sp.val) return false; }
      if (sp.ks && !known.has(r.s)) return false;
      if (sp.xcat && U(r.t).replace(/[^A-Z0-9]/g, '') === sp.xcat) return false;
      if (sp.mt && r.ty !== sp.mt) return false;
      if (sp.base && baseOf(r) !== sp.base) return false;
      if (sp.inf && !+r.inf) return false;
      if (sp.cat && U(r.t) !== U(sp.cat)) return false;
      if (sp.firm && r.fm !== sp.firm) return false;
      if (sp.lb && lrOf(r.l) !== sp.lb) return false;
      if (sp.seg && (r.ty === 'Smart' ? 'OTH' : r.fm === 'MRI' ? 'MRI' : 'SBM') !== sp.seg) return false;
      if (sp.dto && String(r.df || '').toUpperCase().split(',').some((x) => ['RDF', 'CDF', 'IDF'].includes(x.trim()))) return false;
      if (sp.agent && (r.ag || '(blank)') !== sp.agent) return false;
      if (dts && !String(r.df || '').split(',').some((x) => dts.includes(x.trim().toUpperCase()))) return false;
      if (sp.clerk && r.cl !== sp.clerk) return false;
      if (sp.je && (r.je || 'No JE') !== sp.je) return false;
      if (sp.pend && r.rv === 'Resolved') return false;
      if (sp.bd && (r.bd || '-') !== sp.bd) return false;
      if (sp.err && r.rs !== sp.err) return false;
      if (sp.age && ageOf(r._age) !== sp.age) return false;
      if (sp.mob && mobOf(r) !== sp.mob) return false;
      if (sp.nw && !+r.nw) return false;
      if (sp.atr === 'none' && atrOf(r)) return false;
      if (sp.atr === 'given' && !atrOf(r)) return false;
      if (sp.atrv && (atrOf(r) || {}).atr !== sp.atrv) return false;
      if (sp.old && !(atrOf(r) && Date.now() - new Date(atrOf(r).ts).getTime() > sp.old * 86400000)) return false;
      if (sp.k && r.k !== sp.k) return false;
      if (sp.now && r.now !== sp.now) return false;
      if (sp.notu && r.now === 'UNBILLED') return false;
      if (sp.run && !(sp.run === '4+' ? r.run >= 4 : sp.run === '5+' ? r.run >= 5 : r.run === +sp.run)) return false;
      return true;
    };
  }
  async function drillRows(sp) {
    let rows;
    if (sp.st === 'billed') {
      let subs = null;
      if (sp.dim === 'substation') subs = [KNOWN().has(sp.val) ? sp.val : 'OTHERS/BLANK'];
      else if (sp.agent) subs = [...new Set(MRD.rows.filter((r) => (r[2] || '(blank)') === sp.agent).map((r) => (KNOWN().has(r[1]) ? r[1] : 'OTHERS/BLANK')))];
      rows = await getBilled(subs);
    }
    else if (sp.st === 'unbilled') rows = (await getRows('unbilled')).map((r) => ({ ...r, _age: r.mo }));
    else if (sp.st === 'smarterr') rows = (await getRows('unbilled')).filter((r) => r.ty === 'Smart');
    else if (sp.st === 'defective') rows = (await getRows('issues')).filter((r) => +r.isd);
    else if (sp.st === 'provbilled') rows = (await getRows('issues')).filter((r) => U(r.bb) === 'PROV').map((r) => ({ ...r, _age: r.lmo }));
    else if (sp.st === 'provunb') rows = (await getRows('issues')).filter((r) => U(r.bb) === 'PROV').map((r) => ({ ...r, _age: r.lmo, _kind: 'PROV BILLED', mo: r.lmo })).concat((await getRows('unbilled')).map((r) => ({ ...r, _age: r.mo, _kind: 'UNBILLED' })));
    else if (sp.st === 'notfed') rows = (await getRows('notfed')).map((r) => ({ ...r, _age: r.mo }));
    else if (['cleared', 'atrdone', 'repeat'].includes(sp.st)) rows = await getRows(sp.st);
    else rows = [];
    rows = rows.filter(matcher(sp));
    if (sp.top) rows = rows.filter((r) => !atrOf(r)).map((r) => ({ ...r, _p: prio(r) })).sort((a, b) => b._p - a._p).slice(0, sp.top);
    return rows;
  }

  // ------------------------------------------------------------ list formats (same columns as the Billing Operations App)
  const C = {
    a: ['Acct ID', (r) => r.a, 16], sc: ['Consumer No', (r) => r.sc, 14], n: ['Name', (r) => r.n, 24, 1], ad: ['Address', (r) => r.ad, 30, 1], m: ['Mobile No', (r) => r.m, 14], d: ['Division', (r) => r.d, 12],
    t: ['Category', (r) => r.t, 10], l: ['Load (KW)', (r) => r.l, 10], s: ['Substation', (r) => r.s, 20], ty: ['Meter Type', (r) => r.ty, 10], sn: ['Meter Serial No', (r) => r.sn, 16], mno: ['Meter No', (r) => r.sn, 16],
    mo: ['Months Unbilled', (r) => r.mo, 14], cs: ['Case Status', (r) => r.cs || 'PENDING', 14], bb: ['Bill Basis', (r) => r.bb, 10], u: ['Billed Units', (r) => r.u, 12], ap: ['Amount Payable', (r) => r.ap, 14],
    je: ['JE Name', (r) => r.je, 16], cl: ['Clerk', (r) => r.cl, 14], ag: ['MR ID', (r) => r.ag, 12], rr: ['Read Remark', (r) => r.rr, 10], mrn: ['MR Name', (r) => r.mrn, 18, 1], mrm: ['MR Mobile No', (r) => r.mrm, 14], atr: ['ATR', (r) => atrText(r), 30, 1], rem: ['ATR / Remarks', (r) => atrText(r), 30, 1], rem2: ['REMARKS / ATR', (r) => atrText(r), 30, 1],
    o: ['Outstanding', (r) => r.o, 12], pr: ['Priority', (r) => r._p, 9], now: ['This Month', (r) => r.now, 12], run: ['Months Running', (r) => r.run, 10], hist: ['History', (r) => r.hist, 30, 1], res: ['Result', (r) => r.res, 14], atrv: ['ATR Given', (r) => `${r.atr || ''}${r.rem ? ' - ' + r.rem : ''}`, 26, 1], by: ['ATR By', (r) => r.by, 16], ats: ['ATR Date', (r) => (r.ats ? ddmmyyyy(r.ats) : ''), 12],
    lmo: ['Last MU Billed Months', (r) => r.lmo, 16], kind: ['Type', (r) => r._kind, 12], mon: ['Months', (r) => r.mo, 10], rs: ['Reason', (r) => r.rs, 26], df: ['Defect', (r) => r.df, 14], bd: ['Bill Date', (r) => (r.bd ? ddmmyyyy(r.bd) : ''), 12],
    idt: ['Installation Date', (r) => r.idt, 14], old: ['Meter in CC&B', (r) => r.old, 16], er: ['Error', (r) => r.er, 26], cy: ['Current Cycle', (r) => r.cy, 12], ex: ['Correct Cycle', (r) => r.ex, 12], bk: ['Book No', (r) => r.bk, 14], ph: ['Phase', (r) => r.ph, 8],
  };
  const cols = (keys) => keys.split(' ').map((k) => ({ h: C[k][0], f: C[k][1], w: C[k][2], wrap: !!C[k][3] }));
  const FORMATS = {
    cleared: [{ name: 'List', title: 'Unbilled Cases Cleared', cols: cols('a n ad m s je t l sn res bd bb ag mrn') }],
    atrdone: [{ name: 'List', title: 'Billed / Corrected After ATR', cols: cols('a n ad m s je t l atrv by ats bd bb') }],
    repeat: [{ name: 'List', title: 'Repeat Cases', cols: cols('a n ad m s je t l sn now run hist mrn rem') }],
    billed: [{ name: 'List', title: 'Billed Consumers', cols: cols('a sc n d t l s ty bb u ap') }, { name: 'With meter reader', title: 'Billed Consumers', cols: cols('a n t l s mno bb rr bd u ap ag mrn mrm') }],
    unbilled: [{ name: 'List', title: 'Unbilled Cases', cols: cols('a n ad m t l s ty sn mo cs') }, { name: 'Field work sheet', title: 'Unbilled Cases — Field Work Sheet', cols: cols('a n ad m s t l sn mo rem') }, { name: 'Site work sheet with JE & clerk', title: 'Unbilled Cases — Site Work Sheet', cols: cols('a n ad m s je cl t l sn mo rem') }, { name: 'Priority list', title: 'Unbilled Cases — Priority List', cols: cols('pr a n ad m s je t l sn mo o rem') }],
    defective: [{ name: 'Field work sheet', title: 'Defective Bills — Field Work Sheet', cols: cols('a n ad m t l s mno mrn mrm atr') }, { name: 'List with bill details', title: 'Defective Bills', cols: cols('a n ad m t l s mno bb df u ap bd') }, { name: 'Site work sheet with JE & clerk', title: 'Defective Bills — Site Work Sheet', cols: cols('a n ad m t l s je cl mno mrn mrm atr') }],
    provbilled: [{ name: 'List', title: 'PROV Billed Consumers', cols: cols('a n ad m t l s sn lmo ap rem2') }],
    provunb: [{ name: 'List', title: 'PROV Billed + Unbilled', cols: cols('a n ad m t l s sn kind mon rem2') }],
    notfed: [{ name: 'List', title: 'Smart Meter Installed — Not Fed', cols: cols('a n ad m s t l sn old idt mon') }],
    smarterr: [{ name: 'List', title: 'Smart Meter Not Billed', cols: cols('a n ad m t l s sn mo rs') }],
    mastererr: [{ name: 'List', title: 'Master Data Errors', cols: cols('a n ad m s t l sn ty ph cy ex er bk') }],
  };
  const GROUPS = {
    default: [['Substation', (r) => r.s]],
    unbilled: [['Substation', (r) => r.s], ['JE', (r) => r.je || 'No JE'], ['Clerk', (r) => r.cl || 'Unassigned']],
    repeat: [['Substation', (r) => r.s], ['JE', (r) => r.je || 'No JE'], ['Clerk', (r) => r.cl || 'Unassigned']],
    cleared: [['Substation', (r) => r.s], ['JE', (r) => r.je || 'No JE']],
    defective: [['Substation', (r) => r.s], ['Meter reader', (r) => `${r.ag || 'Unknown'}${r.mrn ? ' - ' + r.mrn : ''}`], ['JE', (r) => r.je || 'No JE'], ['Clerk', (r) => r.cl || 'Unassigned']],
  };
  const fname = (s) => String(s || 'Unknown').replace(/[\\/*?:"<>|[\]]/g, '-').trim().slice(0, 80);
  async function xlsxBlob(fmt, rows) {
    await lib('xlsx');
    const aoa = [['S. No', ...fmt.cols.map((c) => c.h)], ...rows.map((r, i) => [i + 1, ...fmt.cols.map((c) => { const v = c.f(r); return v === null || v === undefined ? '' : v; })])];
    const ws = XLSX.utils.aoa_to_sheet(aoa); ws['!cols'] = [{ wch: 7 }, ...fmt.cols.map((c) => ({ wch: c.w }))];
    const wb = XLSX.utils.book_new(); XLSX.utils.book_append_sheet(wb, ws, 'Report');
    return new Blob([XLSX.write(wb, { type: 'array', bookType: 'xlsx' })], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }
  async function pdfBlob(fmt, rows, title) {
    await lib('jspdf'); await lib('autotable');
    const doc = new jspdf.jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4', compress: true });
    doc.setFont('helvetica', 'bold'); doc.setFontSize(14); doc.text(title, doc.internal.pageSize.getWidth() / 2, 42, { align: 'center' });
    const colStyles = { 0: { cellWidth: 30 } }; fmt.cols.forEach((c, i) => { if (c.wrap) colStyles[i + 1] = { overflow: 'linebreak' }; });
    doc.autoTable({ head: [['S. No', ...fmt.cols.map((c) => c.h)]], body: rows.map((r, i) => [i + 1, ...fmt.cols.map((c) => { const v = c.f(r); return v === null || v === undefined ? '' : String(v); })]),
      startY: 55, margin: { left: 30, right: 30, top: 30, bottom: 30 }, theme: 'grid', rowPageBreak: 'avoid',
      styles: { font: 'helvetica', fontSize: 7, cellPadding: 4, textColor: 0, lineColor: 0, lineWidth: 0.5, overflow: 'ellipsize', minCellHeight: 20 },
      headStyles: { fillColor: [255, 255, 255], textColor: 0, fontStyle: 'bold', fontSize: 8, overflow: 'linebreak' }, columnStyles: colStyles });
    return doc.output('blob');
  }
  async function exportList(kind, fmtIdx, type, rows, label, groupIdx) {
    const fmt = FORMATS[kind][fmtIdx]; if (!rows.length) return toast('Nothing to download');
    const base = fname(`${fmt.title}${label ? ' - ' + label : ''}_${REP.reportDate}`).replace(/\s+/g, '_');
    try {
      if (groupIdx === undefined) {
        if (type === 'pdf' && rows.length > 6000 && !confirm(`${N(rows.length)} rows is a very large PDF and may be slow on a phone. Continue? (Tip: filter first, or use Bulk download.)`)) return;
        toast(`Preparing ${type.toUpperCase()}…`, 30000);
        await new Promise((r) => setTimeout(r, 50));
        saveBlob(type === 'pdf' ? await pdfBlob(fmt, rows, fmt.title + (label ? ' — ' + label : '')) : await xlsxBlob(fmt, rows), `${base}.${type}`);
      } else {
        await lib('jszip');
        const [gname, gfn] = (GROUPS[kind] || GROUPS.default)[groupIdx];
        const map = new Map(); for (const r of rows) { const k = gfn(r) || 'Unknown'; if (!map.has(k)) map.set(k, []); map.get(k).push(r); }
        const zip = new JSZip(); const used = new Set(); let i = 0;
        for (const [g, list] of [...map.entries()].sort((a, b) => b[1].length - a[1].length)) {
          toast(`Preparing ${++i}/${map.size}: ${g}`, 30000); await new Promise((r) => setTimeout(r, 20));
          let nm = fname(g), fin = nm, k = 2; while (used.has(fin)) fin = `${nm}_${k++}`; used.add(fin);
          zip.file(`${fin}.${type}`, type === 'pdf' ? await pdfBlob(fmt, list, `${fmt.title} — ${g}`) : await xlsxBlob(fmt, list));
        }
        saveBlob(await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' }), `${fname(kind)}_bulk_by_${gname.toLowerCase().replace(/\s+/g, '_')}_${type}.zip`);
      }
      toast(`Downloaded (${N(rows.length)} consumers)`);
    } catch (e) { console.error(e); toast('Download failed: ' + e.message, 5000); }
  }

  // ------------------------------------------------------------ list page (used by the Cases tabs and by every tapped number)
  const LV = {};
  const FILTERS = {
    cleared: [['je', 'JE'], ['cl', 'Clerk'], ['s', 'Substation'], ['res', 'Result'], ['ty', 'Meter type']],
    atrdone: [['je', 'JE'], ['cl', 'Clerk'], ['s', 'Substation'], ['k', 'Type'], ['by', 'ATR by']],
    repeat: [['je', 'JE'], ['cl', 'Clerk'], ['s', 'Substation'], ['now', 'This month'], ['run', 'Months running'], ['ty', 'Meter type'], ['t', 'Category'], ['_atr', 'ATR']],
    unbilled: [['je', 'JE'], ['cl', 'Clerk'], ['_atr', 'ATR'], ['t', 'Category'], ['s', 'Substation'], ['ty', 'Meter type'], ['_lr', 'Load range'], ['_mo', 'Months unbilled'], ['fm', 'Firm'], ['rs', 'Smart meter reason']],
    defective: [['je', 'JE'], ['cl', 'Clerk'], ['_atr', 'ATR'], ['t', 'Category'], ['s', 'Substation'], ['ty', 'Meter type'], ['_lr', 'Load range'], ['_df', 'Defect type'], ['_ag', 'Meter reader'], ['fm', 'Firm']],
    billed: [['t', 'Category'], ['s', 'Substation'], ['je', 'JE'], ['ty', 'Meter type'], ['_lr', 'Load range'], ['_base', 'Bill basis'], ['_ag', 'Meter reader']],
    mastererr: [['s', 'Substation'], ['er', 'Error'], ['ex', 'Correct cycle'], ['ty', 'Meter type'], ['ph', 'Phase'], ['t', 'Category']],
    other: [['t', 'Category'], ['s', 'Substation'], ['_lr', 'Load range']],
  };
  const fval = (r, k) => (k === '_atr' ? (atrOf(r) ? atrOf(r).atr : 'ATR not given') : k === '_lr' ? lrOf(r.l) : k === '_mo' ? (r.mo === '' ? 'Unknown' : String(r.mo)) : k === '_base' ? baseOf(r) : k === '_ag' ? `${r.ag || '(blank)'}${r.mrn ? ' - ' + r.mrn : ''}` : k === '_df' ? null : String(r[k] ?? ''));
  function listPage(el, id, kind, title, allRows, opts = {}) {
    const st = LV[id] = LV[id] || { f: {}, q: '', shown: 50, fmt: opts.fmt || 0, min: '', sort: opts.keep ? 'asis' : 'sub' };
    const filters = FILTERS[kind] || FILTERS.other;
    const pass = (r, skip) => filters.every(([k]) => { const v = st.f[k]; if (!v || !v.length || k === skip) return true; if (k === '_df') return String(r.df || '').split(',').some((x) => v.includes(x.trim())); return v.includes(fval(r, k)); }) && (!st.min || +r.mo >= +st.min);
    const q = st.q.trim().toUpperCase();
    const rows0 = allRows.filter((r) => pass(r) && (!q || `${r.a} ${r.n} ${r.m || ''} ${r.sn || ''}`.toUpperCase().includes(q)));
    // default order of every list and download: substation, then load (big first), then months pending (most first)
    const num = (v) => (v === '' || v === undefined || v === null || isNaN(+v) ? -1 : +v); const mth = (r) => num(r.mo !== undefined ? r.mo : r.run !== undefined ? r.run : r.lmo);
    const SORTS = { sub: (a, b) => String(a.s || '~').localeCompare(String(b.s || '~')) || num(b.l) - num(a.l) || mth(b) - mth(a), mo: (a, b) => mth(b) - mth(a) || num(b.l) - num(a.l), load: (a, b) => num(b.l) - num(a.l) || mth(b) - mth(a), out: (a, b) => num(b.o) - num(a.o), name: (a, b) => String(a.n || '').localeCompare(String(b.n || '')) };
    const rows = SORTS[st.sort] ? rows0.slice().sort(SORTS[st.sort]) : rows0;
    const options = (k) => { const cnt = {}; for (const r of allRows) { if (!pass(r, k)) continue; const vs = k === '_df' ? String(r.df || '').split(',').map((x) => x.trim()).filter(Boolean) : [fval(r, k)]; for (const v of vs) cnt[v] = (cnt[v] || 0) + 1; } return Object.entries(cnt).sort((a, b) => (k === '_mo' ? (+a[0] || 999) - (+b[0] || 999) : b[1] - a[1])); };
    const fmts = FORMATS[kind]; const groups = GROUPS[kind] || GROUPS.default;
    const tags = (r) => [r._kind ? `<span class="tag ${r._kind === 'UNBILLED' ? 'red' : 'amber'}">${r._kind}</span>` : '', r.mo !== undefined && r.mo !== '' && kind !== 'billed' ? `<span class="tag red">${esc(r.mo)} m</span>` : '', r.bb && kind !== 'unbilled' ? `<span class="tag ${U(r.bb) === 'MU' ? 'green' : 'red'}">${esc(r.bb)}${r.rr && U(r.rr) !== 'OK' ? ' · ' + esc(r.rr) : ''}</span>` : '', r.df ? `<span class="tag amber">${esc(r.df)}</span>` : '',
      `<span class="tag">${esc(shortSub(r.s))}</span>`, `<span class="tag">${esc(r.t)} · ${esc(r.l)} KW</span>`, r.sn ? `<span class="tag ${r.ty === 'Smart' ? 'blue' : ''}">${esc(r.sn)}</span>` : '', r.rs ? `<span class="tag amber">${esc(r.rs)}</span>` : '', r.er ? `<span class="tag red">${esc(r.er)}</span>` : '', r.mrn ? `<span class="tag">MR ${esc(r.mrn)}</span>` : '', r._p ? `<span class="tag amber">Priority ${r._p}</span>` : '', r.run ? `<span class="tag red">${r.run} months · ${esc(r.hist)}</span>` : '', r.res ? `<span class="tag ${r.res === 'Billed' ? 'green' : 'amber'}">${esc(r.res)}${r.bd ? ' ' + dm(r.bd) : ''}</span>` : '', +r.nw ? '<span class="tag amber">NEW</span>' : '', atrOf(r) ? `<span class="tag green">${atrOf(r).ph ? '📷 ' : ''}ATR: ${esc(atrOf(r).atr)}</span>` : r.atr && r.ats ? `<span class="tag green">ATR: ${esc(r.atr)}</span>` : '', r.je ? `<span class="tag blue">JE ${esc(r.je)}</span>` : '', r.cl && kind !== 'billed' ? `<span class="tag">Clerk ${esc(r.cl)}</span>` : '', r.u !== undefined && kind === 'billed' ? `<span class="tag">${N(r.u, 0)} units · ₹${N(r.ap, 0)}</span>` : ''];
    el.innerHTML = `${opts.back ? `<button class="btn sm" id="lvback" style="margin-bottom:8px">← Back to report</button>` : ''}<h2>${esc(title)}</h2>
      <div class="filters">${filters.map(([k, label]) => { const v = st.f[k] || []; return `<button class="fbtn ${v.length ? 'on' : ''}" data-k="${k}"><span>${label}: ${v.length ? esc(v.map((x) => (x === '' ? '(blank)' : x)).join(', ')) : 'all'}</span><i>▾</i></button>`; }).join('')}
        ${kind === 'unbilled' ? `<select id="lvmin"><option value="">Min months: any</option>${[2, 3, 6, 12].map((m) => `<option value="${m}" ${st.min == m ? 'selected' : ''}>${m}+ months unbilled</option>`).join('')}</select>` : ''}</div>
      <div class="row" style="margin-bottom:8px"><input type="search" id="lvq" class="grow" placeholder="Search account, name, mobile, meter" value="${esc(st.q)}" style="min-width:170px"><button class="btn sm" id="lvclear">Clear</button></div>
      <div class="card dl"><div class="row"><b>${N(rows.length)}</b> consumers${rows.length !== allRows.length ? ` <span class="muted">of ${N(allRows.length)}</span>` : ''}
        <select id="lvsort" style="width:auto">${[['sub', 'Substation › Load › Months'], ['mo', 'Months pending (most first)'], ['load', 'Load (big first)'], ['out', 'Outstanding (big first)'], ['name', 'Name A–Z']].concat(opts.keep ? [['asis', 'Priority order']] : []).map(([k, l]) => `<option value="${k}" ${st.sort === k ? 'selected' : ''}>Sort: ${l}</option>`).join('')}</select>
        ${fmts.length > 1 ? `<select id="lvfmt" style="width:auto">${fmts.map((f, i) => `<option value="${i}" ${st.fmt == i ? 'selected' : ''}>Format: ${f.name}</option>`).join('')}</select>` : ''}</div>
        <div class="row" style="margin-top:8px"><button class="btn sm primary" data-x="xlsx">⬇ Excel</button><button class="btn sm primary" data-x="pdf">⬇ PDF</button>
        ${groups.map((g, i) => `<button class="btn sm" data-x="xlsx" data-g="${i}">⬇ Bulk Excel by ${g[0] === 'JE' ? 'JE' : g[0].toLowerCase()} (ZIP)</button><button class="btn sm" data-x="pdf" data-g="${i}">⬇ Bulk PDF by ${g[0] === 'JE' ? 'JE' : g[0].toLowerCase()} (ZIP)</button>`).join('')}</div></div>
      <div class="list">${rows.slice(0, st.shown).map((r, i) => `<div class="case" data-i="${i}"><div class="row"><span class="a grow">${esc(r.a)}</span>${r.m ? `<a class="tag" href="tel:${esc(r.m)}" onclick="event.stopPropagation()">📞 ${esc(r.m)}</a>` : ''}</div><div class="n">${esc(r.n)}</div>${r.ad ? `<div class="ad">${esc(r.ad)}</div>` : ''}<div class="m">${tags(r).join('')}</div></div>`).join('') || '<div class="empty">No consumers</div>'}</div>
      ${rows.length > st.shown ? `<div style="text-align:center;margin:12px"><button class="btn" id="lvmore">Show more (${N(rows.length - st.shown)} left)</button></div>` : ''}`;
    const again = () => listPage(el, id, kind, title, allRows, opts);
    const label = Object.values(st.f).filter((v) => v && v.length).map((v) => v.join('+')).join(' ') + (st.min ? ` ${st.min}+ months` : '');
    // each filter opens a tick-list, so several values can be chosen together (e.g. RDF and CDF)
    el.querySelectorAll('button.fbtn').forEach((b) => (b.onclick = () => {
      const k = b.dataset.k; const lab = filters.find((f) => f[0] === k)[1]; const cur = new Set(st.f[k] || []); const opt = options(k);
      $('sheetIn').innerHTML = `<div class="row"><h2 class="grow" style="margin:0">${esc(lab)}</h2><button class="btn sm" id="fx">✕</button></div><p class="muted" style="margin:6px 0 10px">Tick one or more, then Apply.</p>
        <div class="flist">${opt.map(([v, c], i) => `<label><input type="checkbox" data-i="${i}" ${cur.has(v) ? 'checked' : ''}><span class="grow">${esc(v === '' ? '(blank)' : v)}</span><span class="muted">${N(c)}</span></label>`).join('') || '<div class="empty">Nothing to choose</div>'}</div>
        <div class="row" style="margin-top:12px;position:sticky;bottom:0;background:#fff;padding-top:8px"><button class="btn" id="fall">Clear (all)</button><button class="btn primary grow" id="fok">Apply</button></div>`;
      DET = null; $('sheet').classList.add('open');
      const close = () => $('sheet').classList.remove('open');
      $('fx').onclick = close;
      $('fall').onclick = () => { delete st.f[k]; st.shown = 50; close(); again(); };
      $('fok').onclick = () => { const v = [...$('sheetIn').querySelectorAll('input:checked')].map((x) => opt[+x.dataset.i][0]); if (v.length) st.f[k] = v; else delete st.f[k]; st.shown = 50; close(); again(); };
    }));
    el.querySelector('#lvsort').onchange = (e) => { st.sort = e.target.value; st.shown = 50; again(); };
    const mn = el.querySelector('#lvmin'); if (mn) mn.onchange = () => { st.min = mn.value; again(); };
    const fs = el.querySelector('#lvfmt'); if (fs) fs.onchange = () => { st.fmt = +fs.value; };
    const lq = el.querySelector('#lvq'); lq.oninput = () => { clearTimeout(lq.t); lq.t = setTimeout(() => { st.q = lq.value; st.shown = 50; again(); const n = el.querySelector('#lvq'); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }, 350); };
    el.querySelector('#lvclear').onclick = () => { st.f = {}; st.q = ''; st.min = ''; again(); };
    el.querySelectorAll('button[data-x]').forEach((b) => (b.onclick = () => exportList(kind, st.fmt, b.dataset.x, rows, [opts.label, label].filter(Boolean).join(' '), b.dataset.g === undefined ? undefined : +b.dataset.g)));
    const more = el.querySelector('#lvmore'); if (more) more.onclick = () => { st.shown += 200; again(); };
    const bk = el.querySelector('#lvback'); if (bk) bk.onclick = () => history.back();
    el.querySelectorAll('.case[data-i]').forEach((c) => (c.onclick = () => detail(rows[+c.dataset.i])));
  }
  async function viewCases(kind) {
    const el = $('view'); await atrRefresh();
    if (kind === 'unbilled') return listPage(el, 'tab-unbilled', 'unbilled', 'Unbilled Cases', (await getRows('unbilled')).filter((r) => !S.div || r.d === S.div));
    if (kind === 'defective') return listPage(el, 'tab-defective', 'defective', 'Defective Bills', (await getRows('issues')).filter((r) => +r.isd && (!S.div || r.d === S.div)));
    return listPage(el, 'tab-mastererr', 'mastererr', 'Master Data Errors (wrong bill cycle / no meter serial)', (await getRows('mastererr')).filter((r) => !S.div || r.d === S.div));
  }
  function drillTitle(sp) {
    const names = { cleared: 'Unbilled cases cleared', atrdone: 'Billed / corrected after ATR', repeat: 'Repeat cases', billed: 'Billed', unbilled: 'Unbilled', defective: 'Defective bills', provbilled: 'PROV billed', provunb: 'PROV billed + Unbilled', notfed: 'Smart meter not fed', smarterr: 'Smart meter not billed' };
    return [names[sp.st], sp.val, sp.mt, sp.base, sp.inf ? 'Inflated' : '', sp.cat, sp.firm, sp.lb, sp.seg === 'OTH' ? 'Smart & others' : sp.seg, sp.dto ? 'other defects' : '', sp.xcat ? 'excluding LMV-5' : '', sp.agent ? `MR ${sp.agent}${mrName(sp.agent) ? ' ' + mrName(sp.agent) : ''}` : '', sp.dt, sp.clerk ? 'Clerk ' + sp.clerk : '', sp.je ? 'JE ' + sp.je : '', sp.age, sp.err, sp.mob ? (MOB.find((m) => m[0] === sp.mob) || [])[1] : '', sp.top ? 'top ' + sp.top + ' priority' : '', sp.nw ? 'new since last report' : '', sp.atr === 'none' ? 'ATR not given' : sp.atr === 'given' ? 'ATR given' : '', sp.old ? sp.old + '+ days old' : '', sp.atrv ? 'ATR ' + sp.atrv : '', sp.now, sp.run ? sp.run + ' months running' : '', sp.bd && sp.bd !== '-' ? 'billed on ' + ddmmyyyy(sp.bd) : '', S.div].filter(Boolean).join(' · ');
  }
  function openDrill(sp) { S.drill = sp; S.back = S.tab === 'list' ? S.back : S.tab; LV.drill = null; if (location.hash === '#list') { S.tab = 'list'; render(); } else location.hash = 'list'; }
  async function viewDrill() {
    const sp = S.drill; if (!sp) { location.hash = 'dash'; return; }
    await atrRefresh();
    const rows = await drillRows(sp);
    const kind = sp.st;
    listPage($('view'), 'drill', kind, drillTitle(sp), rows, { back: true, label: drillTitle(sp).replace(/ · /g, ' '), fmt: kind === 'billed' && (['IDF', 'RDF', 'CDF'].includes(sp.base) || sp.agent) ? 1 : sp.top ? 3 : 0, keep: !!sp.top });
  }
  let DET = null;
  // ATR entry for an unbilled case or a defective bill
  function atrBox(r) {
    const isCase = r.mo !== undefined || r.isd !== undefined || r.now || r._kind; if (!isCase || r.res || r.ats) return '';
    const kind = akOf(r); const x = atrOf(r); const opts = (kind === 'unbilled' ? MRD.atrU : MRD.atrD) || [];
    const cur = x ? `<div class="good" style="margin-bottom:8px">ATR: <b>${esc(x.atr)}</b>${x.rem ? ' — ' + esc(x.rem) : ''}<br><span class="muted">by ${esc(x.by || '—')} on ${ddmmyyyy(String(x.ts).slice(0, 10))}</span>${x.ph ? `<div style="margin-top:6px"><button class="btn sm" onclick="BWT.photo('${esc(x.ph)}', this)">📷 View ATR photo</button></div>` : ''}</div>` : '';
    if (!MRD.atr) return `<div class="card dl" style="margin-top:12px">${cur}<span class="muted">ATR entry from the phone is not switched on yet.</span></div>`;
    return `<div class="card dl" style="margin-top:12px"><b>${x ? 'Update ATR' : 'Give ATR'}</b> <span class="muted">(${kind === 'unbilled' ? 'unbilled case' : 'defective bill'})</span>${cur ? '<div style="margin-top:6px">' + cur + '</div>' : ''}
      <select id="atrsel" style="margin-top:8px;width:100%"><option value="">Choose ATR…</option>${opts.map((o) => `<option ${x && x.atr === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>
      <input id="atrrem" placeholder="Remark (optional)" maxlength="200" style="margin-top:8px;width:100%" value="${x ? esc(x.rem || '') : ''}">
      ${r.ty === 'Smart' ? '' : `<label class="phl"><input type="file" id="atrph" accept="image/*" capture="environment" onchange="BWT.picked(this)"><span id="atrphl">📷 Take / attach ATR photo (optional)</span></label>`}
      <button class="btn primary block" id="atrgo" style="margin-top:8px" onclick="BWT.saveAtr()">Save ATR${ME.name ? ' as ' + esc(ME.name) : ''}</button></div>`;
  }
  function detail(r) {
    const mapQ = encodeURIComponent(String(r.ad || '').replace(/\s+IND$/, ''));
    const row = (k, v) => (v === undefined || v === null || v === '' ? '' : `<div class="k">${k}</div><div>${v}</div>`);
    $('sheetIn').innerHTML = `<div class="row"><div class="grow"><div class="muted" style="font-family:monospace">${esc(r.a)}</div><h2 style="margin:2px 0">${esc(r.n)}</h2></div><button class="btn sm" onclick="BWT.close()">✕</button></div>
      ${r.ad ? `<div class="muted" style="margin-bottom:10px">${esc(r.ad)}</div>` : ''}
      <div class="row" style="margin-bottom:10px">${r.m ? `<a class="btn sm" href="tel:${esc(r.m)}">📞 ${esc(r.m)}</a>` : ''}${r.ad ? `<a class="btn sm" target="_blank" href="https://www.google.com/maps/search/?api=1&query=${mapQ}">🗺 Map</a>` : ''}<button class="btn sm" onclick="BWT.searchAcct('${esc(r.a)}')">Full details</button></div>
      <div class="kv">${row('Division', esc(r.d))}${row('Substation', esc(r.s))}${row('Feeder', esc(r.f))}${row('Category / load', `${esc(r.t)} · ${esc(r.l)} KW`)}${row('Meter', `${esc(r.sn || '—')}${r.ty ? ' (' + esc(r.ty) + ')' : ''}`)}
      ${row('Bill', r.bb ? `${esc(r.bb)}${r.bd ? ' · ' + esc(r.bd) : ''}${r.u !== undefined ? ' · ' + N(r.u, 2) + ' units' : ''}${r.ap !== undefined ? ' · ₹' + N(r.ap, 2) : ''}` : '')}${row('Read remark', esc(r.rr))}${row('Defect', esc(r.df))}${row('Months unbilled', r.mo)}${row('Last bill', esc(r.lb))}
      ${row('Last payment', r.lpd ? `${esc(r.lpd)} · ₹${N(r.lpa)}` : '')}${row('Outstanding', r.o !== undefined && r.o !== '' ? '₹' + N(r.o) : '')}${row('Smart reason', esc(r.rs))}${row('Bill cycle', r.cy ? `${esc(r.cy)}${r.ex && +r.wc ? ` <span class="bad">should be ${esc(r.ex)}</span>` : ''}` : '')}${row('Error', esc(r.er))}
      ${row('Meter reader', r.mrn ? `${esc(r.mrn)} ${r.mrm ? '· ' + esc(r.mrm) : ''}` : esc(r.ag))}${row('Clerk', esc(r.cl))}${row('Installed', esc(r.idt))}${row('Meter in CC&B', esc(r.old))}${row('Firm', esc(r.fm))}${row('Book no.', esc(r.bk))}${row('History', esc(r.hist))}</div>${atrBox(r)}`;
    DET = r;
    $('sheet').classList.add('open');
  }
  $('sheet').onclick = (e) => { if (e.target === $('sheet')) $('sheet').classList.remove('open'); };

  // ------------------------------------------------------------ search
  async function viewSearch() {
    $('view').innerHTML = `<h2>Search a consumer</h2><div class="row" style="margin-bottom:10px"><input type="search" id="sq" class="grow" inputmode="numeric" placeholder="10-digit account number or mobile number" value="${esc(S.sq || '')}"><button class="btn primary" id="sgo">Search</button></div><div id="sres"></div>`;
    const go = () => { S.sq = $('sq').value.replace(/\D/g, ''); doSearch(S.sq); };
    $('sgo').onclick = go; $('sq').onkeydown = (e) => { if (e.key === 'Enter') go(); };
    if (S.sq) doSearch(S.sq);
  }
  async function findAcct(a) {
    a = a.replace(/^0+/, '');
    const t = await load('search/a' + String(+a.slice(-2) % 100).padStart(2, '0'));
    const i = t.rows.findIndex((r) => r[0] === a);
    return i < 0 ? null : Object.fromEntries(t.cols.map((c, j) => [c, t.rows[i][j]]));
  }
  async function doSearch(q) {
    const out = $('sres'); if (!q) return;
    out.innerHTML = '<div class="spinner"></div>';
    let accts = [];
    if (q.length === 10) { const p = await load('search/m' + q.slice(-2)); accts = p[q] || []; }
    const direct = await findAcct(q); const recs = [];
    if (direct) recs.push(direct);
    for (const a of accts) if (!recs.some((r) => r.a === a)) { const r = await findAcct(a); if (r) recs.push(r); }
    out.innerHTML = recs.map((r) => `<div class="card"><div class="muted" style="font-family:monospace">${esc(r.a)} · ${esc(r.d)}</div><h2 style="margin:2px 0 4px">${esc(r.n)}</h2><div class="muted">${esc(r.ad)}</div>
      <div class="row" style="margin:10px 0">${r.m ? `<a class="btn sm" href="tel:${esc(r.m)}">📞 ${esc(r.m)}</a>` : ''}</div>
      <div class="kv">
        <div class="k">Status</div><div>${esc(r.st || '—')}${r.td ? ' · TD ' + esc(r.td) : ''}</div>
        <div class="k">Substation / feeder</div><div>${esc(r.s)} · ${esc(r.f || '—')}</div>
        <div class="k">Category / load</div><div>${esc(r.c)} · ${esc(r.l)} KW · book ${esc(r.bk || '—')}</div>
        <div class="k">Meter</div><div>${esc(r.sn || '—')} (${esc(r.ty || '—')}) · cycle ${esc(r.cy || '—')}</div>
        <div class="k">This month</div><div>${r.nb ? `<b>Billed ${esc(r.nb)}</b> on ${esc(r.nbd)} · ${N(r.nu, 2)} units · ₹${N(r.nap, 2)} payable · remark ${esc(r.nrr || '—')}` : r.ub !== '' ? `<b class="bad">Unbilled</b> (${esc(r.ub)} month(s) since last bill)` : 'Not in today\'s billed/unbilled reports'}</div>
        <div class="k">Master (${esc(REP.masterMonth || 'last month')})</div><div>last bill ${esc(r.lb || '—')} · ${esc(r.bb || '—')} · ${N(r.u)} units · CA ₹${N(r.ca, 2)}</div>
        <div class="k">Payment</div><div>₹${N(r.pa)} on ${esc(r.pd || '—')}</div>
        <div class="k">Outstanding</div><div><b>₹${N(r.o)}</b></div>
      </div></div>`).join('') || '<div class="empty">No consumer found. Check the account / mobile number.</div>';
  }

  // ------------------------------------------------------------ public
  window.BWT = {
    picked(inp) { const f = inp.files && inp.files[0]; $('atrphl').textContent = f ? '📷 Photo attached — tap to change' : '📷 Take / attach ATR photo (optional)'; inp.parentNode.classList.toggle('on', !!f); },
    async photo(id, btn) {
      btn.disabled = true; btn.textContent = 'Loading photo…';
      try {
        const r = await fetch(`${MRD.atr.url}?action=photo&id=${encodeURIComponent(id)}&key=${encodeURIComponent(MRD.atr.key)}`); const j = await r.json(); if (!j.ok) throw new Error(j.error);
        const im = document.createElement('img'); im.src = 'data:image/jpeg;base64,' + j.data; im.style.cssText = 'width:100%;border-radius:10px;margin-top:6px'; btn.replaceWith(im);
      } catch (e) { btn.disabled = false; btn.textContent = '📷 View ATR photo'; toast('Could not load the photo'); }
    },
    async saveAtr() {
      const r = DET; const atr = $('atrsel').value; if (!r || !atr) { toast('Choose an ATR first'); return; }
      const b = $('atrgo'); b.disabled = true; b.textContent = 'Saving…';
      try {
        const f = $('atrph') && $('atrph').files && $('atrph').files[0]; let photo = '';
        if (f) { b.textContent = 'Preparing photo…'; photo = await shrinkPhoto(f); b.textContent = 'Uploading…'; }
        const j = await atrSave(r.a, akOf(r), atr, $('atrrem').value.trim(), photo);
        toast(photo && !(j.photos && j.photos[0]) ? 'ATR saved, but the photo was NOT stored — the office has to update the Google script' : photo ? 'ATR and photo saved' : 'ATR saved');
        $('sheet').classList.remove('open'); const y = window.scrollY; render(); setTimeout(() => window.scrollTo(0, y), 300);
      } catch (e) { toast('Could not save ATR — check the internet and try again'); b.disabled = false; b.textContent = 'Save ATR'; }
    },
    close() { $('sheet').classList.remove('open'); },
    searchAcct(a) { $('sheet').classList.remove('open'); S.sq = a; location.hash = 'search'; if (S.tab === 'search') render(); },
    async lock() { await idbDel('login'); KEYS = null; ROLE = ''; Object.keys(MEM).forEach((k) => delete MEM[k]); location.hash = ''; loginView(); },
  };
  start();
})();
