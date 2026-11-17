/* Our Trips — a family view of the household travel agent, plus the resort's daily schedule.
   Data is AES-GCM encrypted (data.enc.json); the passphrase never leaves this device. */
'use strict';
const PASS_KEY = 'tb_pass';
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

let DATA = null;
let resortDay = null;
let resortMeal = null;
let rsMenu = 'club', rsMeal = null, rsOpen = false, drKey = 'wine', drOpen = false;

/* ---------- dates ---------- */
const todayISO = () => { const d = new Date(); return new Date(d.getTime() - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 10); };
const parseISO = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const WD = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const fmtDay = s => { const d = parseISO(s); return `${['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][d.getDay()]}, ${MON[d.getMonth()]} ${d.getDate()}`; };
const fmtShort = s => { const d = parseISO(s); const y = d.getFullYear() !== new Date().getFullYear() ? `, ${d.getFullYear()}` : ''; return `${WD[d.getDay()]} ${MON[d.getMonth()]} ${d.getDate()}${y}`; };
const daysBetween = (a, b) => Math.round((parseISO(b) - parseISO(a)) / 864e5);
function t12(hm) {
  if (!hm) return '';
  let [h, m] = hm.split(':').map(Number);
  if (h === 0 && m === 0) return 'midnight';
  const ap = h >= 12 ? 'pm' : 'am'; h = h % 12 || 12;
  return m ? `${h}:${String(m).padStart(2, '0')} ${ap}` : `${h} ${ap}`;
}

/* ---------- crypto ---------- */
async function decrypt(env, pass) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(env.salt), iterations: env.iter },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(env.iv) }, key, b64(env.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function load(pass) {
  const r = await fetch('data.enc.json?t=' + Date.now(), { cache: 'no-store' });
  if (!r.ok) throw new Error('fetch ' + r.status);
  return decrypt(await r.json(), pass);
}

/* ---------- itinerary picks: shared, encrypted, append-only event log (Supabase) ----------
   Each add/remove is sealed with a key derived from the passphrase; the server stores only
   ciphertext. Rows that don't decrypt (junk from strangers) are ignored. Unsent events wait in
   a local outbox and retry, so a pick made on weak resort Wi-Fi isn't lost. */
const SB_URL = 'https://mxcpjsdvdqhgutdzzggo.supabase.co/rest/v1/trip_picks';
const SB_KEY = 'sb_publishable_pouH8Pbp8THffNLTjavPdA_3RzW0NCf';   // public by design; RLS = insert/read only
const OUTBOX = 'tb_outbox', WHO = 'tb_who';
let PASS = null, PICK_KEY = null, PICKS = [], picksTimer = null;
const u8b64 = u => btoa(String.fromCharCode(...new Uint8Array(u)));
async function pickKey() {
  if (!PICK_KEY) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(PASS), 'PBKDF2', false, ['deriveKey']);
    PICK_KEY = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode('our-trips/picks/v1'), iterations: 310000 },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  return PICK_KEY;
}
async function seal(ev) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await pickKey(), new TextEncoder().encode(JSON.stringify(ev)));
  return `v1.${u8b64(iv)}.${u8b64(ct)}`;
}
async function unseal(p) {
  try {
    const [v, iv, ct] = String(p).split('.');
    if (v !== 'v1') return null;
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(iv) }, await pickKey(), b64(ct));
    const ev = JSON.parse(new TextDecoder().decode(pt));
    return ev && (ev.op === 'add' || ev.op === 'remove') && ev.pid ? ev : null;
  } catch (_) { return null; }
}
const outbox = () => { try { return JSON.parse(localStorage.getItem(OUTBOX) || '[]'); } catch (_) { return []; } };
const setOutbox = xs => localStorage.setItem(OUTBOX, JSON.stringify(xs));
let SERVER_EVENTS = [];
function fold() {
  const m = new Map();
  for (const ev of [...SERVER_EVENTS, ...outbox()]) { if (ev.op === 'add') m.set(ev.pid, ev); else m.delete(ev.pid); }
  PICKS = [...m.values()].sort((a, b) => (a.date + (a.start || '99')).localeCompare(b.date + (b.start || '99')));
}
async function syncPicks() {
  if (!PASS) return;
  const pending = outbox(); const left = [];
  for (const ev of pending) {   // flush queued events first
    try {
      const r = await fetch(SB_URL, { method: 'POST', headers: { apikey: SB_KEY, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
        body: JSON.stringify({ board: 'our-trips', payload: await seal(ev) }) });
      if (!r.ok) left.push(ev);
    } catch (_) { left.push(ev); }
  }
  setOutbox(left);
  try {
    const r = await fetch(`${SB_URL}?select=id,payload&board=eq.our-trips&order=id.asc&limit=2000`, { headers: { apikey: SB_KEY }, cache: 'no-store' });
    if (r.ok) SERVER_EVENTS = (await Promise.all((await r.json()).map(row => unseal(row.payload)))).filter(Boolean);
  } catch (_) { /* offline: keep what we have */ }
  fold(); rerender();
}
function rerender() { if (!DATA) return; renderTrip(); if (resortVisible()) renderResort(); }
const newId = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));
async function whoAmI() {
  let w = localStorage.getItem(WHO);
  if (w) return w;
  const names = (activeTrip()?.travelers || ['Meghan', 'Shea']);
  w = await sheet(`<h3>Who's adding plans on this phone?</h3><div class="sheet-row">${names.map(n => `<button class="pill" data-val="${esc(n)}">${esc(n)}</button>`).join('')}</div>`);
  if (w) localStorage.setItem(WHO, w);
  return w;
}
async function addPick(fields) {
  const by = await whoAmI(); if (!by) return;
  const ev = { op: 'add', pid: newId(), by, ts: new Date().toISOString(), ...fields };
  setOutbox([...outbox(), ev]); fold(); rerender(); toast(`Added to ${fmtShort(ev.date)} 🌺`);
  syncPicks();
}
async function removePick(pid) {
  const p = PICKS.find(x => x.pid === pid); if (!p) return;
  if (!confirm(`Remove “${p.title}” from ${fmtShort(p.date)}?`)) return;
  const by = localStorage.getItem(WHO) || '';
  setOutbox([...outbox(), { op: 'remove', pid, by, ts: new Date().toISOString(), title: p.title, date: p.date, start: p.start }]);
  fold(); rerender(); syncPicks();
}
function toast(msg) {
  let t = $('#toast'); if (!t) { t = document.createElement('div'); t.id = 'toast'; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add('on'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('on'), 1800);
}
/* bottom sheet: resolves with the clicked [data-val] or the form's values, or null */
function sheet(inner) {
  return new Promise(res => {
    const wrap = document.createElement('div'); wrap.className = 'sheet-wrap';
    wrap.innerHTML = `<div class="sheet">${inner}<button class="sheet-cancel">Cancel</button></div>`;
    document.body.appendChild(wrap); requestAnimationFrame(() => wrap.classList.add('on'));
    const done = v => { wrap.classList.remove('on'); setTimeout(() => wrap.remove(), 200); res(v); };
    wrap.addEventListener('click', e => {
      if (e.target === wrap || e.target.closest('.sheet-cancel')) return done(null);
      const b = e.target.closest('[data-val]'); if (b) done(b.dataset.val);
    });
    const f = wrap.querySelector('form');
    if (f) f.addEventListener('submit', e => { e.preventDefault(); done(Object.fromEntries(new FormData(f))); });
  });
}
function timeOptions(from, to, sel) {
  const out = []; let [h, m] = (from || '06:00').split(':').map(Number); const [eh, em] = (to || '23:30').split(':').map(Number);
  while (h * 60 + m <= eh * 60 + em) { const v = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`; out.push(`<option value="${v}" ${v === sel ? 'selected' : ''}>${t12(v)}</option>`); m += 30; if (m >= 60) { h++; m -= 60; } }
  return out.join('');
}
async function addRestaurant(date, r, meal) {
  const last = r.end ? (() => { let [h, m] = r.end.split(':').map(Number); let t = h * 60 + m - 60; if (h === 0) t = 23 * 60; return `${String(Math.floor(t / 60)).padStart(2, '0')}:${String(t % 60).padStart(2, '0')}`; })() : null;
  const def = meal === 'dinner' ? (r.start <= '19:00' && (!last || last >= '19:00') ? '19:00' : r.start) : r.start;
  const v = await sheet(`<h3>${esc(r.name)} · ${fmtShort(date)}</h3><form>
    <label>Time<select name="time">${timeOptions(r.start, last || r.end, def)}</select></label>
    <label>Note (optional)<input name="note" placeholder="e.g. ask for a table by the water" maxlength="200"></label>
    ${r.note && /reserv/i.test(r.note) ? `<p class="small muted">${esc(r.note)}</p>` : ''}
    <button class="pill solid" type="submit">Add to our plans</button></form>`);
  if (!v) return;
  addPick({ date, start: v.time, end: null, title: r.name, where: meal[0].toUpperCase() + meal.slice(1), kind: 'Dining', note: v.note || '',
    needs_reservation: !!(r.note && /reserv/i.test(r.note)) });
}
async function addCustom(date) {
  const v = await sheet(`<h3>Add to ${fmtShort(date)}</h3><form>
    <label>What<input name="title" required maxlength="120" placeholder="e.g. Sunset drinks at Whisper"></label>
    <label>Time<select name="time"><option value="">Any time</option>${timeOptions('06:00', '23:30', '')}</select></label>
    <label>Note (optional)<input name="note" maxlength="200"></label>
    <button class="pill solid" type="submit">Add to our plans</button></form>`);
  if (!v || !v.title.trim()) return;
  addPick({ date, start: v.time || null, end: null, title: v.title.trim(), where: '', kind: 'Our own', note: v.note || '' });
}
const mins = hm => { const [h, m] = hm.split(':').map(Number); return h * 60 + m; };
function markConflicts(evs) {
  const timed = evs.filter(e => e.time);
  for (const e of timed) {
    if (!e.pick) continue;
    const s = mins(e.time), en = e.end ? mins(e.end) : s + 60;
    const hit = timed.find(o => o !== e && o.date === e.date && mins(o.time) < en && s < (o.end ? mins(o.end) : mins(o.time) + 60));
    if (hit) e.conflict = (hit.pick ? hit.what : hit.what.split(/\s+[-–(·]\s*|,/)[0]).trim();
  }
}

/* ---------- tiny markdown (headings, bullets, bold, paragraphs) ---------- */
function md(src) {
  const inline = s => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/\*(.+?)\*/g, '<i>$1</i>');
  const out = []; let list = false, para = [];
  const flush = () => { if (para.length) { out.push(`<p>${inline(para.join(' '))}</p>`); para = []; } };
  for (const raw of String(src || '').split('\n')) {
    const line = raw.trimEnd();
    if (/^#\s/.test(line)) continue;                       // drop the document title
    const h = line.match(/^#{2,3}\s+(.*)/);
    const li = line.match(/^\s*[-*]\s+(.*)/);
    if (h) { flush(); if (list) { out.push('</ul>'); list = false; } out.push(`<h3>${inline(h[1])}</h3>`); }
    else if (li) { flush(); if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${inline(li[1])}</li>`); }
    else if (!line.trim()) { flush(); if (list) { out.push('</ul>'); list = false; } }
    else if (list && /^\s{2,}/.test(raw)) { out[out.length - 1] = out[out.length - 1].replace(/<\/li>$/, ' ' + inline(line.trim()) + '</li>'); }
    else { if (list) { out.push('</ul>'); list = false; } para.push(line.trim()); }
  }
  flush(); if (list) out.push('</ul>');
  return out.join('');
}

/* ---------- trip helpers ---------- */
function activeTrip() {
  const trips = DATA.travel.trips || [];
  const t = todayISO();
  return trips.find(x => x.start <= t && x.end >= t) || trips.find(x => x.start >= t) || null;
}
function statusChip(s) {
  if (!s) return '';
  const ok = /confirm|booked|done|paid|on time/i.test(s) && !/not|unpaid|expired|cancel/i.test(s);
  return `<span class="chip ${ok ? 'ok' : 'warn'}">${esc(s)}</span>`;
}
const normT = x => (x || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
function isPickCopy(r, time) {
  if ((r.status || '').toLowerCase() === 'planned' && /our trips/i.test(r.detail || '')) return true;
  const w = normT(r.what);
  return PICKS.some(p => {
    const pt = normT(p.title);
    if (!pt || p.date !== r.date) return false;
    if (w.startsWith(pt) && (!time || !p.start || p.start === time)) return true;
    return !!(time && p.start === time && w.includes(pt));   // e.g. "Miile Spa - Nidra Treatment, 10:00 AM"
  });
}

function tripEvents(trip) {
  const ev = [];
  for (const f of trip.flights || [])
    ev.push({ date: f.date, time: f.depart, what: `${f.carrier} ${f.number} · ${f.from} → ${f.to}`,
      detail: `Departs ${t12(f.depart)}, arrives ${t12(f.arrive)}${f.seats ? ` · seats ${f.seats}` : ''}${f.cabin ? ` · ${f.cabin}` : ''}`, status: f.status, icon: '✈︎' });
  if (trip.stay) {
    const [ci, cit] = (trip.stay.check_in || '').split(' '); const [co, cot] = (trip.stay.check_out || '').split(' ');
    if (ci) ev.push({ date: ci, time: cit, what: `Check in · ${trip.stay.name}`, detail: trip.stay.room, icon: '🏨' });
    if (co) ev.push({ date: co, time: cot, what: `Check out · ${trip.stay.name}`, detail: '', icon: '🏨' });
  }
  const to24 = (h, m, ap) => { h = +h % 12; if (/pm/i.test(ap)) h += 12; return `${String(h).padStart(2, '0')}:${m}`; };
  for (const g of trip.ground || []) {
    // a pickup time in the text wins; otherwise an airport pickup follows that day's landing
    const pk = (g.detail || '').match(/pick-?up at (\d{1,2}):(\d{2})\s*(AM|PM)/i);
    const land = (trip.flights || []).find(f => f.date === g.date && f.to !== 'DFW');
    const time = pk ? to24(pk[1], pk[2], pk[3]) : land && /airport to/i.test(g.what) ? land.arrive : null;
    ev.push({ date: g.date, time, what: g.what, detail: g.detail, status: g.status, icon: '🚐' });
  }
  for (const r of trip.reservations || []) {
    const m = (r.what || '').match(/(\d{1,2}):(\d{2})\s*(AM|PM)/i);
    let time = null; if (m) { let h = +m[1] % 12; if (/pm/i.test(m[3])) h += 12; time = `${String(h).padStart(2, '0')}:${m[2]}`; }
    // The agent copies app picks into its records as "planned" items. The pick log is the live
    // source (it shows removals at once), so skip the agent's copy of any Our Trips plan.
    if (isPickCopy(r, time)) continue;
    ev.push({ date: r.date, time, what: r.what, detail: r.detail, status: r.status, icon: '★' });
  }
  for (const d of trip.deadlines || []) ev.push({ date: d.date, time: null, what: d.what, detail: '', status: 'deadline', icon: '⏰' });
  for (const p of PICKS) if (p.date >= trip.start && p.date <= trip.end)
    ev.push({ date: p.date, time: p.start || null, end: p.end || null, what: p.title, pick: p, icon: '🌺',
      detail: [p.where, p.note].filter(Boolean).join(' · ') });
  ev.sort((a, b) => (a.date + (a.time || '99')).localeCompare(b.date + (b.time || '99')));
  markConflicts(ev);
  return ev;
}
function eventHTML(e) {
  if (e.pick) {
    const p = e.pick, pending = outbox().some(o => o.pid === p.pid);
    return `<div class="item pick"><div class="t">${e.time ? t12(e.time) : e.icon}</div><div class="b">
      <div class="what">${esc(e.what)}</div>${e.detail ? `<div class="detail">${esc(e.detail)}</div>` : ''}
      <span class="chip pick">Our pick · ${esc(p.by || '')}</span>${pending ? '<span class="chip kind">Saving…</span>' : ''}
      ${p.needs_reservation ? '<span class="chip warn">Needs a reservation</span>' : ''}
      ${e.conflict ? `<div class="conflict">⚠︎ Overlaps ${esc(e.conflict.length > 40 ? e.conflict.slice(0, 38) + '…' : e.conflict)}</div>` : ''}
      </div><button class="unpick" data-unpick="${esc(p.pid)}" aria-label="Remove">✕</button></div>`;
  }
  return `<div class="item"><div class="t">${e.time ? t12(e.time) : e.icon}</div><div class="b">
    <div class="what">${esc(e.what)}</div>${e.status ? statusChip(e.status) : ''}
    ${e.detail ? `<details><summary class="detail">Details</summary><div class="detail">${esc(e.detail)}</div></details>` : ''}</div></div>`;
}

/* The agent may write the brief the night before ("Good evening", "## Tomorrow") or the same
   morning; its day-plan section is always about meta.for. Label it relative to the real today. */
function tripModeMd(tm, t) {
  const f = tm.meta?.for; let m = tm.markdown;
  if (!f) return m;
  const n = daysBetween(t, f);
  const rel = n === 0 ? 'Today' : n === 1 ? 'Tomorrow' : n === -1 ? 'Yesterday' : fmtShort(f);
  const label = n === 0 || n === 1 || n === -1 ? `${rel} · ${fmtShort(f)}` : rel;
  m = m.replace(/^##\s*(Tomorrow|Today|Tonight)\b.*$/gim, `## ${label}`);
  m = m.replace(/^##\s*Good (morning|afternoon|evening)\s*$/gim, '## The big picture');
  return m;
}

/* ---------- Our trip tab ---------- */
function renderTrip() {
  const el = $('#tab-trip'); const T = DATA.travel; const trip = activeTrip(); const t = todayISO();
  let h = '';
  if (trip) {
    const until = daysBetween(t, trip.start); const dayN = daysBetween(trip.start, t) + 1; const len = daysBetween(trip.start, trip.end) + 1;
    const when = until > 1 ? `In ${until} days` : until === 1 ? 'Tomorrow!' : until === 0 ? 'Today!' : `Day ${dayN} of ${len}`;
    h += `<div class="card hero"><div class="big">${esc(trip.stay?.name || trip.name)}</div>
      <div>${fmtShort(trip.start)} – ${fmtShort(trip.end)} · ${esc((trip.travelers || []).join(' & '))}</div>
      <div class="muted small" style="margin-top:4px">${when}${trip.stay?.room ? ' · ' + esc(trip.stay.room) : ''}</div></div>`;
  }
  const tm = T.trip_mode || {};
  if (tm.markdown && (tm.meta?.active || '').toLowerCase() === 'yes') {
    h += `<div class="card"><h2>☀️ ${tm.meta.for ? 'For ' + fmtShort(tm.meta.for) : 'Today'}</h2><div class="md">${md(tripModeMd(tm, t))}</div></div>`;
  }
  if (trip) {
    const ev = tripEvents(trip); const byDate = {};
    ev.forEach(e => (byDate[e.date] = byDate[e.date] || []).push(e));
    h += `<div class="card"><h2>✈️ Itinerary</h2>`;
    for (const d of Object.keys(byDate).sort()) {
      if (d < t && trip.start > t) continue;
      h += `<div class="day"><div class="day-head">${fmtDay(d)}${d === t ? ' · today' : ''}</div>${byDate[d].map(eventHTML).join('')}</div>`;
    }
    h += `</div>`;
    if ((trip.to_do || []).length) h += `<div class="card"><h2>📝 To do</h2><div class="md"><ul>${trip.to_do.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>`;
    if (trip.notes) h += `<div class="card"><h2>🐚 Notes</h2><div class="small">${esc(trip.notes)}</div></div>`;
  }
  if (T.report_md) h += `<div class="card"><details><summary><h2 style="display:inline">📰 Travel report</h2></summary><div class="md" style="margin-top:10px">${md(T.report_md)}</div></details></div>`;
  const later = (T.trips || []).filter(x => !trip || x.id !== trip.id);
  if (later.length) h += `<div class="card"><h2>🗓️ Coming up</h2>${later.map(x => `<div class="item"><div class="t">${fmtShort(x.start).replace(/^\w+ /, '')}</div><div class="b"><div class="what">${esc(x.stay?.name || x.name)}</div><div class="detail">${fmtShort(x.start)} – ${fmtShort(x.end)}${x.stay?.room ? ' · ' + esc(x.stay.room) : ''}</div>${x.notes ? `<details><summary class="detail">Notes</summary><div class="detail">${esc(x.notes)}</div></details>` : ''}</div></div>`).join('')}</div>`;
  for (const l of T.loyalty || []) {
    const q = l.qualifying; const pct = q && q.need ? Math.min(100, Math.round(100 * q.have / q.need)) : null;
    h += `<div class="card"><h2>⭐ ${esc(l.program)}</h2><div class="big" style="font-weight:700">${esc(l.tier || '')}</div>
      ${l.points != null ? `<div>${Number(l.points).toLocaleString()} ${esc(l.points_name || 'points')}</div>` : ''}
      ${pct != null ? `<div class="progress"><div style="width:${pct}%"></div></div><div class="small muted">${Number(q.have).toLocaleString()} of ${Number(q.need).toLocaleString()} ${esc(q.label || '')}${l.expires ? ' · by ' + fmtShort(l.expires) : ''}</div>` : ''}
      ${l.notes ? `<details><summary class="small muted">Notes</summary><div class="small muted">${esc(l.notes)}</div></details>` : ''}</div>`;
  }
  el.innerHTML = h || '<div class="card empty">No trips on file.</div>';
}

/* ---------- Resort tab ---------- */
function resortVisible() { const R = DATA.resort; return !!(R && R.days && R.days.length && todayISO() <= R.window_end); }
function renderResort() {
  const R = DATA.resort; const el = $('#tab-resort'); const t = todayISO();
  if (!resortDay || !R.days.find(d => d.date === resortDay)) resortDay = (R.days.find(d => d.date === t) || R.days.find(d => d.date > t) || R.days[0]).date;
  const day = R.days.find(d => d.date === resortDay);
  const trip = activeTrip();
  let h = `<div class="days">${R.days.map(d => { const x = parseISO(d.date); return `<button data-day="${d.date}" class="${d.date === resortDay ? 'on' : ''}"><span class="dw">${WD[x.getDay()]}</span><span class="dn">${x.getDate()}</span>${d.date === t ? '<span class="today">TODAY</span>' : ''}</button>`; }).join('')}</div>`;

  // our plans that day
  if (trip) {
    const mine = tripEvents(trip).filter(e => e.date === day.date && e.status !== 'deadline');
    h += `<div class="card plans"><h2>🌺 Our plans · ${fmtDay(day.date)}</h2>${mine.length ? mine.map(eventHTML).join('') : '<div class="empty">Nothing planned yet — tap ＋ on anything below.</div>'}
      <button class="add-custom" data-add-custom="${day.date}">＋ Add something else</button></div>`;
  }

  // restaurants
  const meals = day.meals; const order = ['breakfast', 'lunch', 'dinner'];
  if (!resortMeal) { const hr = new Date().getHours(); resortMeal = day.date === t ? (hr < 11 ? 'breakfast' : hr < 16 ? 'lunch' : 'dinner') : 'dinner'; }
  h += `<div class="card"><h2>🍽️ Restaurants open</h2><div class="seg">${order.map(m => `<button data-meal="${m}" class="${m === resortMeal ? 'on' : ''}">${m[0].toUpperCase() + m.slice(1)} <span class="small">(${meals[m].length})</span></button>`).join('')}</div>`;
  const list = meals[resortMeal];
  const picked = (title, start) => PICKS.some(p => p.date === day.date && p.title === title && (!start || p.start === start));
  h += list.length ? list.map((r, i) => `<div class="rest"><div class="row"><span class="name">${esc(r.name)}</span><span class="hrs">${t12(r.start)}–${t12(r.end)}</span></div>
      <div class="cui">${esc(r.cuisine)}</div>
      <div class="tags">${r.club ? '<span class="chip club">Club only</span>' : ''}${r.dress ? `<span class="chip dress">${esc(r.dress)}</span>` : ''}${r.menu ? `<a class="menu-link" href="${esc(r.menu)}" target="_blank" rel="noopener">Menu ↗</a>` : ''}
      ${picked(r.name) ? '<span class="added">✓ In our plans</span>' : `<button class="add" data-add-rest="${resortMeal}|${i}">＋ Add</button>`}</div>
      ${r.note ? `<div class="note">${esc(r.note)}</div>` : ''}</div>`).join('')
    : '<div class="empty">Nothing listed.</div>';
  h += `<div class="small muted" style="margin-top:8px">The buffet, room service (24 h), Típico and the Sports Bar are open every day.</div></div>`;

  // room service (same every day)
  const RS = R.room_service || [];
  if (RS.length) {
    if (!rsMeal) { const hm = new Date().toTimeString().slice(0, 5); rsMeal = hm >= '05:30' && hm < '11:30' ? 'Breakfast' : hm >= '11:30' && hm < '23:30' ? 'Lunch & dinner' : 'Night'; }
    const keys = [...new Set(RS.map(m => m.key))];
    const cur = RS.find(m => m.key === rsMenu && m.meal === rsMeal) || RS.find(m => m.meal === rsMeal) || RS[0];
    h += `<div class="card"><details id="rsCard" ${rsOpen ? 'open' : ''}><summary><h2 style="display:inline">🛎️ Room service</h2></summary>
      <div class="small muted" style="margin:8px 0 10px">Around the clock and included. Delivery takes about 35 minutes, and they'll set dinner up on your terrace if you ask. Your suite gets the Club menu.</div>
      <div class="seg">${['Breakfast', 'Lunch & dinner', 'Night'].map(m => `<button data-rs-meal="${m}" class="${m === cur.meal ? 'on' : ''}">${m === 'Lunch & dinner' ? 'All day' : m}</button>`).join('')}</div>
      ${keys.length > 1 ? `<div class="seg mini">${keys.map(k => `<button data-rs-menu="${k}" class="${k === cur.key ? 'on' : ''}">${k === 'club' ? 'Club menu' : 'Standard menu'}</button>`).join('')}</div>` : ''}
      <div class="small muted">${esc(cur.menu)} · ${esc(cur.meal)} · served ${esc(cur.hours || '')}</div>
      ${cur.sections.map(sc => `<div class="meal-title">${esc(sc.name)}</div>${sc.note ? `<div class="small muted">${esc(sc.note)}</div>` : ''}${sc.items.map(i => `<div class="rs-item"><b>${esc(i.name)}</b>${i.desc ? ` <span class="muted">· ${esc(i.desc)}</span>` : ''}</div>`).join('')}`).join('')}
      </details></div>`;
  }

  // wine & spirits (priced lists)
  const DR = R.drinks || [];
  if (DR.length) {
    const cur = DR.find(x => x.key === drKey) || DR[0];
    h += `<div class="card"><details id="drCard" ${drOpen ? 'open' : ''}><summary><h2 style="display:inline">🍷 Wine & spirits</h2></summary>
      <div class="small muted" style="margin:8px 0 10px">Premium bottles, pours and tastings with a price, on top of the drinks included in your stay. Prices in US dollars; La Cava also does tastings.</div>
      <div class="seg">${DR.map(x => `<button data-dr="${x.key}" class="${x.key === cur.key ? 'on' : ''}">${esc(x.label)}</button>`).join('')}</div>
      ${cur.sections.map(sc => {
        let last = null;
        const rows = sc.items.map(i => { const g = i.group && i.group !== last ? `<div class="dr-group">${esc(i.group)}</div>` : ''; last = i.group;
          return `${g}<div class="dr-item"><div class="row"><b>${esc(i.name)}</b><span class="dr-price">${esc(i.price)}</span></div>${i.desc ? `<div class="small muted">${esc(i.desc)}</div>` : ''}</div>`; }).join('');
        return `<details class="dr-sec"><summary>${esc(sc.name)} <span class="small muted">(${sc.items.length})</span></summary>${rows}</details>`;
      }).join('')}
      </details></div>`;
  }

  // activities
  const acts = day.activities;
  const part = a => { const hr = +(a.start || '0').slice(0, 2); return a.kind === 'Evening show' || hr >= 18 ? 'Evening' : hr >= 12 ? 'Afternoon' : 'Morning'; };
  h += `<div class="card"><h2>🎶 Activities & shows</h2>`;
  for (const p of ['Morning', 'Afternoon', 'Evening']) {
    const xs = acts.filter(a => part(a) === p); if (!xs.length) continue;
    h += `<div class="day-head">${p}</div>` + xs.map(a => {
      const ai = acts.indexOf(a), on = picked(a.name, a.start);
      const show = a.kind === 'Evening show';
      const meta = [esc(a.where), !show && a.kind !== 'Activity' ? esc(a.kind) : ''].filter(Boolean).join(' · ');
      const body = `<div class="what">${esc(a.name)}${show ? ' <span class="chip show">Show</span>' : ''}</div><div class="detail">${meta}</div>`;
      return `<div class="item act ${show ? 'evening' : ''}"><div class="t">${t12(a.start)}<small>${t12(a.end)}</small></div><div class="b">${
        a.desc ? `<details><summary>${body}</summary><div class="detail about">${esc(a.desc)}</div></details>` : body}</div>${
        on ? '<span class="add-dot on" aria-label="In our plans">✓</span>' : `<button class="add-dot" data-add-act="${ai}" aria-label="Add to our plans">＋</button>`}</div>`;
    }).join('');
  }
  if (!acts.length) h += '<div class="empty">No activities listed.</div>';
  h += `</div>`;

  // bars
  h += `<div class="card"><details><summary><h2 style="display:inline">🍹 Bars open (${day.bars.length})</h2></summary>${day.bars.map(b => `<div class="rest"><div class="row"><span class="name">${esc(b.name)}</span><span class="hrs">${t12(b.start)}–${t12(b.end)}</span></div><div class="cui">${esc(b.drinks)}</div>${b.club ? '<span class="chip club">Club only</span>' : ''}</div>`).join('')}</details></div>`;

  if ((R.tips || []).length) h += `<div class="card"><h2>🐢 Good to know</h2><div class="md"><ul>${R.tips.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div></div>`;
  h += `<div class="small muted">From the resort's own app${R.app_read_at ? ', checked ' + esc(R.app_read_at) : ''}. Times are resort time (Cancún). The resort can change the schedule.</div>`;
  el.innerHTML = h;
}

/* ---------- shell ---------- */
function setTab(name) {
  document.querySelectorAll('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
  $('#tab-trip').hidden = name !== 'trip'; $('#tab-resort').hidden = name !== 'resort';
  sessionStorage.setItem('tb_tab', name); window.scrollTo(0, 0);
}
function render() {
  const trip = activeTrip();
  $('#topTitle').textContent = trip ? (trip.destination || trip.name) : 'Our Trips';
  $('#topSub').textContent = trip ? `${fmtShort(trip.start)} – ${fmtShort(trip.end)}` : '';
  renderTrip();
  const rv = resortVisible();
  $('#resortTabBtn').hidden = !rv;
  if (rv) renderResort();
  $('#foot').textContent = `Updated ${DATA.published ? new Date(DATA.published).toLocaleString([], { weekday: 'short', hour: 'numeric', minute: '2-digit' }) : ''}. Confirmation numbers are left out on purpose.`;
  setTab(rv && sessionStorage.getItem('tb_tab') === 'resort' ? 'resort' : 'trip');
}
class BadPass extends Error {}
async function open(pass) {
  let data;
  try { data = await load(pass); }
  catch (e) { if (e && e.name === 'OperationError') throw new BadPass(); throw e; }   // AES-GCM auth failure = wrong passphrase
  DATA = data; PASS = pass; PICK_KEY = null; fold();
  localStorage.setItem(PASS_KEY, pass);
  $('#lock').hidden = true; $('#app').hidden = false;
  try { render(); }
  catch (e) {   // never lock her out because of a display bug — show what broke instead
    $('#tab-trip').innerHTML = `<div class="card"><h2>Something didn't display</h2><div class="small muted">${esc(e && (e.stack || e.message) || e)}</div></div>` + $('#tab-trip').innerHTML;
    $('#tab-trip').hidden = false;
  }
  syncPicks();
  clearInterval(picksTimer);
  picksTimer = setInterval(() => { if (document.visibilityState === 'visible') syncPicks(); }, 60000);
}
document.addEventListener('click', e => {
  const tb = e.target.closest('#tabs button'); if (tb) return setTab(tb.dataset.tab);
  const db = e.target.closest('[data-day]'); if (db) { resortDay = db.dataset.day; resortMeal = null; renderResort(); return; }
  const mb = e.target.closest('[data-meal]'); if (mb) { resortMeal = mb.dataset.meal; renderResort(); return; }
  const rm = e.target.closest('[data-rs-meal]'); if (rm) { rsMeal = rm.dataset.rsMeal; rsOpen = true; renderResort(); return; }
  const dk = e.target.closest('[data-dr]'); if (dk) { drKey = dk.dataset.dr; drOpen = true; renderResort(); return; }
  const rk = e.target.closest('[data-rs-menu]'); if (rk) { rsMenu = rk.dataset.rsMenu; rsOpen = true; renderResort(); return; }
  const day = () => DATA.resort.days.find(d => d.date === resortDay);
  const aa = e.target.closest('[data-add-act]');
  if (aa) { const a = day().activities[+aa.dataset.addAct]; addPick({ date: resortDay, start: a.start, end: a.end, title: a.name, where: a.where, kind: a.kind, note: '' }); return; }
  const ar = e.target.closest('[data-add-rest]');
  if (ar) { const [meal, i] = ar.dataset.addRest.split('|'); addRestaurant(resortDay, day().meals[meal][+i], meal); return; }
  const ac = e.target.closest('[data-add-custom]'); if (ac) { addCustom(ac.dataset.addCustom); return; }
  const un = e.target.closest('[data-unpick]'); if (un) { removePick(un.dataset.unpick); }
});
$('#lockForm').addEventListener('submit', async e => {
  e.preventDefault(); $('#lockErr').hidden = true;
  try { await open($('#pass').value.trim()); }
  catch (err) {
    $('#lockErr').textContent = err instanceof BadPass ? "That passphrase didn't work." : "Couldn't load the trip data — check your connection and try again.";
    $('#lockErr').hidden = false;
  }
});
document.addEventListener('visibilitychange', async () => {   // refresh when she comes back to the app
  const p = localStorage.getItem(PASS_KEY);
  if (document.visibilityState === 'visible' && p && DATA) { try { DATA = await load(p); render(); } catch (_) {} syncPicks(); }
});
(async () => {
  const p = localStorage.getItem(PASS_KEY);
  if (p) {
    try { await open(p); return; }
    catch (e) {
      if (e instanceof BadPass) localStorage.removeItem(PASS_KEY);   // passphrase changed; ask again
      else { $('#lockErr').textContent = "Couldn't load the trip data — check your connection and try again."; $('#lockErr').hidden = false; }
    }
  }
  $('#lock').hidden = false;
})();

document.addEventListener('toggle', e => { if (e.target && e.target.id === 'rsCard') rsOpen = e.target.open; if (e.target && e.target.id === 'drCard') drOpen = e.target.open; }, true);
