const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const state = { q: '', risk: '', kind: '' };
let freshId = null;

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.add('hidden'), 3500);
}

const fmtDay = (d) => new Date(d + 'T00:00:00Z').toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
const fmtTime = (iso) => new Date(iso).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const riskLabel = (r) => r.toUpperCase() + ' RISK';

async function loadStats() {
  try {
    const s = await (await fetch('/api/stats')).json();
    $('#stats').innerHTML = [
      ['', s.total, 'Total'], ['high', s.high, 'High'], ['medium', s.medium, 'Medium'], ['low', s.low, 'Low']
    ].map(([c, n, l]) => `<div class="stat ${c}"><b>${n}</b><span>${l}</span></div>`).join('');
  } catch {}
}

async function loadList() {
  const p = new URLSearchParams({ q: state.q, risk: state.risk, kind: state.kind });
  let items = [];
  try { items = await (await fetch('/api/items?' + p)).json(); }
  catch { $('#list').innerHTML = '<p class="empty">Cannot reach the server. Retrying…</p>'; return; }
  if (!items.length) {
    $('#list').innerHTML = `<p class="empty">${state.q ? 'No attacks or vulnerabilities match “' + esc(state.q) + '”.' : 'No items yet — the first feed check is running. Pull to refresh in a minute.'}</p>`;
    return;
  }
  let html = '', day = '';
  for (const it of items) {
    if (it.pub_day !== day) { day = it.pub_day; html += `<div class="day">${fmtDay(day)}</div>`; }
    html += `<article class="card ${it.risk} ${it.id === freshId ? 'fresh' : ''}" data-id="${it.id}">
      <div class="tags"><span class="tag ${it.risk}">${riskLabel(it.risk)}</span><span class="tag kind ${it.kind}">${esc(it.kind)}</span></div>
      <h3>${esc(it.title)}</h3>
      <div class="meta">${esc(it.company !== 'Not specified' ? it.company + ' · ' : '')}${esc(it.crime_type)} · ${esc(it.source)}</div>
    </article>`;
  }
  $('#list').innerHTML = html;
}

async function openDetail(id) {
  const it = await (await fetch('/api/items/' + id)).json();
  const f = (l, v) => v ? `<div class="field"><label>${l}</label><div>${esc(v)}</div></div>` : '';
  $('#detail').innerHTML = `
    <div class="tags"><span class="tag ${it.risk}">${riskLabel(it.risk)}</span><span class="tag kind ${it.kind}">${esc(it.kind)}</span></div>
    <h2>${esc(it.title)}</h2>
    ${f('Risk level', riskLabel(it.risk) + (it.cvss ? ` (CVSS ${it.cvss})` : ''))}
    ${f('Type', it.kind)}
    ${f('Date of exposure', fmtTime(it.published))}
    ${f('Crime type', it.crime_type)}
    ${f('Company / product involved', it.company)}
    ${it.cve ? f('CVE ID', it.cve) : ''}
    ${f('Short notes', it.summary)}
    ${f('Mitigation steps taken', it.mitigation)}
    ${f('Was the response delayed?', it.delayed)}
    ${f('Effects and damages', it.effects)}
    <div class="field"><label>Source</label><div>${esc(it.source)} · <a href="${esc(it.url)}" target="_blank" rel="noopener">Read full report</a></div></div>`;
  $('#modal').classList.remove('hidden');
  history.replaceState(null, '', '/');
}

$('#list').addEventListener('click', (e) => { const c = e.target.closest('.card'); if (c) openDetail(c.dataset.id); });
$('#close').onclick = () => $('#modal').classList.add('hidden');
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') $('#modal').classList.add('hidden'); });

let timer;
$('#q').addEventListener('input', (e) => { clearTimeout(timer); timer = setTimeout(() => { state.q = e.target.value.trim(); loadList(); }, 250); });
document.querySelector('.filters').addEventListener('click', (e) => {
  const b = e.target.closest('.chip'); if (!b) return;
  const isKind = b.classList.contains('k');
  document.querySelectorAll('.chip' + (isKind ? '.k' : ':not(.k)')).forEach((x) => x.classList.remove('on'));
  b.classList.add('on');
  state[isKind ? 'kind' : 'risk'] = (isKind ? b.dataset.kind : b.dataset.risk) || '';
  loadList();
});

// ---- live updates while the app is open ----
function connectLive() {
  const es = new EventSource('/api/stream');
  es.onopen = () => $('#live').classList.add('on');
  es.onerror = () => $('#live').classList.remove('on');
  es.addEventListener('item', (e) => { freshId = JSON.parse(e.data).id; loadList(); loadStats(); });
}

// ---- phone notifications (Web Push) ----
const b64 = (s) => { const p = '='.repeat((4 - (s.length % 4)) % 4); const r = atob((s + p).replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from([...r].map((c) => c.charCodeAt(0))); };

async function enableAlerts() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    return toast('Push is not supported here. On iPhone: Share → Add to Home Screen, then open the app from the home screen.');
  }
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') return toast('Notifications were blocked. Allow them in your browser/site settings.');
  const reg = await navigator.serviceWorker.ready;
  const { key } = await (await fetch('/api/vapid')).json();
  let sub = await reg.pushManager.getSubscription();
  if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64(key) });
  await fetch('/api/subscribe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sub) });
  markEnabled();
  toast('Alerts on. You will get each new threat with its risk level.');
  fetch('/api/test-push', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sub) });
}
function markEnabled() { const b = $('#notifyBtn'); b.textContent = '🔔 Alerts on'; b.classList.add('done'); }
$('#notifyBtn').onclick = enableAlerts;

async function init() {
  if ('serviceWorker' in navigator) {
    const reg = await navigator.serviceWorker.register('/sw.js');
    const sub = await reg.pushManager.getSubscription();
    if (sub && Notification.permission === 'granted') { markEnabled(); fetch('/api/subscribe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(sub) }); }
  }
  await Promise.all([loadList(), loadStats()]);
  connectLive();
  const id = new URLSearchParams(location.search).get('id');
  if (id) openDetail(id);
  setInterval(() => { loadList(); loadStats(); }, 60000);
}
init();
