const express = require('express');
const Parser = require('rss-parser');
const webpush = require('web-push');
const fs = require('fs');
const path = require('path');
const { createStore } = require('./lib/store');

const PORT = process.env.PORT || 3000;
const POLL_MS = Number(process.env.POLL_SECONDS || 60) * 1000; // how often sources are checked
const FRESH_HOURS = Number(process.env.FRESH_HOURS || 6); // only push items published this recently
const NVD_PUSH_MIN = process.env.NVD_PUSH_MIN || 'medium'; // CVE firehose: push only this risk or higher

// Hosted Turso database if configured (survives restarts), otherwise a local file for development.
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
let dbUrl = process.env.TURSO_DATABASE_URL;
if (!dbUrl) { fs.mkdirSync(DATA_DIR, { recursive: true }); dbUrl = 'file:' + path.join(DATA_DIR, 'cyberwatch.db'); }
const store = createStore({ url: dbUrl, authToken: process.env.TURSO_AUTH_TOKEN });

// ---------- sources ----------
const FEEDS = [
  ['The Hacker News', 'https://feeds.feedburner.com/TheHackersNews'],
  ['BleepingComputer', 'https://www.bleepingcomputer.com/feed/'],
  ['Krebs on Security', 'https://krebsonsecurity.com/feed/'],
  ['SecurityWeek', 'https://feeds.feedburner.com/securityweek'],
  ['Dark Reading', 'https://www.darkreading.com/rss.xml'],
  ['CISA Advisories', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'],
  ['The Record', 'https://therecord.media/feed'],
  ['Help Net Security', 'https://www.helpnetsecurity.com/feed/'],
  ['Google Project Zero', 'https://googleprojectzero.blogspot.com/feeds/posts/default'],
  ['Microsoft Security Response Center', 'https://msrc.microsoft.com/blog/feed']
];
const parser = new Parser({ timeout: 15000, headers: { 'User-Agent': 'CyberWatch/1.0' } });

async function pullRss([name, url]) {
  const feed = await parser.parseURL(url);
  return feed.items.slice(0, 30).map((it) => ({
    raw: { title: it.title, text: it['content:encoded'] || it.content || it.contentSnippet || it.summary || '' },
    source: name, url: it.link || it.guid, published: it.isoDate || it.pubDate
  }));
}

async function pullKEV() {
  const r = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { signal: AbortSignal.timeout(20000) });
  const j = await r.json();
  return (j.vulnerabilities || []).slice(-25).map((v) => {
    const ransom = v.knownRansomwareCampaignUse === 'Known';
    return {
      raw: {
        title: `${v.vendorProject} ${v.product}: actively exploited — ${v.vulnerabilityName} (${v.cveID})`,
        text: `${v.shortDescription} CISA added this flaw to its Known Exploited Vulnerabilities catalog, meaning attackers are exploiting it in the wild.${ransom ? ' It is known to be used in ransomware campaigns.' : ''}`,
        kind: 'Attack', risk: 'high', company: v.vendorProject, cve: v.cveID,
        crimeType: ransom ? 'Ransomware / Exploited vulnerability' : 'Exploited vulnerability (in the wild)',
        mitigation: `${v.requiredAction} (CISA remediation due date: ${v.dueDate})`,
        effects: 'Active exploitation confirmed by CISA; impact depends on the affected product.'
      },
      source: 'CISA KEV', url: 'https://nvd.nist.gov/vuln/detail/' + v.cveID + '#kev', published: v.dateAdded + 'T00:00:00Z'
    };
  });
}

async function pullNVD() {
  const end = new Date();
  const start = new Date((await store.getMeta('nvd_last')) || end.getTime() - 2 * 3600 * 1000);
  const f = (d) => d.toISOString().replace('Z', '').slice(0, 23) + 'Z';
  const u = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${f(start)}&pubEndDate=${f(end)}`;
  const r = await fetch(u, { signal: AbortSignal.timeout(25000), headers: process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {} });
  if (!r.ok) throw new Error('NVD HTTP ' + r.status);
  const j = await r.json();
  await store.setMeta('nvd_last', end.toISOString());
  return (j.vulnerabilities || []).map((w) => {
    const c = w.cve;
    const desc = (c.descriptions || []).find((d) => d.lang === 'en')?.value || '';
    const m = c.metrics || {};
    const cv = (m.cvssMetricV31 || m.cvssMetricV40 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0]?.cvssData;
    const cpe = JSON.stringify(c.configurations || '').match(/cpe:2\.3:[aoh]:([^:]+):/);
    return {
      raw: {
        title: `${c.id}: ${desc.split(/(?<=\.)\s/)[0].slice(0, 110)}`, text: desc, kind: 'Vulnerability',
        cvss: cv?.baseScore, cve: c.id, company: cpe ? cpe[1].replace(/_/g, ' ') : undefined,
        mitigation: 'Check the vendor advisory and apply the patch when available.'
      },
      source: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/' + c.id, published: c.published
    };
  });
}

// ---------- push + live stream ----------
const sseClients = new Set();
const RANK = { low: 1, medium: 2, high: 3 };
const ICON = { high: '🔴', medium: '🟠', low: '🟢' };

function notificationFor(row) {
  return {
    title: `${ICON[row.risk]} ${row.risk.toUpperCase()} RISK${row.kind === 'Attack' ? ' • ATTACK' : row.kind === 'Vulnerability' ? ' • VULNERABILITY' : ''}`,
    body: row.title,
    url: '/?id=' + row.id,
    tag: row.id
  };
}

async function pushToAll(row) {
  const payload = JSON.stringify(notificationFor(row));
  const subs = await store.allSubs();
  await Promise.all(subs.map(async (s) => {
    try { await webpush.sendNotification(s, payload, { urgency: 'high', TTL: 3600 }); }
    catch (e) { if (e.statusCode === 404 || e.statusCode === 410) await store.delSub(s.endpoint).catch(() => {}); }
  }));
}

async function handleNew(rows, seeded, source) {
  for (const row of rows) {
    for (const c of sseClients) c.write(`event: item\ndata: ${JSON.stringify({ id: row.id })}\n\n`);
    if (!seeded) continue; // first run: fill the database silently, don't spam old news
    if (Date.now() - new Date(row.published) > FRESH_HOURS * 3600e3) continue;
    if (source === 'NVD' && RANK[row.risk] < RANK[NVD_PUSH_MIN]) continue;
    await pushToAll(row);
  }
}

let running = false;
async function poll() {
  if (running) return;
  running = true;
  try {
    const seeded = (await store.getMeta('seeded')) === '1';
    const jobs = [...FEEDS.map((f) => [f[0], () => pullRss(f)]), ['CISA KEV', pullKEV], ['NVD', pullNVD]];
    let okCount = 0;
    await Promise.all(jobs.map(async ([name, fn]) => {
      try { await handleNew(await store.saveMany(await fn()), seeded, name); okCount++; }
      catch (e) { console.warn(`[${name}] ${String(e.message).slice(0, 120)}`); }
    }));
    if (!seeded && okCount > 0) await store.setMeta('seeded', '1'); // first successful fill is silent
    await store.setMeta('last_poll', new Date().toISOString());
  } catch (e) { console.warn('[poll]', String(e.message).slice(0, 160)); }
  running = false;
}

// ---------- web server ----------
async function main() {
  await store.init();

  // Phone-push keys: from env if given, otherwise generated once and kept in the database.
  let VAPID = { pub: process.env.VAPID_PUBLIC, priv: process.env.VAPID_PRIVATE };
  if (!VAPID.pub || !VAPID.priv) {
    const saved = await store.getMeta('vapid');
    if (saved) VAPID = JSON.parse(saved);
    else {
      const k = webpush.generateVAPIDKeys();
      VAPID = { pub: k.publicKey, priv: k.privateKey };
      await store.setMeta('vapid', JSON.stringify(VAPID));
    }
  }
  webpush.setVapidDetails('mailto:' + (process.env.VAPID_EMAIL || 'alerts@example.com'), VAPID.pub, VAPID.priv);

  const app = express();
  app.use(express.json({ limit: '50kb' }));
  app.use(express.static(path.join(__dirname, 'public')));
  const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.warn(e.message); res.status(500).json({ error: 'server error' }); });

  app.get('/healthz', (_, res) => res.send('ok'));
  app.get('/api/vapid', (_, res) => res.json({ key: VAPID.pub }));
  app.post('/api/subscribe', wrap(async (req, res) => {
    if (!req.body?.endpoint) return res.status(400).json({ error: 'bad subscription' });
    await store.addSub(req.body); res.json({ ok: true });
  }));
  app.post('/api/unsubscribe', wrap(async (req, res) => {
    if (req.body?.endpoint) await store.delSub(req.body.endpoint);
    res.json({ ok: true });
  }));
  app.post('/api/test-push', async (req, res) => {
    try {
      await webpush.sendNotification(req.body, JSON.stringify({ title: '🔴 HIGH RISK • ATTACK', body: 'Test alert: notifications are working', url: '/', tag: 'test' }));
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });
  app.get('/api/items', wrap(async (req, res) => res.json(await store.list(req.query))));
  app.get('/api/items/:id', wrap(async (req, res) => {
    const r = await store.get(req.params.id);
    r ? res.json(r) : res.status(404).json({ error: 'not found' });
  }));
  app.get('/api/stats', wrap(async (_, res) => res.json(await store.stats())));
  app.get('/api/stream', (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.flushHeaders();
    res.write('retry: 5000\n\n');
    sseClients.add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 25000);
    req.on('close', () => { clearInterval(ping); sseClients.delete(res); });
  });

  app.listen(PORT, () => {
    console.log(`CyberWatch running on port ${PORT} (database: ${process.env.TURSO_DATABASE_URL ? 'Turso' : 'local file'}, polling every ${POLL_MS / 1000}s)`);
    poll();
    setInterval(poll, POLL_MS);
  });
}
main().catch((e) => { console.error('Startup failed:', e.message); process.exit(1); });
