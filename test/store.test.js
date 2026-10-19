const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { createStore } = require('../lib/store');

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-'));
  const store = createStore({ url: 'file:' + path.join(dir, 't.db') });
  await store.init();

  const mk = (t, text, url, day, extra = {}) => ({ raw: { title: t, text, ...extra }, source: 'test', url, published: day });
  const first = await store.saveMany([
    mk('Ransomware hits Acme hospital', 'Attackers encrypted systems. The company restored backups. 2 million records were stolen.', 'u1', '2026-10-19T08:00:00Z'),
    mk('Cisco fixes flaw CVE-2026-1111', 'Cisco released a patch for a remote code execution vulnerability.', 'u2', '2026-10-19T09:00:00Z'),
    mk('Conference dates announced', 'The conference is in spring.', 'u3', '2026-10-18T09:00:00Z')
  ]);
  assert.strictEqual(first.length, 3);

  const again = await store.saveMany([mk('Ransomware hits Acme hospital', 'x', 'u1', '2026-10-19T08:00:00Z')]);
  assert.strictEqual(again.length, 0, 'duplicates are ignored');

  const all = await store.list({});
  assert.strictEqual(all.length, 3);
  assert.strictEqual(all[0].pub_day, '2026-10-19');
  assert.ok(all[0].risk_rank >= all[1].risk_rank, 'risk sorted within a day');
  assert.strictEqual((await store.list({ q: 'cisco' })).length, 1, 'keyword search');
  assert.strictEqual((await store.list({ q: 'ransomware', risk: 'high' })).length, 1);
  assert.strictEqual((await store.list({ kind: 'Attack' })).length, 1);

  await store.addSub({ endpoint: 'https://push.example/abc', keys: { p256dh: 'a', auth: 'b' } });
  assert.strictEqual((await store.allSubs()).length, 1);
  await store.delSub('https://push.example/abc');
  assert.strictEqual((await store.allSubs()).length, 0);

  await store.setMeta('vapid', '{"a":1}');
  assert.strictEqual(await store.getMeta('vapid'), '{"a":1}');

  const s = await store.stats();
  assert.strictEqual(s.total, 3);
  assert.strictEqual(typeof s.high, 'number');
  assert.ok(JSON.parse(JSON.stringify(all[0])).title, 'rows serialise to JSON');
  console.log('store tests passed:', JSON.stringify(s));
  fs.rmSync(dir, { recursive: true, force: true });
})().catch((e) => { console.error(e); process.exit(1); });
