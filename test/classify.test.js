const assert = require('assert');
const { analyze } = require('../lib/classify');

const cases = [
  ['Ransomware gang hits hospital network, millions of patient records stolen',
   'Attackers encrypted systems at the hospital. The company said it restored backups and notified law enforcement. Over 2 million records were stolen.',
   { kind: 'Attack', risk: 'high' }],
  ['Cisco patches critical flaw CVE-2026-1234 in routers',
   'Cisco released a patch for a remote code execution vulnerability. Customers are urged to update.',
   { kind: 'Vulnerability', risk: 'high' }],
  ['Minor information disclosure bug fixed in photo app',
   'A bug in the app could leak file names. The vendor fixed it in version 2.1.',
   { kind: 'Vulnerability', risk: 'medium' }],
  ['Security conference announces 2027 dates',
   'The conference will take place next spring in Lisbon.',
   { kind: 'News', risk: 'low' }]
];

for (const [title, text, want] of cases) {
  const a = analyze({ title, text });
  assert.strictEqual(a.kind, want.kind, `${title} → kind ${a.kind}`);
  assert.strictEqual(a.risk, want.risk, `${title} → risk ${a.risk}`);
  console.log('ok', a.risk.padEnd(6), a.kind.padEnd(13), '|', a.crimeType, '|', a.company);
}
const c = analyze({ title: 'Cisco bug', text: 'Cisco fixed it.', cvss: 5.1, kind: 'Vulnerability' });
assert.strictEqual(c.risk, 'medium');
console.log('all classifier tests passed');
