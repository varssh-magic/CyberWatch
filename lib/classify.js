// Turns a raw news/advisory item into structured, categorised fields.
// Everything here is keyword-based, so fields the source never mentions
// are reported as "Not reported" rather than guessed.

const VENDORS = [
  'Microsoft', 'Google', 'Apple', 'Amazon', 'AWS', 'Meta', 'Facebook', 'Instagram', 'WhatsApp', 'Cisco', 'Fortinet',
  'Palo Alto Networks', 'Ivanti', 'VMware', 'Broadcom', 'Oracle', 'SAP', 'Adobe', 'Samsung', 'Qualcomm', 'Intel', 'AMD',
  'Nvidia', 'Citrix', 'F5', 'SonicWall', 'Zyxel', 'Juniper', 'Atlassian', 'GitLab', 'GitHub', 'Jenkins', 'WordPress',
  'Cloudflare', 'Okta', 'Zoom', 'Slack', 'Salesforce', 'Dell', 'HP', 'Lenovo', 'IBM', 'Red Hat', 'Mozilla', 'Firefox',
  'Chrome', 'Android', 'Tesla', 'Boeing', 'Toyota', 'Uber', 'X Corp', 'TikTok', 'Telegram', 'Signal', 'PayPal',
  'Coinbase', 'Binance', 'Barclays', 'HSBC', 'Snowflake', 'MongoDB', 'Progress Software', 'SolarWinds', 'Veeam',
  'Trend Micro', 'Check Point', 'CrowdStrike', 'SentinelOne', 'Zscaler', 'Kaseya', 'ConnectWise', 'Apache', 'Linux',
  'Cloudflare', 'Shopify', 'Netflix', 'Spotify', 'Discord', 'Reddit', 'LinkedIn', 'Dropbox', 'Zimbra', 'Roundcube',
  'Synology', 'QNAP', 'TP-Link', 'D-Link', 'Netgear', 'Asus', 'Hikvision', 'Siemens', 'Schneider Electric', 'Honeywell',
  'NHS', 'FBI', 'CISA', 'Europol'
];

const clean = (s = '') =>
  String(s)
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#8217;/g, "'")
    .replace(/&#8230;|&hellip;/g, '...')
    .replace(/\s+/g, ' ')
    .trim();

const sentences = (t) => clean(t).split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/).filter((s) => s.length > 15);
const clip = (s, n) => (s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s);
const pick = (sents, re, max = 2) => sents.filter((s) => re.test(s)).slice(0, max);

const ATTACK_RE = /actively exploited|exploited in the wild|being exploited|ransomware|data breach|\bbreach(ed)?\b|hacked|cyber ?attack|ddos|botnet|campaign|stolen|compromised|phishing|malware|extortion|spyware|infostealer|threat actors?|hackers?|backdoor(ed)?|supply[- ]chain attack|espionage|leaked|wiper/i;
const VULN_RE = /cve-\d{4}-\d+|vulnerabilit|\bflaws?\b|\bbugs?\b|patch(es|ed)?\b|security update|advisory|misconfiguration|zero-day|0-day/i;

const CRIME_TYPES = [
  [/ransomware|extortion|encrypt(ed|s)? (files|systems)/i, 'Ransomware / Extortion'],
  [/ddos|denial[- ]of[- ]service/i, 'DDoS / Denial of Service'],
  [/supply[- ]chain/i, 'Supply-chain compromise'],
  [/zero-day|0-day/i, 'Zero-day exploitation'],
  [/phishing|smishing|vishing|social engineering/i, 'Phishing / Social engineering'],
  [/infostealer|credential|password|account takeover|session (token|cookie)/i, 'Credential theft'],
  [/data breach|\bbreach(ed)?\b|leaked|exposed (database|data|records)|stolen data|exfiltrat/i, 'Data breach / Data leak'],
  [/espionage|nation[- ]state|\bapt\d*\b|state-sponsored/i, 'Espionage / Nation-state (APT)'],
  [/botnet/i, 'Botnet'],
  [/wiper|destructive/i, 'Destructive malware'],
  [/malware|trojan|backdoor|spyware|rat\b|loader/i, 'Malware'],
  [/fraud|scam|bec\b|business email compromise|crypto(currency)? theft|heist/i, 'Fraud / Financial crime'],
  [/remote code execution|\brce\b|privilege escalation|authentication bypass|sql injection|xss|buffer overflow|out-of-bounds|use-after-free|path traversal|ssrf|csrf/i, 'Software vulnerability (exploitable flaw)']
];

function detectKind(text) {
  if (ATTACK_RE.test(text)) return 'Attack';
  if (VULN_RE.test(text)) return 'Vulnerability';
  return 'News';
}

function detectRisk(text, kind, cvss) {
  const critical = /zero-day|0-day|actively exploited|exploited in the wild|being exploited|ransomware|remote code execution|\brce\b|\bcritical\b|wormable|mass exploitation|supply[- ]chain|millions?\b|billions?\b|nation[- ]state|\bapt\d*\b|unauthenticated|hospital|critical infrastructure/i.test(text);
  const medium = /data breach|\bbreach|leak|phishing|malware|botnet|ddos|stolen|hijack|privilege escalation|authentication bypass|spyware|trojan|backdoor|campaign|injection|vulnerab|\bflaw|cve-/i.test(text);
  let risk;
  if (typeof cvss === 'number') {
    risk = cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
    if (critical && risk !== 'high' && kind === 'Attack') risk = 'high';
  } else {
    risk = critical ? 'high' : medium ? 'medium' : 'low';
  }
  if (kind === 'Attack' && risk === 'low') risk = 'medium';
  return risk;
}

function detectCompany(title, text) {
  let best = null;
  for (const v of VENDORS) {
    const re = new RegExp('\\b' + v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
    const mt = title.match(re);
    if (mt && (best === null || mt.index < best.idx)) best = { name: v, idx: mt.index, inTitle: true };
  }
  if (best) return best.name;
  let count = 0, name = null;
  for (const v of VENDORS) {
    const re = new RegExp('\\b' + v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'gi');
    const n = (text.match(re) || []).length;
    if (n > count) { count = n; name = v; }
  }
  return name || 'Not specified';
}

function analyze(raw) {
  const title = clean(raw.title);
  const text = clean(raw.text || '');
  const all = title + '. ' + text;
  const sents = sentences(text);

  const kind = raw.kind || detectKind(all);
  const cvss = typeof raw.cvss === 'number' ? raw.cvss : null;
  const risk = raw.risk || detectRisk(all, kind, cvss);

  let crime = raw.crimeType;
  if (!crime) {
    const hit = CRIME_TYPES.find(([re]) => re.test(all));
    crime = hit ? hit[1] : kind === 'News' ? 'General security news' : 'Not reported';
  }

  const cveMatch = all.match(/CVE-\d{4}-\d{4,7}/i);
  const company = raw.company || detectCompany(title, all);

  const mitSents = pick(sents, /patch|fixed|fixes|mitigat|updated?\b|workaround|advis|disabled|revoked|contained|remediat|rotate|isolated|taken offline|law enforcement|seiz|arrest|takedown|upgrade/i, 2);
  const mitigation = raw.mitigation || (mitSents.length ? mitSents.map((s) => clip(s, 240)).join(' ') : 'No mitigation details reported yet');

  const delaySent = pick(sents, /unpatched|no patch|not (yet )?patched|delayed|(weeks|months) (after|before|later)|took (weeks|months|days)|slow to|still (unpatched|vulnerable)|went unnoticed|undetected for/i, 1);
  let delayed;
  if (delaySent.length) delayed = 'Yes — ' + clip(delaySent[0], 200);
  else if (raw.delayed) delayed = raw.delayed;
  else if (mitSents.length) delayed = 'No delay reported';
  else delayed = 'Unknown / not reported';

  const effSents = pick(sents, /million|billion|\brecords\b|customers|users|stolen|exposed|leak|outage|disrupt|downtime|\$\s?\d|losses|encrypt|affected|compromised|shut down|victims/i, 2);
  const effects = raw.effects || (effSents.length ? effSents.map((s) => clip(s, 240)).join(' ') : 'No damage details reported yet');

  const notes = (sents.length ? sents : [title]).slice(0, 3).map((s) => '• ' + clip(s, 220));

  return {
    title,
    kind,
    risk,
    riskRank: risk === 'high' ? 3 : risk === 'medium' ? 2 : 1,
    crimeType: crime,
    company,
    cve: raw.cve || (cveMatch ? cveMatch[0].toUpperCase() : null),
    cvss,
    summary: notes.join('\n'),
    mitigation,
    delayed,
    effects
  };
}

module.exports = { analyze, clean };
