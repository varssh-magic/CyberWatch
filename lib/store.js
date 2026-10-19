// Storage layer. Works with a hosted Turso database (survives restarts on free hosting)
// or a local SQLite file for development.
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const { analyze } = require('./classify');

const sha = (s) => crypto.createHash('sha1').update(s).digest('hex').slice(0, 20);

const SCHEMA = `
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY, title TEXT, risk TEXT, risk_rank INTEGER, kind TEXT, crime_type TEXT,
  company TEXT, cve TEXT, cvss REAL, published TEXT, pub_day TEXT, summary TEXT, mitigation TEXT,
  delayed TEXT, effects TEXT, source TEXT, url TEXT, created TEXT);
CREATE INDEX IF NOT EXISTS idx_day_risk ON items(pub_day DESC, risk_rank DESC);
CREATE TABLE IF NOT EXISTS subs(endpoint TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
`;

const INSERT = `INSERT OR IGNORE INTO items
 (id,title,risk,risk_rank,kind,crime_type,company,cve,cvss,published,pub_day,summary,mitigation,delayed,effects,source,url,created)
 VALUES (:id,:title,:risk,:risk_rank,:kind,:crime_type,:company,:cve,:cvss,:published,:pub_day,:summary,:mitigation,:delayed,:effects,:source,:url,:created)`;

function createStore({ url, authToken }) {
  const db = createClient({ url, authToken: authToken || undefined });
  const rows = async (sql, args = []) => (await db.execute({ sql, args })).rows.map((r) => ({ ...r }));

  return {
    async init() { await db.executeMultiple(SCHEMA); },

    async getMeta(k) { return (await rows('SELECT v FROM meta WHERE k=?', [k]))[0]?.v; },
    async setMeta(k, v) { await db.execute({ sql: 'INSERT OR REPLACE INTO meta VALUES(?,?)', args: [k, String(v)] }); },

    // cands: [{ raw, source, url, published }]. Returns only the rows that were NEW.
    async saveMany(cands) {
      const prepared = cands.map((c) => {
        const a = analyze(c.raw);
        const d = c.published && !isNaN(new Date(c.published)) ? new Date(c.published) : new Date();
        const pub = d.toISOString();
        return {
          id: sha(c.url || a.title), title: a.title, risk: a.risk, risk_rank: a.riskRank, kind: a.kind,
          crime_type: a.crimeType, company: a.company, cve: a.cve, cvss: a.cvss, published: pub,
          pub_day: pub.slice(0, 10), summary: a.summary, mitigation: a.mitigation, delayed: a.delayed,
          effects: a.effects, source: c.source, url: c.url || '', created: new Date().toISOString()
        };
      });
      const uniq = [...new Map(prepared.map((r) => [r.id, r])).values()];
      if (!uniq.length) return [];
      const ids = uniq.map((r) => r.id);
      const have = new Set((await rows(`SELECT id FROM items WHERE id IN (${ids.map(() => '?').join(',')})`, ids)).map((r) => r.id));
      const fresh = uniq.filter((r) => !have.has(r.id));
      if (fresh.length) await db.batch(fresh.map((r) => ({ sql: INSERT, args: r })), 'write');
      return fresh;
    },

    async list({ q = '', risk = '', kind = '', limit = 300 }) {
      const where = [], args = [];
      for (const term of String(q).trim().split(/\s+/).filter(Boolean).slice(0, 6)) {
        const like = '%' + term.replace(/[%_]/g, '') + '%';
        where.push('(title LIKE ? OR summary LIKE ? OR company LIKE ? OR crime_type LIKE ? OR cve LIKE ? OR effects LIKE ? OR mitigation LIKE ? OR kind LIKE ? OR risk LIKE ?)');
        for (let i = 0; i < 9; i++) args.push(like);
      }
      if (['high', 'medium', 'low'].includes(risk)) { where.push('risk=?'); args.push(risk); }
      if (['Attack', 'Vulnerability', 'News'].includes(kind)) { where.push('kind=?'); args.push(kind); }
      const sql = `SELECT * FROM items ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                   ORDER BY pub_day DESC, risk_rank DESC, published DESC LIMIT ?`;
      return rows(sql, [...args, Math.min(Number(limit) || 300, 1000)]);
    },
    async get(id) { return (await rows('SELECT * FROM items WHERE id=?', [id]))[0]; },

    async stats() {
      const s = (await rows(`SELECT COUNT(*) total, COALESCE(SUM(risk='high'),0) high, COALESCE(SUM(risk='medium'),0) medium,
        COALESCE(SUM(risk='low'),0) low, COALESCE(SUM(kind='Attack'),0) attacks FROM items`))[0];
      s.subscribers = (await rows('SELECT COUNT(*) n FROM subs'))[0].n;
      s.lastPoll = (await this.getMeta('last_poll')) || null;
      return s;
    },

    async addSub(sub) { await db.execute({ sql: 'INSERT OR REPLACE INTO subs VALUES(?,?)', args: [sub.endpoint, JSON.stringify(sub)] }); },
    async delSub(endpoint) { await db.execute({ sql: 'DELETE FROM subs WHERE endpoint=?', args: [endpoint] }); },
    async allSubs() { return (await rows('SELECT data FROM subs')).map((r) => JSON.parse(r.data)); }
  };
}

module.exports = { createStore };
