# CyberWatch

Live cybersecurity alerts on your phone: attacks, breaches and vulnerabilities from around the world, tagged
**HIGH / MEDIUM / LOW risk**, stored in a searchable database,.

## What it does
- Checks 10 security news feeds + CISA's "actively exploited" list + the NVD CVE feed **every 60 seconds**.
- Tags every item High / Medium / Low risk, and as **Attack**, **Vulnerability** or **News**.
- Sends a push notification to your phone the moment a new item is found, e.g.
  `🔴 HIGH RISK • ATTACK` — *Ransomware gang hits hospital network…*
- Database grouped by **date**, then sorted by **risk** within each day.
- Search bar: type any keyword (company, CVE, "ransomware", "Microsoft") and matching items appear.
- Tap an item for the full notes: title, risk, date of exposure, crime type, company, short notes,
  mitigation taken, whether it was delayed, effects and damages, source link.

## Run it on your computer
```bash
npm install
npm start          # open http://localhost:3000
```

## Get alerts on your phone, free
Phone notifications need HTTPS and a server that stays awake. Free setup = Render (server) + Turso (database) + UptimeRobot (keeps it awake).

**1. Database (Turso, free)** — sign up at turso.tech, create a database, then copy two things:
`TURSO_DATABASE_URL` (starts with `libsql://`) and `TURSO_AUTH_TOKEN` (create a token for the database).

**2. Server (Render, free Web Service)** — put this folder on GitHub, then on render.com choose
New → Web Service → your repo. Build command `npm install`, start command `npm start`, plan **Free**.
Add environment variables `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`. No disk needed.

**3. Keep it awake (UptimeRobot, free)** — add an HTTP monitor for `https://YOUR-APP.onrender.com/healthz`,
interval 5 minutes. Free servers sleep after ~15 idle minutes, and a sleeping server cannot send alerts.

**4. On your phone** open the Render address:
- **Android (Chrome):** menu → *Install app*, then tap **Enable alerts**.
- **iPhone (iOS 16.4+):** Safari → Share → *Add to Home Screen*, open it from the home screen, tap **Enable alerts**.

A test alert arrives immediately if it worked. News history, your phone's subscription and the push keys are stored
in Turso, so restarts and redeploys lose nothing.

## Settings (environment variables)
| Name | Default | Meaning |
|---|---|---|
| `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN` | – | Hosted database. If unset, a local file `./data/cyberwatch.db` is used |
| `POLL_SECONDS` | 60 | How often sources are checked |
| `FRESH_HOURS` | 6 | Only push items published within this many hours |
| `NVD_PUSH_MIN` | medium | NVD publishes hundreds of CVEs a day; only push this risk or higher (all are still stored). Set `low` to push every one |
| `NVD_API_KEY` | – | Free key from nvd.nist.gov for higher rate limits |
| `VAPID_PUBLIC`, `VAPID_PRIVATE` | auto | Optional; otherwise generated once and saved in the database |

## Honest limits
- "No delay" means within about a minute of the source publishing. Sources decide when news goes public.
- Risk, crime type, company, mitigation and effects are read from article text by keyword rules, so they are a good
  first triage, not a verdict. Anything a source doesn't state shows "Not reported". Open the source link to confirm.
- The classifier is unit-tested (`npm test`). The live feed connections could not be tested from the build
  environment (no internet), so check your first deploy's logs for any feed that errors.
