// Run SQL against a Present D1 database via the REST API.
// Usage: CLOUDFLARE_API_TOKEN=... PRESENT_D1_ID=<uuid> node worker/d1.mjs worker/schema.sql
//        CLOUDFLARE_API_TOKEN=... PRESENT_D1_ID=<uuid> node worker/d1.mjs -e "SELECT COUNT(*) FROM users"
import { readFileSync } from 'node:fs';
const ACCOUNT = process.env.CF_ACCOUNT_ID || '75d481a4f6708914925e5d6f8b078e34';
const DB = process.env.PRESENT_D1_ID; if (!DB) throw new Error('PRESENT_D1_ID not set');
const a = process.argv.slice(2);
const sql = a[0] === '-e' ? a[1] : readFileSync(a[0], 'utf8');
const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/d1/database/${DB}/query`, {
  method: 'POST', headers: { authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`, 'content-type': 'application/json' },
  body: JSON.stringify({ sql }) });
const j = await r.json();
if (!j.success) { console.error(JSON.stringify(j.errors)); process.exit(1); }
for (const res of j.result) console.log(JSON.stringify(res.results));
