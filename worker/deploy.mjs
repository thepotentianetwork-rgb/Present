// Deploy present-app via the Cloudflare REST API (no wrangler).
// Usage: CLOUDFLARE_API_TOKEN=... node worker/deploy.mjs   (run from repo root)
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ACCOUNT = process.env.CF_ACCOUNT_ID || '75d481a4f6708914925e5d6f8b078e34';
const SCRIPT = 'present-app';
const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
if (!TOKEN) throw new Error('CLOUDFLARE_API_TOKEN not set');
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}`;

async function cf(path, init = {}, token = TOKEN) {
  const r = await fetch(path.startsWith('http') ? path : API + path, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) throw new Error(`${init.method || 'GET'} ${path} -> ${r.status} ${JSON.stringify(j.errors || j).slice(0, 500)}`);
  return j;
}

// Static assets: index.html + every image at repo root.
const files = readdirSync(root).filter(f => f === 'index.html' || /\.(jpe?g|png|webp|svg|ico)$/i.test(f));
const manifest = {}; const byHash = {};
for (const f of files) {
  const buf = readFileSync(join(root, f)); const b64 = buf.toString('base64');
  const hash = createHash('sha256').update(b64 + extname(f).slice(1)).digest('hex').slice(0, 32);
  manifest['/' + f] = { hash, size: buf.length }; byHash[hash] = { b64, f };
}
const sess = await cf(`/workers/scripts/${SCRIPT}/assets-upload-session`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ manifest }) });
let jwt = sess.result.jwt;
for (const bucket of sess.result.buckets || []) {
  const fd = new FormData();
  for (const h of bucket) {
    const ext = extname(byHash[h].f).slice(1).toLowerCase();
    const type = ext === 'html' ? 'text/html' : ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : `image/${ext}`;
    fd.append(h, new Blob([byHash[h].b64], { type }), h);
  }
  const up = await cf(`/workers/assets/upload?base64=true`, { method: 'POST', body: fd }, jwt);
  if (up.result && up.result.jwt) jwt = up.result.jwt;
}
console.log(`assets: ${files.length} files, ${(sess.result.buckets || []).flat().length} uploaded`);

const metadata = {
  main_module: 'worker.js',
  compatibility_date: '2026-08-04',
  assets: { jwt, config: { run_worker_first: true, html_handling: 'auto-trailing-slash', not_found_handling: 'none' } },
  bindings: [{ type: 'assets', name: 'ASSETS' }, { type: 'plain_text', name: 'ANTHROPIC_MODEL', text: MODEL }],
  keep_bindings: ['secret_text'],
  observability: { enabled: true },
};
const fd = new FormData();
fd.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
fd.append('worker.js', new Blob([readFileSync(join(here, 'worker.js'))], { type: 'application/javascript+module' }), 'worker.js');
await cf(`/workers/scripts/${SCRIPT}`, { method: 'PUT', body: fd });
await cf(`/workers/scripts/${SCRIPT}/subdomain`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: true, previews_enabled: false }) });
const sub = await cf(`/workers/subdomain`);
console.log(`deployed: https://${SCRIPT}.${sub.result.subdomain}.workers.dev`);
