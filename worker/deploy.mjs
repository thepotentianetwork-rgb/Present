// Deploy Present via the Cloudflare REST API (no wrangler).
// Usage (from repo root):
//   CLOUDFLARE_API_TOKEN=... PRESENT_SCRIPT=present-app-preview PRESENT_D1_ID=<uuid> node worker/deploy.mjs
// Deploying the testers' worker (present-app) also needs PRESENT_CONFIRM_PROD=yes, so it can't happen by accident.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ACCOUNT = process.env.CF_ACCOUNT_ID || '75d481a4f6708914925e5d6f8b078e34';
const SCRIPT = process.env.PRESENT_SCRIPT;
const D1_ID = process.env.PRESENT_D1_ID;
const TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const MEMORY_MODEL = process.env.MEMORY_MODEL || 'claude-haiku-5-5';
if (!TOKEN) throw new Error('CLOUDFLARE_API_TOKEN not set');
if (!SCRIPT) throw new Error('PRESENT_SCRIPT not set (e.g. present-app-preview)');
if (!D1_ID) throw new Error('PRESENT_D1_ID not set (the D1 database uuid for this worker)');
if (SCRIPT === 'present-app' && process.env.PRESENT_CONFIRM_PROD !== 'yes') throw new Error('Refusing to deploy the testers\' worker without PRESENT_CONFIRM_PROD=yes');
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}`;

async function cf(path, init = {}, token = TOKEN) {
  const r = await fetch(path.startsWith('http') ? path : API + path, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers || {}) } });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.success === false) throw new Error(`${init.method || 'GET'} ${path} -> ${r.status} ${JSON.stringify(j.errors || j).slice(0, 500)}`);
  return j;
}

// Static assets: index.html, manifest, icons and images at the root, plus scenes/ (Sanctuary backgrounds).
const ASSET_RE = /\.(jpe?g|png|webp|svg|ico)$/i;
const files = readdirSync(root).filter(f => f === 'index.html' || f === 'manifest.webmanifest' || ASSET_RE.test(f));
if (existsSync(join(root, 'scenes'))) readdirSync(join(root, 'scenes')).filter(f => ASSET_RE.test(f)).forEach(f => files.push('scenes/' + f));
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
    const type = ext === 'webmanifest' ? 'application/manifest+json' : ext === 'html' ? 'text/html' : ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : ext === 'svg' ? 'image/svg+xml' : `image/${ext}`;
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
  bindings: [
    { type: 'assets', name: 'ASSETS' },
    { type: 'd1', name: 'DB', id: D1_ID },
    { type: 'plain_text', name: 'ANTHROPIC_MODEL', text: MODEL },
    { type: 'plain_text', name: 'MEMORY_MODEL', text: MEMORY_MODEL },
  ],
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
