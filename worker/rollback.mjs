// Point a Present worker back at an earlier uploaded version (code, assets and bindings as they were).
// D1 data is not touched. Usage (from repo root):
//   CLOUDFLARE_API_TOKEN=... PRESENT_SCRIPT=present-app PRESENT_CONFIRM_PROD=yes node worker/rollback.mjs <version_id>
//   node worker/rollback.mjs --list      (shows recent versions)
const ACCOUNT = process.env.CF_ACCOUNT_ID || '75d481a4f6708914925e5d6f8b078e34';
const SCRIPT = process.env.PRESENT_SCRIPT, TOKEN = process.env.CLOUDFLARE_API_TOKEN;
if (!TOKEN || !SCRIPT) throw new Error('Set CLOUDFLARE_API_TOKEN and PRESENT_SCRIPT');
const API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/${SCRIPT}`;
const cf = async (p, init = {}) => { const r = await fetch(API + p, { ...init, headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' } });
  const j = await r.json(); if (!j.success) throw new Error(JSON.stringify(j.errors)); return j.result; };
const arg = process.argv[2];
if (!arg || arg === '--list') {
  const v = await cf('/versions'); v.items.slice(0, 10).forEach(i => console.log(i.number, i.id, i.metadata?.created_on)); process.exit(0);
}
if (SCRIPT === 'present-app' && process.env.PRESENT_CONFIRM_PROD !== 'yes') throw new Error('Refusing to change the testers\' worker without PRESENT_CONFIRM_PROD=yes');
const d = await cf('/deployments', { method: 'POST', body: JSON.stringify({ strategy: 'percentage', versions: [{ version_id: arg, percentage: 100 }], annotations: { 'workers/message': 'rollback via worker/rollback.mjs' } }) });
const now = await cf('/deployments'); console.log('now serving', JSON.stringify(now.deployments[0].versions));
