// Usage: CLOUDFLARE_API_TOKEN=... PRESENT_SCRIPT=present-app-preview node worker/set-secret.mjs NAME < value_file
// Reads the value from stdin so it never appears in shell history or argv.
const [name] = process.argv.slice(2);
const ACCOUNT = process.env.CF_ACCOUNT_ID || '75d481a4f6708914925e5d6f8b078e34';
const SCRIPT = process.env.PRESENT_SCRIPT;
if (!SCRIPT) throw new Error('PRESENT_SCRIPT not set');
let text = ''; for await (const c of process.stdin) text += c; text = text.replace(/\r?\n$/, '');
if (!name || !text) throw new Error('usage: node set-secret.mjs NAME < file');
const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/workers/scripts/${SCRIPT}/secrets`, {
  method: 'PUT', headers: { authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`, 'content-type': 'application/json' },
  body: JSON.stringify({ name, text, type: 'secret_text' }) });
const j = await r.json(); console.log(SCRIPT, name, r.status, j.success ? 'ok' : JSON.stringify(j.errors));
