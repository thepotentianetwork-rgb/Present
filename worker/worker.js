// Present — Cloudflare Worker: password gate + static app + AI proxy.
// app -> this worker (holds the key) -> Anthropic. No key ever reaches the page.
// Secrets: PRESENT_PASSWORD, SESSION_SECRET, ANTHROPIC_API_KEY (optional)
// Vars:    ANTHROPIC_MODEL (optional)   Bindings: ASSETS (static assets)

const COOKIE = 'present_session';
const SESSION_DAYS = 30;
const DEFAULT_MODEL = 'claude-sonnet-5-5';
const MAX_TOKENS = 1024;
const MAX_MESSAGES = 40;          // 20 turns, both roles
const MAX_MESSAGE_CHARS = 8000;
const MAX_SYSTEM_CHARS = 60000;
const MAX_BODY_BYTES = 400000;
const FAIL_LIMIT = 5;             // failures before backoff starts
const FAIL_WINDOW_S = 15 * 60;

const enc = new TextEncoder();

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });
}
function b64url(buf) {
  let s = ''; const b = new Uint8Array(buf);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}
// Constant-time compare: hash both sides so lengths match, then XOR every byte.
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb); let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0 && a.length === b.length;
}
async function makeSession(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_DAYS * 86400;
  const payload = `v1.${exp}.${b64url(crypto.getRandomValues(new Uint8Array(12)))}`;
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}
async function validSession(request, env) {
  if (!env.SESSION_SECRET) return false;
  const m = (request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') return false;
  const payload = parts.slice(0, 3).join('.');
  if (!(await safeEqual(parts[3], await hmac(env.SESSION_SECRET, payload)))) return false;
  return Number(parts[1]) > Date.now() / 1000;
}
function cookie(value, maxAge) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

// ---- login rate limit (Cache API, per IP) ----
// Limits: the Cache API is per data centre and entries can be evicted, so this is
// a speed bump against casual guessing, not a guarantee. A long random password
// is the real protection. For stronger limits use a KV/DO/WAF rate-limit rule.
function rlKey(ip) { return new Request(`https://rl.present.internal/login/${encodeURIComponent(ip)}`); }
async function getFails(ip) {
  const r = await caches.default.match(rlKey(ip));
  if (!r) return { n: 0, until: 0 };
  try { return await r.json(); } catch { return { n: 0, until: 0 }; }
}
async function putFails(ip, st) {
  await caches.default.put(rlKey(ip), new Response(JSON.stringify(st), { headers: { 'cache-control': `max-age=${FAIL_WINDOW_S}` } }));
}

function loginPage(msg = '', status = 200) {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Present</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#241A2E;font-family:"Nunito Sans",-apple-system,BlinkMacSystemFont,sans-serif;color:#2E2438;padding:20px}
.card{width:100%;max-width:380px;background:#FDF7F0;border-radius:28px;padding:40px 30px 32px;box-shadow:0 20px 60px rgba(0,0,0,.35);text-align:center}
h1{font-family:Georgia,"Times New Roman",serif;font-weight:400;color:#4A3560;font-size:34px;margin:0 0 8px}
p{color:#6B5484;margin:0 0 26px;line-height:1.5;font-size:15px}
input{width:100%;font:inherit;font-size:16px;padding:15px 18px;border-radius:16px;border:1.5px solid #E6D9CC;background:#fff;color:#2E2438;outline:none}
input:focus{border-color:#6B5484}
button{width:100%;margin-top:14px;font:inherit;font-weight:700;font-size:16px;padding:15px;border:0;border-radius:16px;background:#4A3560;color:#FDF7F0;cursor:pointer}
button:hover{background:#3B2A4D}.msg{color:#9A3D5C;font-size:14px;margin:14px 0 0;min-height:1em}
label{position:absolute;left:-9999px}</style></head><body>
<form class="card" method="post" action="/login">
<h1>Present</h1><p>Take a breath. Enter the password to come in.</p>
<label for="pw">Password</label>
<input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Come in</button>
<div class="msg" role="alert">${msg}</div></form></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY' } });
}

async function handleLogin(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const now = Date.now() / 1000;
  const st = await getFails(ip);
  if (st.until > now) return loginPage('Too many tries. Please wait a few minutes and try again.', 429);
  let pw = '';
  try { pw = String((await request.formData()).get('password') || ''); } catch {}
  if (env.PRESENT_PASSWORD && pw && await safeEqual(pw, env.PRESENT_PASSWORD)) {
    if (st.n) await caches.default.delete(rlKey(ip));
    return new Response(null, { status: 303, headers: { location: '/', 'set-cookie': cookie(await makeSession(env), SESSION_DAYS * 86400), 'cache-control': 'no-store' } });
  }
  const n = st.n + 1;
  // backoff: after FAIL_LIMIT failures, lock 30s, 60s, 120s ... up to 15 min
  const until = n >= FAIL_LIMIT ? now + Math.min(FAIL_WINDOW_S, 30 * 2 ** (n - FAIL_LIMIT)) : 0;
  await putFails(ip, { n, until });
  return loginPage("That password didn't work. Try again.", 401);
}

async function handleGenerate(request, env) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: 'AI not configured' }, 503);
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY_BYTES) return json({ error: 'Request too large' }, 413);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  const system = typeof body.system === 'string' ? body.system.slice(0, MAX_SYSTEM_CHARS) : '';
  let messages = Array.isArray(body.messages) ? body.messages : [];
  messages = messages
    .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
    .slice(-MAX_MESSAGES)
    .map(m => ({ role: m.role, content: m.content.slice(0, MAX_MESSAGE_CHARS) }));
  while (messages.length && messages[0].role !== 'user') messages.shift();
  if (!messages.length) return json({ error: 'No messages' }, 400);
  try {
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: env.ANTHROPIC_MODEL || DEFAULT_MODEL, max_tokens: MAX_TOKENS, system, messages }),
    });
    if (!res.ok) {
      console.log(JSON.stringify({ evt: 'anthropic_error', status: res.status })); // status only, never content
      return json({ error: 'AI unavailable' }, 502);
    }
    const data = await res.json();
    const text = (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
    if (!text) return json({ error: 'AI unavailable' }, 502);
    return json({ text });
  } catch {
    console.log(JSON.stringify({ evt: 'anthropic_fetch_failed' }));
    return json({ error: 'AI unavailable' }, 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (p === '/login') {
      if (request.method === 'POST') return handleLogin(request, env);
      if (await validSession(request, env)) return Response.redirect(new URL('/', url).toString(), 303);
      return loginPage();
    }
    if (p === '/logout') {
      return new Response(null, { status: 303, headers: { location: '/login', 'set-cookie': cookie('', 0), 'cache-control': 'no-store' } });
    }
    if (p === '/favicon.ico') return new Response(null, { status: 204, headers: { 'cache-control': 'public, max-age=86400' } });
    const authed = await validSession(request, env);
    if (p === '/api/generate') {
      if (!authed) return json({ error: 'Not signed in' }, 401);
      if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
      return handleGenerate(request, env);
    }
    if (!authed) {
      if (request.method === 'GET' && (p === '/' || p === '/index.html')) return loginPage();
      return new Response(null, { status: 303, headers: { location: '/login', 'cache-control': 'no-store' } });
    }
    const res = await env.ASSETS.fetch(request);
    const h = new Headers(res.headers);
    h.set('cache-control', 'private, no-store'); h.set('x-robots-tag', 'noindex');
    return new Response(res.body, { status: res.status, headers: h });
  },
};
