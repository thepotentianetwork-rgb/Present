// Present — Cloudflare Worker: per-user accounts (D1) + static app + AI proxy.
// app -> this worker (holds the key) -> Anthropic. No key ever reaches the page.
//
// Secrets:  PRESENT_PASSWORD  (now the INVITE CODE for creating an account)
//           ANTHROPIC_API_KEY (optional)
// Vars:     ANTHROPIC_MODEL (chat), MEMORY_MODEL (small model for memory extraction)
// Bindings: ASSETS (static assets), DB (D1, schema in worker/schema.sql)
//
// Privacy rules this file keeps:
//  * every read/write of personal data is scoped by the signed-in user's id (WHERE user_id = ?)
//  * delete means DELETE — no soft-delete flags, no archive tables
//  * message content is never logged

const COOKIE = 'present_sid';
const LEGACY_COOKIE = 'present_session';      // the old shared-password cookie; cleared, never trusted
const SESSION_DAYS = 30;
const DEFAULT_MODEL = 'claude-sonnet-5-5';
const DEFAULT_MEMORY_MODEL = 'claude-haiku-5-5';
const MAX_TOKENS = 1024;
const MAX_MESSAGES = 40;
const MAX_MESSAGE_CHARS = 8000;
const MAX_SYSTEM_CHARS = 60000;
const MAX_BODY_BYTES = 400000;
const FAIL_LIMIT = 5;
const FAIL_WINDOW_S = 15 * 60;
const PBKDF2_ITER = 100000;                   // the Workers runtime caps PBKDF2 at 100k iterations
const MAX_MEMORIES = 200;
const MAX_PREF_BYTES = 64000;
const MAX_PREF_KEYS = 80;
const PREF_KEY_RE = /^present[A-Za-z0-9_]{1,48}$/;

const enc = new TextEncoder();

// ---------- small helpers ----------
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
function fromB64url(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const rid = (n = 16) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const now = () => Date.now();
async function sha256(s) { return b64url(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
// Constant-time compare: hash both sides so lengths match, then XOR every byte.
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb); let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0 && a.length === b.length;
}
async function pbkdf2(password, saltBytes, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: iter }, key, 256);
  return b64url(bits);
}
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function readCookie(request, name) {
  const m = (request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return m ? m[1] : null;
}
function cookie(value, maxAge) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
const clearLegacy = `${LEGACY_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

// ---------- sessions ----------
async function createSession(env, userId) {
  const token = rid(32);
  const t = now();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(token), userId, t, t + SESSION_DAYS * 864e5).run();
  // opportunistic cleanup of this user's expired sessions
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND expires_at < ?').bind(userId, t).run();
  return token;
}
async function currentUser(request, env) {
  if (!env.DB) return null;
  const token = readCookie(request, COOKIE);
  if (!token || token.length > 100) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.email, u.name, u.memory_enabled FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?'
  ).bind(await sha256(token), now()).first();
  return row || null;
}

// ---------- rate limit (Cache API, per IP and action) ----------
function rlKey(ip, what) { return new Request(`https://rl.present.internal/${what}/${encodeURIComponent(ip)}`); }
async function getFails(ip, what) {
  const r = await caches.default.match(rlKey(ip, what));
  if (!r) return { n: 0, until: 0 };
  try { return await r.json(); } catch { return { n: 0, until: 0 }; }
}
async function putFails(ip, what, st) {
  await caches.default.put(rlKey(ip, what), new Response(JSON.stringify(st), { headers: { 'cache-control': `max-age=${FAIL_WINDOW_S}` } }));
}
async function noteFail(ip, what, st) {
  const n = st.n + 1, t = now() / 1000;
  const until = n >= FAIL_LIMIT ? t + Math.min(FAIL_WINDOW_S, 30 * 2 ** (n - FAIL_LIMIT)) : 0;
  await putFails(ip, what, { n, until });
}

// ---------- the sign-in / create-account page ----------
function authPage({ mode = 'signin', msg = '', status = 200, email = '', name = '' } = {}) {
  const signup = mode === 'signup';
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="robots" content="noindex">
<meta name="theme-color" content="#F6EDE4"><title>Present</title><style>
*{box-sizing:border-box}html,body{margin:0}
body{min-height:100vh;min-height:100dvh;display:flex;align-items:center;justify-content:center;padding:24px 18px calc(24px + env(safe-area-inset-bottom));
background:radial-gradient(120% 80% at 20% 0%,#FBE4EC 0%,rgba(251,228,236,0) 60%),radial-gradient(100% 70% at 100% 100%,#EAE1F4 0%,rgba(234,225,244,0) 60%),#F6EDE4;
font-family:"Nunito Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#2E2438}
.card{width:100%;max-width:400px;background:#FDF7F0;border-radius:28px;padding:34px 28px 26px;box-shadow:0 18px 50px rgba(74,53,96,.14)}
h1{font-family:"Cormorant Garamond",Georgia,serif;font-weight:400;color:#4A3560;font-size:38px;margin:0;text-align:center}
.sub{color:#6B5484;margin:6px 0 22px;line-height:1.5;font-size:15px;text-align:center}
.tabs{display:grid;grid-template-columns:1fr 1fr;background:#F0E7DD;border-radius:999px;padding:4px;margin:0 0 20px}
.tabs a{text-align:center;padding:10px 6px;border-radius:999px;color:#6B5484;font-weight:700;font-size:14px;text-decoration:none}
.tabs a.on{background:#fff;color:#4A3560;box-shadow:0 2px 8px rgba(74,53,96,.10)}
label{display:block;font-size:13px;font-weight:700;color:#4A3560;margin:12px 4px 6px}
small.hint{display:block;font-weight:400;color:#6D6079;font-size:12.5px;margin-top:2px}
input{width:100%;font:inherit;font-size:16px;padding:14px 16px;border-radius:16px;border:1.5px solid #E6D9CC;background:#fff;color:#2E2438;outline:none}
input:focus{border-color:#A78BC4;box-shadow:0 0 0 3px rgba(167,139,196,.25)}
button{width:100%;margin-top:20px;font:inherit;font-weight:700;font-size:16px;padding:15px;border:0;border-radius:999px;background:#4A3560;color:#FDF7F0;cursor:pointer}
button:hover{background:#3B2A4D}button:focus-visible,a:focus-visible{outline:3px solid #A78BC4;outline-offset:2px}
.msg{color:#9A3D5C;font-size:14px;margin:14px 0 0;min-height:1em;text-align:center;line-height:1.45}
.fine{color:#6D6079;font-size:12.5px;line-height:1.6;margin:18px 4px 0;text-align:center}
</style></head><body>
<form class="card" method="post" action="${signup ? '/signup' : '/login'}" autocomplete="on">
<h1>Present</h1><p class="sub">${signup ? 'Make a private space that\u2019s just yours.' : 'Take a breath. Sign in when you\u2019re ready.'}</p>
<nav class="tabs" aria-label="Sign in or create an account"><a href="/login" class="${signup ? '' : 'on'}" ${signup ? '' : 'aria-current="page"'}>Sign in</a><a href="/signup" class="${signup ? 'on' : ''}" ${signup ? 'aria-current="page"' : ''}>Create account</a></nav>
${signup ? `<label for="name">Your name<small class="hint">However you'd like Present to know you</small></label>
<input id="name" name="name" autocomplete="given-name" maxlength="60" required value="${esc(name)}">` : ''}
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="${signup ? 'email' : 'username'}" maxlength="200" required value="${esc(email)}" ${signup ? '' : 'autofocus'}>
<label for="pw">Password${signup ? '<small class="hint">At least 8 characters</small>' : ''}</label>
<input id="pw" name="password" type="password" autocomplete="${signup ? 'new-password' : 'current-password'}" minlength="${signup ? 8 : 1}" maxlength="200" required>
${signup ? `<label for="invite">Invite code<small class="hint">The Present password you were given for testing</small></label>
<input id="invite" name="invite" type="password" autocomplete="off" maxlength="200" required>` : ''}
<button type="submit">${signup ? 'Create my account' : 'Come in'}</button>
<div class="msg" role="alert">${esc(msg)}</div>
<p class="fine">${signup ? 'Your conversations, memories and settings are private to your account.' : 'New here? Choose \u201cCreate account\u201d above.'}</p>
</form></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin' } });
}
const okEmail = e => /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e);

async function handleLogin(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const st = await getFails(ip, 'login');
  if (st.until > now() / 1000) return authPage({ msg: 'Too many tries. Please wait a few minutes and try again.', status: 429 });
  let f; try { f = await request.formData(); } catch { return authPage({ status: 400 }); }
  const email = String(f.get('email') || '').trim().toLowerCase().slice(0, 200);
  const pw = String(f.get('password') || '').slice(0, 200);
  const u = email ? await env.DB.prepare('SELECT id, pw_hash, pw_salt, pw_iter FROM users WHERE email = ?').bind(email).first() : null;
  // Always run one PBKDF2 so a missing account takes as long as a wrong password.
  const calc = await pbkdf2(pw || 'x', u ? fromB64url(u.pw_salt) : enc.encode('present-dummy-salt'), u ? u.pw_iter : PBKDF2_ITER);
  if (u && pw && await safeEqual(calc, u.pw_hash)) {
    if (st.n) await caches.default.delete(rlKey(ip, 'login'));
    const token = await createSession(env, u.id);
    const h = new Headers({ location: '/', 'cache-control': 'no-store' });
    h.append('set-cookie', cookie(token, SESSION_DAYS * 86400)); h.append('set-cookie', clearLegacy);
    return new Response(null, { status: 303, headers: h });
  }
  await noteFail(ip, 'login', st);
  return authPage({ msg: "That email and password don't match. Try again.", status: 401, email });
}

async function handleSignup(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const st = await getFails(ip, 'signup');
  if (st.until > now() / 1000) return authPage({ mode: 'signup', msg: 'Too many tries. Please wait a few minutes and try again.', status: 429 });
  let f; try { f = await request.formData(); } catch { return authPage({ mode: 'signup', status: 400 }); }
  const name = String(f.get('name') || '').replace(/\s+/g, ' ').trim().slice(0, 60);
  const email = String(f.get('email') || '').trim().toLowerCase().slice(0, 200);
  const pw = String(f.get('password') || '').slice(0, 200);
  const invite = String(f.get('invite') || '');
  const back = (msg, status = 400) => authPage({ mode: 'signup', msg, status, email, name });
  if (!env.PRESENT_PASSWORD || !invite || !(await safeEqual(invite, env.PRESENT_PASSWORD))) {
    await noteFail(ip, 'signup', st);
    return back("That invite code didn't work. It's the Present password you were given.", 401);
  }
  if (!name) return back('Please add a name.');
  if (!okEmail(email)) return back('Please check the email address.');
  if (pw.length < 8) return back('Please use a password of at least 8 characters.');
  const exists = await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first();
  if (exists) return back('There is already an account with that email. Try signing in instead.', 409);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const id = 'u_' + rid(12);
  await env.DB.prepare('INSERT INTO users (id, email, name, pw_hash, pw_salt, pw_iter, memory_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)')
    .bind(id, email, name, await pbkdf2(pw, salt, PBKDF2_ITER), b64url(salt), PBKDF2_ITER, now()).run();
  if (st.n) await caches.default.delete(rlKey(ip, 'signup'));
  const token = await createSession(env, id);
  const h = new Headers({ location: '/', 'cache-control': 'no-store' });
  h.append('set-cookie', cookie(token, SESSION_DAYS * 86400)); h.append('set-cookie', clearLegacy);
  return new Response(null, { status: 303, headers: h });
}

async function handleLogout(request, env) {
  const token = readCookie(request, COOKIE);
  if (token && env.DB) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
  const h = new Headers({ location: '/login', 'cache-control': 'no-store' });
  h.append('set-cookie', cookie('', 0)); h.append('set-cookie', clearLegacy);
  return new Response(null, { status: 303, headers: h });
}

// ---------- boot data injected into index.html ----------
async function bootData(env, user) {
  const { results } = await env.DB.prepare('SELECT key, value FROM prefs WHERE user_id = ?').bind(user.id).all();
  const prefs = {}; (results || []).forEach(r => { prefs[r.key] = r.value; });
  return { user: { id: user.id, name: user.name, email: user.email }, memoryOn: !!user.memory_enabled, prefs };
}
async function serveApp(request, env, user) {
  // '/' rather than '/index.html': with auto-trailing-slash html handling the latter is a redirect.
  const res = await env.ASSETS.fetch(new Request(new URL('/', request.url), { method: 'GET' }));
  if (!res.ok) return new Response('Present could not load.', { status: 502, headers: { 'cache-control': 'no-store' } });
  let html = await res.text();
  const data = JSON.stringify(await bootData(env, user)).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  html = html.replace('/*__PRESENT_BOOT__*/null', data);
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'private, no-store', 'x-robots-tag': 'noindex', 'x-frame-options': 'DENY', 'referrer-policy': 'same-origin' } });
}

// ---------- AI ----------
async function anthropic(env, { model, system, messages, max_tokens }) {
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model, max_tokens, system, messages }),
  });
  if (!res.ok) { console.log(JSON.stringify({ evt: 'anthropic_error', status: res.status, model })); throw new Error('upstream'); }
  const data = await res.json();
  return (data.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n').trim();
}

async function memoryBlock(env, user, useMemory) {
  if (!useMemory) {
    return `\n\n==================================================\nMEMORY\n==================================================\nThis chat has no saved memories available${user.memory_enabled ? ' (it is a temporary chat)' : ' (the person turned memory off)'}. Do not claim to remember anything from other conversations.`;
  }
  const { results } = await env.DB.prepare('SELECT text FROM memories WHERE user_id = ? ORDER BY created_at DESC LIMIT 40').bind(user.id).all();
  const rows = (results || []).map(r => '- ' + String(r.text).slice(0, 300));
  if (!rows.length) return `\n\n==================================================\nMEMORY\n==================================================\nNothing is saved in this person's memory yet. Do not claim to remember anything from other conversations.`;
  return `\n\n==================================================\nSAVED MEMORIES — things this person shared before and are saved in their own account\n==================================================\n${rows.join('\n')}\n\nUse these only when they're relevant, naturally and lightly — the way a friend who remembers would. Don't list them, don't announce "I remember", and never add details that aren't written here or in this conversation. If they ask what you remember, tell them plainly and mention they can view or delete memories under Settings → What Present knows.`;
}

async function handleGenerate(request, env, user) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: 'AI not configured' }, 503);
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY_BYTES) return json({ error: 'Request too large' }, 413);
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  let system = typeof body.system === 'string' ? body.system.slice(0, MAX_SYSTEM_CHARS) : '';
  let messages = Array.isArray(body.messages) ? body.messages : [];
  messages = messages
    .filter(m => m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
    .slice(-MAX_MESSAGES)
    .map(m => ({ role: m.role, content: m.content.slice(0, MAX_MESSAGE_CHARS) }));
  while (messages.length && messages[0].role !== 'user') messages.shift();
  if (!messages.length) return json({ error: 'No messages' }, 400);
  // Memory is added here, on the server, from this user's rows only. A temporary chat never gets it.
  const temporary = body.temporary === true;
  system += await memoryBlock(env, user, !temporary && !!user.memory_enabled);
  try {
    const text = await anthropic(env, { model: env.ANTHROPIC_MODEL || DEFAULT_MODEL, system, messages, max_tokens: MAX_TOKENS });
    if (!text) return json({ error: 'AI unavailable' }, 502);
    return json({ text });
  } catch {
    return json({ error: 'AI unavailable' }, 502);
  }
}

const EXTRACT_SYSTEM = `You decide what a gentle mental-health companion app should remember long-term about one person. Reply with JSON only: {"memories":[{"text":"...","category":"..."}]}.

Save something ONLY if the person clearly said it about themselves in their latest message and it would genuinely help future conversations:
- how they like to be supported, or what helps / doesn't help them ("support")
- goals or things they're working on ("goal")
- lasting preferences ("preference")
- important ongoing life context they chose to share, e.g. a new job, a pet's name, a person in their life by name and relationship ("about")

Never save: passing moods or today's one-off events; anything about self-harm, suicide, crisis or danger; diagnoses, medications or other health details; sexual details; private details about other people beyond a name and relationship; guesses, interpretations or anything not stated outright. Never invent.
Write each memory as one short second-person sentence (max 140 characters), e.g. "You prefer to vent first before any advice." Do not repeat anything already saved. At most 2. If nothing qualifies, return {"memories":[]}.`;

async function handleExtract(request, env, user) {
  if (!user.memory_enabled) return json({ saved: [], reason: 'memory_off' });
  if (!env.ANTHROPIC_API_KEY) return json({ saved: [], reason: 'ai_off' });
  let body; try { body = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  let cid = body.conversation_id ? String(body.conversation_id) : null;
  let latest, prev;
  if (cid) {
    const conv = await env.DB.prepare('SELECT id, last_extracted_id FROM conversations WHERE id = ? AND user_id = ?').bind(cid, user.id).first();
    if (!conv) return json({ error: 'Not found' }, 404);
    latest = await env.DB.prepare("SELECT id, content FROM messages WHERE conversation_id = ? AND user_id = ? AND role = 'user' ORDER BY id DESC LIMIT 1").bind(cid, user.id).first();
    if (!latest || latest.id <= conv.last_extracted_id) return json({ saved: [] });
    await env.DB.prepare('UPDATE conversations SET last_extracted_id = ? WHERE id = ? AND user_id = ?').bind(latest.id, cid, user.id).run();
    prev = await env.DB.prepare("SELECT content FROM messages WHERE conversation_id = ? AND user_id = ? AND role = 'assistant' AND id < ? ORDER BY id DESC LIMIT 1").bind(cid, user.id, latest.id).first();
  } else {
    // Conversation saving is off: the client sends just the latest message (and the reply before it, as context).
    // Neither is stored; only a memory the model picks out is saved, because memory is on.
    const l = typeof body.latest === 'string' ? body.latest.trim() : '';
    if (!l) return json({ error: 'Bad request' }, 400);
    latest = { content: l.slice(0, MAX_MESSAGE_CHARS) };
    prev = typeof body.previous === 'string' && body.previous.trim() ? { content: body.previous.slice(0, 2000) } : null;
  }
  const { results } = await env.DB.prepare('SELECT text FROM memories WHERE user_id = ? ORDER BY created_at DESC LIMIT 60').bind(user.id).all();
  const existing = (results || []).map(r => r.text);
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM memories WHERE user_id = ?').bind(user.id).first();
  if ((count && count.n) >= MAX_MEMORIES) return json({ saved: [], reason: 'full' });
  const prompt = `Already saved:\n${existing.length ? existing.map(t => '- ' + t).join('\n') : '(nothing yet)'}\n\n` +
    (prev ? `Present's previous message (context only, never a source of memories):\n"""${String(prev.content).slice(0, 1200)}"""\n\n` : '') +
    `The person's latest message:\n"""${String(latest.content).slice(0, 3000)}"""`;
  let out = [];
  try {
    const text = await anthropic(env, { model: env.MEMORY_MODEL || DEFAULT_MEMORY_MODEL, system: EXTRACT_SYSTEM, messages: [{ role: 'user', content: prompt }], max_tokens: 300 });
    const m = text.match(/\{[\s\S]*\}/);
    const parsed = m ? JSON.parse(m[0]) : { memories: [] };
    out = Array.isArray(parsed.memories) ? parsed.memories : [];
  } catch { return json({ saved: [], reason: 'ai_unavailable' }); }
  const seen = new Set(existing.map(t => t.toLowerCase().replace(/\W+/g, ' ').trim()));
  const saved = [];
  for (const mm of out.slice(0, 2)) {
    const t = String((mm && mm.text) || '').replace(/\s+/g, ' ').trim().slice(0, 200);
    const key = t.toLowerCase().replace(/\W+/g, ' ').trim();
    if (t.length < 6 || seen.has(key)) continue;
    const cat = ['support', 'goal', 'preference', 'about'].includes(mm.category) ? mm.category : 'about';
    const id = 'm_' + rid(10), at = now();
    await env.DB.prepare("INSERT INTO memories (id, user_id, text, category, source, conversation_id, created_at) VALUES (?, ?, ?, ?, 'chat', ?, ?)")
      .bind(id, user.id, t, cat, cid, at).run();
    seen.add(key); saved.push({ id, text: t, category: cat, source: 'chat', created_at: at });
  }
  return json({ saved });
}

// ---------- JSON API (all scoped to the signed-in user) ----------
async function readJson(request) {
  const len = Number(request.headers.get('content-length') || 0);
  if (len > MAX_BODY_BYTES) throw new Error('too large');
  return await request.json();
}
const cleanMsg = m => (m && (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string' && m.content.trim())
  ? { role: m.role, content: m.content.slice(0, MAX_MESSAGE_CHARS) } : null;

async function insertMessages(env, user, cid, msgs) {
  const t = now(); let lastId = null;
  const stmts = msgs.map((m, i) => env.DB.prepare('INSERT INTO messages (conversation_id, user_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)').bind(cid, user.id, m.role, m.content, t + i));
  if (stmts.length) {
    const r = await env.DB.batch(stmts); lastId = r[r.length - 1].meta.last_row_id;
    await env.DB.prepare('UPDATE conversations SET updated_at = ?, message_count = message_count + ? WHERE id = ? AND user_id = ?').bind(t, stmts.length, cid, user.id).run();
  }
  return lastId;
}

async function api(request, env, user, url) {
  const p = url.pathname, m = request.method;
  // State-changing requests must come from this site.
  if (m !== 'GET') {
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) return json({ error: 'Forbidden' }, 403);
  }
  try {
    if (p === '/api/me' && m === 'GET') return json(await bootData(env, user));

    if (p === '/api/prefs' && m === 'PUT') {
      const body = await readJson(request); const prefs = body && body.prefs;
      if (!prefs || typeof prefs !== 'object') return json({ error: 'Bad request' }, 400);
      const entries = Object.entries(prefs).filter(([k, v]) => PREF_KEY_RE.test(k) && (typeof v === 'string' || v === null)).slice(0, 40);
      const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM prefs WHERE user_id = ?').bind(user.id).first();
      const stmts = [];
      for (const [k, v] of entries) {
        if (v === null) { stmts.push(env.DB.prepare('DELETE FROM prefs WHERE user_id = ? AND key = ?').bind(user.id, k)); continue; }
        if (v.length > MAX_PREF_BYTES) continue;
        stmts.push(env.DB.prepare('INSERT INTO prefs (user_id, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').bind(user.id, k, v, now()));
      }
      if ((n && n.n) + stmts.length > MAX_PREF_KEYS + 40) return json({ error: 'Too many settings' }, 400);
      if (stmts.length) await env.DB.batch(stmts);
      return json({ ok: true, saved: stmts.length });
    }

    // conversations
    if (p === '/api/conversations' && m === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT c.id, c.title, c.mode, c.created_at, c.updated_at, c.message_count,
          (SELECT content FROM messages x WHERE x.conversation_id = c.id AND x.user_id = c.user_id ORDER BY x.id DESC LIMIT 1) AS last
         FROM conversations c WHERE c.user_id = ? ORDER BY c.updated_at DESC LIMIT 200`).bind(user.id).all();
      return json({ conversations: (results || []).map(r => ({ ...r, last: r.last ? String(r.last).slice(0, 140) : '' })) });
    }
    if (p === '/api/conversations' && m === 'POST') {
      const body = await readJson(request);
      const msgs = (Array.isArray(body.messages) ? body.messages : []).map(cleanMsg).filter(Boolean).slice(0, 20);
      const id = 'c_' + rid(12), t = now();
      const title = String(body.title || '').replace(/\s+/g, ' ').trim().slice(0, 80);
      await env.DB.prepare('INSERT INTO conversations (id, user_id, title, mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(id, user.id, title, String(body.mode || '').slice(0, 30) || null, t, t).run();
      const last_id = await insertMessages(env, user, id, msgs);
      return json({ id, last_id });
    }
    if (p === '/api/conversations' && m === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM messages WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM conversations WHERE user_id = ?').bind(user.id),
      ]);
      return json({ ok: true });
    }
    let mm = p.match(/^\/api\/conversations\/(c_[A-Za-z0-9_-]{6,40})(\/messages)?$/);
    if (mm) {
      const cid = mm[1];
      const conv = await env.DB.prepare('SELECT id, title, mode, created_at, updated_at, message_count FROM conversations WHERE id = ? AND user_id = ?').bind(cid, user.id).first();
      if (!conv) return json({ error: 'Not found' }, 404);
      if (mm[2]) {
        if (m !== 'POST') return json({ error: 'Method not allowed' }, 405);
        const body = await readJson(request);
        const msgs = (Array.isArray(body.messages) ? body.messages : []).map(cleanMsg).filter(Boolean).slice(0, 20);
        if (conv.message_count + msgs.length > 2000) return json({ error: 'Conversation is full' }, 400);
        const last_id = await insertMessages(env, user, cid, msgs);
        return json({ ok: true, last_id });
      }
      if (m === 'GET') {
        const { results } = await env.DB.prepare('SELECT id, role, content, created_at FROM messages WHERE conversation_id = ? AND user_id = ? ORDER BY id').bind(cid, user.id).all();
        return json({ conversation: conv, messages: results || [] });
      }
      if (m === 'PATCH') {
        const body = await readJson(request);
        const title = String(body.title || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        await env.DB.prepare('UPDATE conversations SET title = ? WHERE id = ? AND user_id = ?').bind(title, cid, user.id).run();
        return json({ ok: true });
      }
      if (m === 'DELETE') {
        await env.DB.batch([
          env.DB.prepare('DELETE FROM messages WHERE conversation_id = ? AND user_id = ?').bind(cid, user.id),
          env.DB.prepare('DELETE FROM conversations WHERE id = ? AND user_id = ?').bind(cid, user.id),
        ]);
        return json({ ok: true });
      }
      return json({ error: 'Method not allowed' }, 405);
    }

    // memories
    if (p === '/api/memories' && m === 'GET') {
      const { results } = await env.DB.prepare('SELECT id, text, category, source, created_at FROM memories WHERE user_id = ? ORDER BY created_at DESC').bind(user.id).all();
      return json({ enabled: !!user.memory_enabled, memories: results || [] });
    }
    if (p === '/api/memories' && m === 'POST') {
      const body = await readJson(request);
      const t = String(body.text || '').replace(/\s+/g, ' ').trim().slice(0, 300);
      if (t.length < 2) return json({ error: 'Empty' }, 400);
      const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM memories WHERE user_id = ?').bind(user.id).first();
      if ((count && count.n) >= MAX_MEMORIES) return json({ error: 'Memory is full' }, 400);
      const id = 'm_' + rid(10), at = now();
      await env.DB.prepare("INSERT INTO memories (id, user_id, text, category, source, conversation_id, created_at) VALUES (?, ?, ?, 'about', 'you', NULL, ?)").bind(id, user.id, t, at).run();
      return json({ saved: { id, text: t, category: 'about', source: 'you', created_at: at } });
    }
    if (p === '/api/memories' && m === 'DELETE') {
      await env.DB.prepare('DELETE FROM memories WHERE user_id = ?').bind(user.id).run();
      return json({ ok: true });
    }
    if (p === '/api/memories/settings' && m === 'PUT') {
      const body = await readJson(request);
      await env.DB.prepare('UPDATE users SET memory_enabled = ? WHERE id = ?').bind(body.enabled ? 1 : 0, user.id).run();
      return json({ ok: true, enabled: !!body.enabled });
    }
    if (p === '/api/memories/extract' && m === 'POST') return handleExtract(request, env, user);
    mm = p.match(/^\/api\/memories\/(m_[A-Za-z0-9_-]{6,40})$/);
    if (mm && m === 'DELETE') {
      await env.DB.prepare('DELETE FROM memories WHERE id = ? AND user_id = ?').bind(mm[1], user.id).run();
      return json({ ok: true });
    }

    // everything saved for this account, but keep the account itself
    if (p === '/api/data' && m === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM messages WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM conversations WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM memories WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM prefs WHERE user_id = ?').bind(user.id),
      ]);
      return json({ ok: true });
    }

    // account
    if (p === '/api/account' && m === 'DELETE') {
      const body = await readJson(request);
      const u = await env.DB.prepare('SELECT pw_hash, pw_salt, pw_iter FROM users WHERE id = ?').bind(user.id).first();
      const calc = await pbkdf2(String(body.password || '').slice(0, 200) || 'x', fromB64url(u.pw_salt), u.pw_iter);
      if (!(await safeEqual(calc, u.pw_hash))) return json({ error: "That password didn't match." }, 401);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM messages WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM conversations WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM memories WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM prefs WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
        env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
      ]);
      return json({ ok: true }, 200, { 'set-cookie': cookie('', 0) });
    }
  } catch (e) {
    console.log(JSON.stringify({ evt: 'api_error', path: p, method: m, msg: String(e && e.message || e).slice(0, 120) }));
    return json({ error: 'Something went wrong' }, 500);
  }
  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;
    if (!env.DB) return new Response('Present is missing its database binding.', { status: 500 });
    if (p === '/login' || p === '/signup') {
      if (request.method === 'POST') return p === '/login' ? handleLogin(request, env) : handleSignup(request, env);
      if (await currentUser(request, env)) return Response.redirect(new URL('/', url).toString(), 303);
      return authPage({ mode: p === '/signup' ? 'signup' : 'signin' });
    }
    if (p === '/logout') return handleLogout(request, env);
    if (p === '/favicon.ico') return new Response(null, { status: 204, headers: { 'cache-control': 'public, max-age=86400' } });
    // Home-screen install files carry nothing private and are fetched without cookies.
    if (/^\/(manifest\.webmanifest|icon-(180|192|512)\.png)$/.test(p)) return env.ASSETS.fetch(request);
    const user = await currentUser(request, env);
    if (p.startsWith('/api/')) {
      if (!user) return json({ error: 'Not signed in' }, 401);
      if (p === '/api/generate') {
        if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405);
        return handleGenerate(request, env, user);
      }
      return api(request, env, user, url);
    }
    if (!user) {
      if (request.method === 'GET' && (p === '/' || p === '/index.html')) return authPage();
      return new Response(null, { status: 303, headers: { location: '/login', 'cache-control': 'no-store' } });
    }
    if (p === '/' || p === '/index.html') return serveApp(request, env, user);
    const res = await env.ASSETS.fetch(request);
    const h = new Headers(res.headers);
    // Scene images and other static files are the same for everyone: cacheable in the browser, never shared caches.
    if (/^\/scenes\//.test(p)) h.set('cache-control', 'private, max-age=604800');
    else h.set('cache-control', 'private, no-store');
    h.set('x-robots-tag', 'noindex');
    return new Response(res.body, { status: res.status, headers: h });
  },
};
