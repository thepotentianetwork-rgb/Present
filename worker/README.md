# present-app Worker

Serves Present (`index.html` + images at repo root) behind one shared password,
and proxies AI replies: app → this Worker (holds the key) → Anthropic.
Separate from the CRM worker `potentia-assistant`; this does not touch it or any D1.

URL: https://present-app.thepotentianetwork.workers.dev

## Routes
- `GET /login`: calm password page. `POST /login`: constant-time check against `PRESENT_PASSWORD`,
  sets `present_session` (HMAC-SHA256 with `SESSION_SECRET`, HttpOnly, Secure, SameSite=Lax, 30 days).
- `/logout`: clears the cookie and redirects to /login.
- `POST /api/generate` `{system, messages}` → `{text}`. Needs a session (401 if missing). It caps at 40 messages,
  8k chars/message, 60k system, `max_tokens` 1024. Returns 503 `AI not configured` if there's no key and 502
  `AI unavailable` on upstream failure, so the app falls back to its local replies. Message content is never logged.
- Everything else: static assets, but only with a session (otherwise you're redirected to /login).

Login rate limit: per IP via the Cache API. After 5 failures it backs off 30s, 60s, 120s… up to 15 min.
Limits: the cache is per data centre and can evict entries, so this only slows casual guessing.
The long random password is the real protection. Use a WAF rate-limit rule or Durable Object if you need a hard limit.

## Secrets / vars
| name | kind | notes |
|---|---|---|
| `PRESENT_PASSWORD` | secret | shared login password |
| `SESSION_SECRET` | secret | HMAC key for the cookie. Rotating it signs everyone out |
| `ANTHROPIC_API_KEY` | secret | optional. Without it, /api/generate returns `AI not configured` |
| `ANTHROPIC_MODEL` | plain var | default `claude-sonnet-5-5`. Set by deploy.mjs from env `ANTHROPIC_MODEL` |
| `ASSETS` | assets binding | `run_worker_first: true` so the gate covers every file |

## Deploy (Cloudflare REST API, no wrangler)
```bash
export CLOUDFLARE_API_TOKEN=...            # needs Workers Scripts: Edit on the account
node worker/deploy.mjs                     # uploads assets + worker.js, enables workers.dev
# secrets (value read from stdin, never argv); keep_bindings preserves them across deploys
node worker/set-secret.mjs PRESENT_PASSWORD < .secrets/present-password.txt
openssl rand -hex 32 | node worker/set-secret.mjs SESSION_SECRET
node worker/set-secret.mjs ANTHROPIC_API_KEY < /path/to/key.txt
```
deploy.mjs: assets-upload-session → /workers/assets/upload (base64) → PUT /workers/scripts/present-app
(multipart: metadata + worker.js) → POST …/subdomain. Node 20+.
