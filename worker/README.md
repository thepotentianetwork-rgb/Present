# Present Worker (accounts version, v8)

Serves Present (`index.html`, icons, `scenes/`) to signed-in users, stores each person's chats, memory
and settings in D1, and proxies AI replies: app → this Worker (holds the key) → Anthropic.
Separate from the CRM worker `potentia-assistant`. It only touches its own D1 database (`present-data`
for the preview), never the ShedPro/Potentia databases.

- Preview: https://present-app-preview.thepotentianetwork.workers.dev (script `present-app-preview`, D1 `present-data`)
- Testers today: https://present-app.thepotentianetwork.workers.dev (script `present-app`, still the old shared-password build)

## Accounts
- `GET/POST /signup`: name, email, password (at least 8 characters) and an **invite code**. The invite code is the
  value of the `PRESENT_PASSWORD` secret, i.e. the old shared password. Passwords: PBKDF2-SHA256,
  100k iterations (the Workers cap), 16-byte random salt.
- `GET/POST /login`, `/logout`. Session: random token in an HttpOnly, Secure, SameSite=Lax cookie
  `present_sid` (30 days). Only its SHA-256 hash is stored in `sessions`. Same-origin check on every
  non-GET `/api/*` call. Failed logins are rate-limited per IP (Cache API) with a constant-time path for
  unknown emails.
- The legacy `present_session` cookie is cleared and never trusted.
- Every query is scoped by `user_id` from the session. Other people's IDs return 404.

## API (all need a session)
| route | what |
|---|---|
| `GET /api/me` | account + saved settings (also injected into the page at load) |
| `PUT /api/prefs` | save settings (home layout, pins, theme, Sanctuary scene/sound/volume, sound & vibration…) |
| `GET/POST/DELETE /api/conversations` | list / create (title, mode, messages) / delete all |
| `GET/PATCH/DELETE /api/conversations/:id`, `POST …/:id/messages` | read, rename, delete, append |
| `GET/POST/DELETE /api/memories`, `DELETE /api/memories/:id` | list / add your own / delete all / delete one |
| `PUT /api/memories/settings` | memory on/off |
| `POST /api/memories/extract` `{conversation_id}` | Haiku reads the last turns and saves 0–2 lasting facts. Returns `saved: []` when memory is off. The prompt forbids saving crisis, health or guessed details, and the client never asks after a safety reply. Returns exactly what it wrote |
| `POST /api/generate` `{system, messages, temporary}` | Sonnet reply. Adds the person's memories to the system prompt unless memory is off or `temporary` |
| `DELETE /api/data` | deletes chats, memories and settings (keeps the account) |
| `DELETE /api/account` `{password}` | deletes the account and everything in it |

Message content is never logged.

## Secrets / vars
| name | kind | notes |
|---|---|---|
| `PRESENT_PASSWORD` | secret | now the **invite code** for sign-up (no longer a login) |
| `ANTHROPIC_API_KEY` | secret | without it the app falls back to local replies and memory extraction is off |
| `ANTHROPIC_MODEL` / `MEMORY_MODEL` | plain vars | defaults `claude-sonnet-5-5` / `claude-haiku-5-5`, set by deploy.mjs |
| `DB` | D1 binding | set by deploy.mjs from `PRESENT_D1_ID` |
| `ASSETS` | assets binding | `run_worker_first: true` so the sign-in gate covers every file |
| `SESSION_SECRET` | (old) | unused now; can be deleted after promotion |

## Deploy (Cloudflare REST API, no wrangler, Node 20+)
```bash
export CLOUDFLARE_API_TOKEN=...
PRESENT_D1_ID=<uuid> node worker/d1.mjs worker/schema.sql          # idempotent
PRESENT_SCRIPT=present-app-preview PRESENT_D1_ID=<uuid> node worker/deploy.mjs
PRESENT_SCRIPT=present-app-preview node worker/set-secret.mjs PRESENT_PASSWORD < .secrets/present-password.txt
PRESENT_SCRIPT=present-app-preview node worker/set-secret.mjs ANTHROPIC_API_KEY < /path/to/key.txt
```
Deploying `present-app` (the testers' URL) also needs `PRESENT_CONFIRM_PROD=yes`, so it can't happen by accident.

## Promotion to the testers' URL (needs Nando's approval; not done)
1. Merge `present-v2` into the branch the testers' build comes from.
2. Pick the database. Either reuse `present-data` (it still holds preview test data; run
   `DELETE FROM sessions; DELETE FROM messages; DELETE FROM conversations; DELETE FROM memories; DELETE FROM prefs; DELETE FROM users;`
   through d1.mjs first) or create a fresh D1, e.g. `present-prod`, and run `worker/schema.sql` on it.
3. Make sure `present-app` has `ANTHROPIC_API_KEY` (it already has one) and `PRESENT_PASSWORD`. That
   existing shared password becomes the invite code, so testers already know it.
4. `PRESENT_CONFIRM_PROD=yes PRESENT_SCRIPT=present-app PRESENT_D1_ID=<uuid> node worker/deploy.mjs`
   (keeps existing secrets and adds the D1 binding).
5. What testers see: their old cookie is cleared and they land on Sign in. They tap **Create an account**,
   enter name, email, a password and the invite code (the old password). On first load the app offers to
   **Bring this device's data into my account** (check-ins, journal, settings saved in that browser),
   **Start fresh** or **Decide later**.
6. Smoke test: sign up, send one message, check Chats and Memory, sign out and in again.
7. Optional: delete the unused `SESSION_SECRET` secret. Roll back by redeploying the previous commit
   (D1 data stays put).
