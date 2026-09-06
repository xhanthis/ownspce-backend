# Ownspce API Reference

Base URL `https://api.ownspce.com/v1`. JSON in, JSON out. Binary fields are base64 (standard or URL-safe, padded or not, on the way in; padded standard on the way out).

Authenticated routes take `Authorization: Bearer <accessToken>`. Errors are uniform:

```json
{ "error": { "code": "stale_epoch", "message": "the space key has rotated; ..." } }
```

| Status | Codes seen |
|---|---|
| 400 | `invalid_request` |
| 401 | `unauthorized`, `token_reused`, `token_expired` |
| 403 | `device_pending`, `insufficient_role`, `approval_required`, `origin_not_permitted`, `publish_limit`, `email_unverified`, `owner_immutable` |
| 404 | `not_found` |
| 409 | `username_taken`, `username_reserved`, `slug_reserved`, `stale_epoch`, `epoch_conflict`, `version_conflict`, `snapshot_conflict`, `already_member_or_stale_epoch` |
| 413 | `bucket_violation`, `payload_too_large` |
| 429 | `rate_limited` (with `Retry-After`) |
| 451 | `taken_down` |
| 503 | `unavailable` |

---

## Health & keys

**GET /health** → `{"status":"ok","env":"production"}`, or 503 with `{"status":"degraded","database":"..."}`.

**GET /.well-known/jwks.json** → the Ed25519 public key so other services can verify session tokens.

---

## Auth & profile

### POST /auth/email/code
Public. Mails a six-digit sign-in code. Always `204`, whether or not the address has an account — the endpoint is deliberately not a membership oracle. `503 unavailable` only when the deployment has no mail provider.

```json
{ "email": "r@x.com" }   →  204
```

A code lasts ten minutes, works once, is stored only as SHA-256, and is burnt after five wrong guesses. An address may be sent five codes an hour; beyond that the response is still `204` and no mail is sent.

### POST /auth/session
Public. Verifies a Google or Apple ID token — or a code this API mailed — creates the user on first call, and registers the calling device's public key in the same step. All three providers resolve to one account per email address, so a Google user who later signs in by code lands on the account they already have.

```json
// request, provider "google" or "apple"
{ "provider": "google",
  "idToken": "eyJ...",
  "device": { "label": "MacBook", "platform": "macos", "publicKey": "<base64 32B X25519>" } }

// request, provider "email"
{ "provider": "email",
  "email": "r@x.com",
  "code": "123456",
  "device": { "label": "MacBook", "platform": "macos", "publicKey": "<base64 32B X25519>" } }

// 200
{ "accessToken": "eyJ...", "refreshToken": "zxGx...", "expiresIn": 900, "isNewUser": false,
  "user": { "id": "…", "email": "r@x.com", "name": "Rahul", "username": "rahul", "avatarUrl": null,
            "plan": "free", "streakCount": 0, "streakUpdatedOn": null, "theme": "system",
            "font": "grotesk", "palette": "cream", "customTheme": null,
            "language": "en", "notifyEmail": true, "notifyPush": true, "recoveryPublicKey": "" },
  "device": { "id": "…", "status": "active" } }
```

`platform` ∈ `ios | macos | android | windows | linux | web | ""`. Every device is `active` from this call. Signing in **is** the gate — proving the account with Google, Apple or a mailed code is the whole check — and there is no approval step behind it.

A device that holds no keys is handed the account's escrow copies during this call. That is also the lost-every-device path: revoke or lose them all, sign in again, and the replacement device is both trusted and able to read.

A browser is additionally handed the cross-surface session cookie (see below). An installed app is not: it sends no `Origin` and keeps no cookie jar.

A wrong or expired code answers `401`; a code burnt by five wrong guesses answers `403 code_exhausted`.

### POST /auth/refresh
Public. Rotates the refresh token. Replaying a spent token revokes the entire family — the client must sign in again.

```json
{ "refreshToken": "zxGx..." }   →  same shape as POST /auth/session
```

### POST /auth/continue
Public. Turns "this browser is signed in to OwnSpce somewhere" into a session on the surface asking, using the cross-surface cookie.

```json
{ "device": { "label": "Chrome", "platform": "web", "publicKey": "<base64 32B X25519>" } }
   →  same shape as POST /auth/session
```

`ownspce.com` (the marketing page and the app, one deployment) and `money.ownspce.com` are separate origins with separate storage, so each mints its own device keypair and neither can see the other's session. This endpoint spends the shared cookie: it proves the account, registers the calling surface's device as a device of its own, hands it the account escrow copies, and rotates the cookie on the way out.

Call it with `credentials: "include"`, once, before painting a sign-in screen. A browser that has never signed in anywhere pays one `401` — and its cookie, if it had a dead one, is cleared so the next cold start does not pay again.

### The cross-surface session cookie
`os_session`, set on `/auth/session`, `/auth/refresh` and `/auth/continue`, cleared on `/auth/logout`:

```
Set-Cookie: os_session=…; Domain=ownspce.com; Path=/; Max-Age=…; HttpOnly; Secure; SameSite=Lax
```

It carries a refresh token in its own family, so it inherits sliding expiry, replay detection and family revocation from the ordinary token machinery. `HttpOnly` keeps it out of reach of script on every surface at once; `SameSite=Lax` is sufficient because api, app and money share a registrable domain and the request is therefore same-site.

Set **both** `SESSION_COOKIE_DOMAIN` (e.g. `ownspce.com`) and `SESSION_ORIGINS` (e.g. `https://ownspce.com,https://money.ownspce.com`) to enable it. With either unset — the right answer locally, and for any deployment whose surfaces do not share a domain — no cookie is issued and each surface asks for its own sign-in.

`SESSION_ORIGINS` is deliberately **shorter than the CORS allowlist**: name only the app surfaces. An origin outside it is never handed the cookie and gets `403 origin_not_permitted` from `/auth/continue`. Every origin on the list is an origin whose scripts can register an attacker's own device on somebody's account, holding every space key re-wrapped from escrow — reading the response is not even needed, the registration is the damage.

> **Published pages must never execute on a session origin.** `/@username/slug` serves HTML somebody else wrote, and since the marketing page and the app became one deployment it serves it from `ownspce.com` — a session origin. What keeps the two apart is no longer the origin list but the frame: the page body is rendered in an `<iframe sandbox="allow-popups">` **without** `allow-same-origin`, so it has an opaque origin and its requests arrive as `Origin: null`, which is on no list. Only first-party markup may run on `ownspce.com` itself. Adding `allow-same-origin` to that frame re-opens the hole. `TestOnlyAnAppSurfaceMaySpendTheCookie` pins both halves.

### POST /auth/logout
Revokes the calling device's refresh tokens, and clears **and revokes** the cross-surface cookie. Signing out of Money and staying silently signed in on app is worse than signing out of both. → `204`.

### GET /me
→ the `user` object above.

### PATCH /me
Any subset. All Tier 0.

```json
{ "name": "Rahul", "username": "rahul", "avatarUrl": "https://…", "theme": "dark",
  "font": "grotesk", "palette": "graphite",
  "customTheme": { "base": "graphite",
                   "light": { "accent": "#2E3192", "onAccent": "#FFFFFF" },
                   "dark":  { "accent": "#8B8FE8" } },
  "language": "en", "notifyEmail": true, "notifyPush": false,
  "streakCount": 7, "streakUpdatedOn": "2026-07-26",
  "recoveryPublicKey": "<base64 32B>" }
```

Username: `^[a-z0-9_]{3,30}$`, unique, not reserved. `theme` ∈ `system|light|dark`, `font` ∈ `grotesk|sans|serif`, `palette` ∈ `cream|paper|sand|graphite|midnight|indigo|evergreen`. → the updated `user` object.

`customTheme` is the theme the account built for itself, and it is three-state: leave the field out and the stored theme is untouched, send `null` and the account goes back to painting its preset, send an object and it replaces what was there. `base` is the preset it was forked from, and `light` and `dark` each carry the colours that scheme overrides — only `accent`, `onAccent`, `success`, `warning`, `danger`, `background`, `surface`, `elevated`, `border`, `primaryText` and `secondaryText`, each a `#rrggbb` value. Anything else is a 400. The remaining colours in a palette are derived by the clients from these, so the server never has to know how a theme is built, only that it cannot carry anything but colours.

Appearance (`theme`, `font`, `palette`, `customTheme`) is deliberately Tier 0: it describes how a page is painted, never what it says, and storing it here is what makes a workspace look the same on every device — including on the sign-in and pending-device screens, which render before any space key has been unwrapped.

### GET /users/{username}
Public. → `{"id","username","name","avatarUrl"}`. Never email, plan, or settings.

---

## Devices & keys

### GET /devices
→ `{"devices":[{"id","label","platform","publicKey","status","createdAt","lastSeenAt","isCurrent"}]}`. `status` is `active` for anything a person can still sign in on; `pending` survives in the schema only for rows written before device approval was removed, and clears on that device's next sign-in.

### POST /devices
Adds a device to an already-authenticated account (CLI, etc.). `{"label","platform","publicKey"}` → `201` device object. Device keys are immutable: a new key is a new device. It is active and holding its escrow copies from creation, on the same terms as one registered at sign-in.

### GET /devices/{deviceId}/pending-keys
Tells a device holding a space key exactly what another device still needs wrapped. → `{"deviceId","publicKey","spaces":[{"spaceId","keyEpoch"}]}`.

### POST /devices/{deviceId}/approve
Files space keys wrapped to a device's public key.

This is no longer a gate — a device is in the account from sign-in — but it is still how a device gets a key for a space with **no escrow copy**, which is every space created before escrow existed. Nothing else can produce that key: the server does not hold it.

```json
{ "emailCode": "",
  "wrappedKeys": [ { "spaceId": "…", "keyEpoch": 2, "wrappedKey": "<base64 sealed box>" } ] }
```

Two callers are allowed:
- **another** device of the same account (after the user compares key fingerprints), supplying the wraps itself;
- the **device itself** with `emailCode` and no wraps, having proved the account's email address; the server re-wraps the account escrow copies for it. A device may never file wraps for itself without that code — otherwise it could claim keys nobody granted it, and `403 approval_required` says so.

Keys naming a space the user has left, or an epoch that has since rotated, are silently skipped — refetch and retry. → `200` device object.

### DELETE /devices/{deviceId}
Revokes: refresh tokens die, space keys wrapped to that device are deleted, and its next request is rejected. Rotate the affected space keys afterwards — revocation cannot make a device forget a key it already holds. → `204`.

### POST /devices/{deviceID}/verify-email/code
Mails a six-digit code to the account's **own** address so the calling device can collect the account escrow copies. Only for itself: a `deviceID` other than the caller's answers `400`.

```
→  204
```

### GET /keys/{userId}
The key directory an inviter wraps for. → `{"userId","devices":[{"deviceId","publicKey"}],"recoveryPublicKey"}` — active devices only, public keys only.

---

## Spaces & membership

### POST /spaces
No name is accepted — the space name lives sealed inside its workspace document.

```json
{ "wrappedKeys": [ { "deviceId": "…", "wrappedKey": "…" },
                   { "deviceId": null,  "wrappedKey": "<wrapped to account escrow key>" } ] }
// 201
{ "id": "…", "role": "owner", "keyEpoch": 1, "headSeq": 0, "workspaceVersion": 0 }
```

`deviceId: null` means the key is wrapped to the account escrow key, which is what makes the household recoverable by email later. A request whose keys match none of your active devices is rejected — a space nobody can decrypt is never created.

### GET /spaces
The account escrow copy of a space key is never served here, or anywhere. It is sealed to a key only the server can open, so no caller could use it.

```json
{ "spaces": [ { "id": "…", "role": "owner", "keyEpoch": 2, "headSeq": 1042, "oldestSeq": 1001,
                "workspaceVersion": 7, "memberCount": 3,
                "wrappedKey": "<for the calling device, null if not yet granted>",
                } ] }
```

### GET /spaces/{id}/members
→ `{"members":[{"userId","username","name","avatarUrl","role","joinedAt"}]}`.

### POST /spaces/{id}/members
Owner only. The invite **is** the wrapped key.

```json
{ "userId": "…", "role": "editor", "keyEpoch": 2,
  "wrappedKeys": [ { "deviceId": "…", "wrappedKey": "…" }, { "deviceId": null, "wrappedKey": "…" } ] }
```
`role` ∈ `editor|viewer`. → `201 {"spaceId","userId","role"}`.

### DELETE /spaces/{id}/members/{userId}
Owner removes anyone; a member may remove themselves. The owner cannot be removed (`403 owner_immutable`). → `204`. **Rotate the space key next.**

### POST /spaces/{id}/keys
Owner only. Advances the key epoch after a removal.

```json
{ "newEpoch": 2,
  "wrappedKeys": [ { "userId": "…", "deviceId": "…",  "wrappedKey": "…" },
                   { "userId": "…", "deviceId": null, "wrappedKey": "…" } ] }
```

`newEpoch` must be exactly current + 1. The server checks **coverage** — every remaining member's active devices must receive a key — and rejects the whole rotation otherwise, so a partial rotation can never lock anyone out. → `200 {"spaceId","keyEpoch"}`. Writes at the old epoch then fail with `409 stale_epoch`.

---

## Sync

Roles: read needs `viewer`, write needs `editor`.

### POST /spaces/{id}/updates
Appends sealed change-sets and returns the sequence number each was given. Up to 100 per batch.

```json
// request
{ "keyEpoch": 2, "changes": [ { "cid": "<client uuid>", "ciphertext": "<base64>" } ] }
// 200
{ "assigned": [ { "cid": "…", "seq": 1042 } ], "head": 1042 }
```

Each ciphertext length must equal a padding bucket + 40 bytes of AEAD overhead (see `docs/client-crypto.md`) or the batch is refused with `413 bucket_violation`. `cid` makes retries idempotent — resending returns the original `seq`. Writing at a rotated epoch gives `409 stale_epoch`.

### GET /spaces/{id}/updates?since=N&limit=200
The catch-up poll (every 1–2s while active). Send `If-None-Match` with the previous `ETag` to make idle polls cost a `304`.

```json
{ "changes": [ { "seq": 1043, "cid": "…", "keyEpoch": 2, "authorDeviceId": "…",
                 "ciphertext": "<base64>", "createdAt": "2026-07-26T12:00:00Z" } ],
  "head": 1050, "oldestSeq": 1001, "keyEpoch": 2, "workspaceVersion": 7,
  "resync": false, "nextSince": 1043 }
```

If `since` predates compaction, the response is `{"resync": true, "snapshot": {…}, "nextSince": <snapshot.uptoSeq>}` — load the snapshot, then poll from `nextSince`.

### POST /spaces/{id}/snapshot
Commits a compacted snapshot and truncates the log up to `uptoSeq`. Exactly one of `ciphertext` (inline, ≤ 256 KB bucket) or `blobUrl` (from the upload route).

```json
{ "uptoSeq": 1040, "keyEpoch": 2, "ciphertext": "<base64>" }
{ "uptoSeq": 1040, "keyEpoch": 2, "blobUrl": "https://….blob.vercel-storage.com/snapshots/…", "sizeBucket": 262144 }
// 200
{ "uptoSeq": 1040, "keyEpoch": 2, "storage": "inline", "oldestSeq": 1041 }
```

A snapshot behind the stored one, ahead of `head`, or built under a rotated key → `409 snapshot_conflict`. The superseded blob is deleted in the background.

### PUT /spaces/{id}/snapshot/blob
Raw ciphertext body (not JSON) for snapshots too large to inline. → `201 {"blobUrl","sizeBucket"}`. `503` when no blob store is configured.

### GET /spaces/{id}/snapshot
→ `{"uptoSeq","keyEpoch","storage","ciphertext","blobUrl","sizeBucket","createdAt"}`, or `404` before the first compaction.

### GET /spaces/{id}/workspace
The sealed Tier 1 document. → `{"version","keyEpoch","ciphertext","updatedAt"}`. Before the first write: `{"version":0,"keyEpoch":0,"ciphertext":null}`.

### PUT /spaces/{id}/workspace
```json
{ "baseVersion": 7, "keyEpoch": 2, "ciphertext": "<base64>" }   →  { "version": 8 }
```
`baseVersion: 0` creates it. A mismatch is `409 version_conflict`: refetch, merge locally, retry — the server cannot merge what it cannot read.

---

## Shares

Read-only public links. A share does not hand out the space key: the client mints a fresh key for this one snapshot, seals the page with it, uploads the ciphertext here, and puts the key in the URL **fragment** (`/s/<id>#<key>`). Browsers never send a fragment — not in the request line, not in `Referer` — so the link works while this server still cannot read what it stores.

The share id is minted by the client and is the capability in the link. It cannot be rebound: once an id belongs to a space, another space writing to it is `403 share_forbidden`.

### PUT /spaces/{id}/shares/{shareId}
Editor role. Raw ciphertext body (not JSON), capped at 2 MiB and required to begin with the `OSA1` container header. Republishing overwrites in place, so a link a reader already holds keeps resolving. → `200 {"shareId"}`.

### DELETE /spaces/{id}/shares/{shareId}
Editor role. Destroys the ciphertext, which is the real revocation — someone who already opened the link keeps what they read; what this guarantees is that nobody can fetch it again. → `204`, and `204` again if it was already gone.

### GET /shares/{shareId}
**Unauthenticated**, rate limited as a public read. → `200` with `application/octet-stream` and `X-Robots-Tag: noindex, nofollow`. A revoked link and one that never existed answer identically (`404`), and no response header carries the originating space.

---

## Attachments

Descriptors sync inside the page's own ciphertext; bytes do not. The server stores a sealed blob and a byte count, and never learns the file name, type, or true length.

The bytes cannot travel through a JSON request — a sealed photo runs to megabytes — and the uploading fetch carries no `Authorization` header. So the API authorizes the upload, then hands back a URL that carries its own permission: an HMAC grant binding exactly one space, one attachment id, and one byte count, valid for 15 minutes. Altering any of the three invalidates it.

### POST /spaces/{id}/attachments/{attachmentId}/upload-url
Editor role. `{"size": <sealed bytes>}` → `200 {"url","expiresIn"}`. `413` outside 1..12 MiB, `503` when no blob store is configured.

### PUT /spaces/{id}/attachments/{attachmentId}/blob?size=&exp=&sig=
**No session** — the grant in the query string is the whole authorization, and it is checked against the body length actually received. Refused requests are judged before storage availability, so a forged URL learns nothing about the service. → `201 {"size"}`, `403 grant_invalid` on any mismatch or expiry.

The row is written here, immediately after the bytes land: it can never point at an object that does not exist, and no state has to survive between two requests that may reach different instances.

### POST /spaces/{id}/attachments/{attachmentId}
Editor role. `{"size"}` → `200 {"size"}` — the client's checkpoint, re-checking the space role and reporting the size actually stored. `409 upload_missing` when the bytes were never uploaded.

### GET /spaces/{id}/attachments/{attachmentId}
Viewer role. → `200` with `application/octet-stream`. Proxied rather than redirected, so the bearer-readable object URL never reaches the client.

### DELETE /spaces/{id}/attachments/{attachmentId}
Editor role. Removes the row and sweeps the object behind it. → `204`.

---

## Publishing

The single deliberate exception to zero knowledge: the client decrypts the page and uploads plaintext, because the user asked for it to be public.

### POST /publish/assets
Raw image body. `Content-Type` ∈ png, jpeg, webp, gif, svg. Max 5 MB. → `201 {"url","sizeBytes"}`.

### POST /publish
```json
{ "slug": "my-reading-list", "html": "<base64, ≤2MB>", "blocks": "<base64 JSON, ≤2MB>",
  "assetUrls": ["https://….blob.vercel-storage.com/assets/…"],
  "ogTitle": "My reading list", "ogDescription": "Books I loved" }
// 200
{ "url": "https://ownspce.com/@rahul/my-reading-list", "slug": "…", "publishedAt": "…", "updatedAt": "…" }
```

Requires a username (`400`). Slug `^[a-z0-9][a-z0-9-]{0,63}$`, unique per user, not reserved (`409 slug_reserved`). Limits: 25 assets per page, 20 live pages per account (`403 publish_limit`). Republishing the same slug replaces it and deletes the old blobs.

### GET /publish
→ `{"pages":[{"slug","url","status","sizeBytes","ogTitle","publishedAt","updatedAt"}]}`.

### DELETE /publish/{slug}
Deletes the row and its blobs. → `204`.

### GET /public/pages/{username}/{slug}
Public, cached 60s. Consumed by the ownspce.com serving route.

```json
{ "username": "rahul", "slug": "my-reading-list",
  "htmlUrl": "https://…", "blocksUrl": "https://…", "assetUrls": ["https://…"],
  "ogTitle": "…", "ogDescription": "…", "publishedAt": "…", "updatedAt": "…" }
```
`451 taken_down` for moderated pages.

### POST /public/pages/{username}/{slug}/report
Public abuse intake. `{"reason":"…","details":"…"}` → `202 {"status":"received"}`. The reporter's IP is stored one-way hashed. Takedown is an operator action that flips `publishes.status`.

---

## Automations

Hands a task to a Claude Code agent running on the user's own Mac, which opens a
pull request. Two auth planes: the user plane below uses the normal access token,
while `/daemon/*` uses an opaque daemon token (`ospd_` + 43 url-safe characters,
stored only as SHA-256, revocable, no expiry).

**This is the one part of the API that stores plaintext user content.** A run
carries the task title and the instructions the user typed, because the agent has
to read them. Nothing else about the page is sent, and the web app makes the
trade explicit before queueing.

### POST /automations/runs
`{pageId, taskId, taskTitle, instructions, repo, baseBranch}` → `201 {run}`. The
branch is computed server-side and stored. `baseBranch: ""` takes the connected
repo's default. `403 repo_not_connected` when no live daemon reports the repo;
`409 run_active` when that task already has a queued or running run.

### GET /automations/runs?pageId=&limit=&cursor=
`200 {runs, nextCursor}`, newest first. `pageId` is optional — omitted lists every
run for the user, which is what the global Automations view renders. `limit`
defaults to 50, clamps to 100, and never errors. `cursor` is opaque; malformed
values are rejected rather than silently restarting the walk. List rows omit
`instructions` and `progressLog`.

### GET /automations/runs/{runId}
`200 {run}` including `instructions` and `progressLog`. `404` for another user's
run, which is never distinguished from a run that does not exist.

### POST /automations/runs/{runId}/cancel
`200 {run}`. `409 run_not_active` once the run is terminal. A daemon holding it
learns within about five seconds and stops without pushing.

### POST /automations/runs/{runId}/retry
`201 {run}` — a new row copying the payload; the original is kept for history.

### GET /automations/status
`200 {online, daemons, repos}`. `repos` is the deduplicated union across live
daemons and is exactly what the repo picker renders. Liveness is computed
server-side (`lastSeenAt` within 120s).

### POST /automations/daemons
`{name}` → `201 {token, daemon}`. **The plaintext token is returned once and is
never recoverable.**

### GET /automations/daemons · DELETE /automations/daemons/{daemonId}
List, and revoke (`204`, idempotent). Revoking never deletes run history; runs the
daemon held are reclaimed within ten minutes.

### POST /daemon/register
`{name, version, repos}` → `200 {daemon}`. Replaces the daemon's whole repo set
and stamps liveness. At most 50 repos, no duplicates.

### POST /daemon/runs/claim
`200 {run}` or `204` when idle. Reclaims runs abandoned for more than ten minutes,
then claims the oldest queued run **whose repo this daemon reported**, under
`FOR UPDATE SKIP LOCKED` so concurrent daemons never take the same run.

### PATCH /daemon/runs/{runId}/progress
`{phase, progressLog, tokensUsed}` → `200 {accepted, status, phase, attempts, maxAttempts}`.
Heartbeat and cancel channel in one. It answers `200` even when the guard fails:
`accepted:false` means the run was canceled, reclaimed or reassigned and the
daemon must abort. A `409` here would be indistinguishable from a transport error.

### POST /daemon/runs/{runId}/complete · /fail · /release
`complete` takes `{prUrl, tokensUsed}` and parks the run at `pr_ready`. `fail`
takes `outcome ∈ {auth, error, max_turns, checks}` — `auth` parks immediately
without spending an attempt, the rest re-queue until `maxAttempts`. `release`
takes `outcome ∈ {quota, deadline}` and re-queues without spending an attempt.
All three return `409 run_conflict` if the daemon no longer owns the run.

### Status codes
Adds `403 repo_not_connected`, `409 run_active`, `409 run_not_active`, and
`409 run_conflict` to the shared table.

---

## Rate limits

Fixed windows, keyed per subject. Exceeding one returns `429` with `Retry-After`.

| Route | Limit | Subject |
|---|---|---|
| POST /auth/session | 10 / min | IP |
| POST /auth/email/code | 15 / hour | IP (plus 5 / hour per address, in the store) |
| POST /devices/{id}/verify-email/code | 15 / hour | user |
| POST /auth/refresh | 30 / min | IP |
| GET …/updates | 120 / min | device |
| POST …/updates, PUT …/workspace | 60 / min | device |
| POST …/snapshot, PUT …/snapshot/blob | 6 / hour | space |
| POST /spaces, member and key routes | 60 / min | user |
| GET /keys/:userId | 60 / min | user |
| PATCH /me | 20 / min | user |
| POST /devices | 10 / hour | user |
| POST /publish, /publish/assets | 5 / hour | user |
| public reads (incl. GET /shares/:id) | 300 / min | IP |
| PUT …/shares/:id, DELETE …/shares/:id | 60 / hour | user |
| attachment upload-url, commit, delete | 120 / hour | user |
| PUT …/attachments/:id/blob | 120 / hour | IP |
| automation writes (queue, cancel, retry, revoke daemon) | 30 / hour | user |
| automation reads (runs, status, daemons) | 240 / min | user |
| POST /automations/daemons | 5 / hour | user |
| all /daemon/* routes | 120 / min | daemon |
