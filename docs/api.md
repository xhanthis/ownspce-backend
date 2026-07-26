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
| 403 | `device_pending`, `insufficient_role`, `approval_required`, `publish_limit`, `email_unverified`, `owner_immutable` |
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

### POST /auth/session
Public. Verifies a Google or Apple ID token, creates the user on first call, and registers the calling device's public key in the same step.

```json
// request
{ "provider": "google",
  "idToken": "eyJ...",
  "device": { "label": "MacBook", "platform": "macos", "publicKey": "<base64 32B X25519>" } }

// 200
{ "accessToken": "eyJ...", "refreshToken": "zxGx...", "expiresIn": 900, "isNewUser": false,
  "user": { "id": "…", "email": "r@x.com", "name": "Rahul", "username": "rahul", "avatarUrl": null,
            "plan": "free", "streakCount": 0, "streakUpdatedOn": null, "theme": "system",
            "language": "en", "notifyEmail": true, "notifyPush": true, "recoveryPublicKey": "" },
  "device": { "id": "…", "status": "active" } }
```

`platform` ∈ `ios | macos | android | windows | linux | web | ""`. The **first** live device of an account is `active`; every later one is `pending` until approved (see device approval). A pending device gets a session so it can poll for approval, but every data route answers `403 device_pending`.

### POST /auth/refresh
Public. Rotates the refresh token. Replaying a spent token revokes the entire family — the client must sign in again.

```json
{ "refreshToken": "zxGx..." }   →  same shape as POST /auth/session
```

### POST /auth/logout
Revokes the calling device's refresh tokens. → `204`.

### GET /me
→ the `user` object above.

### PATCH /me
Any subset. All Tier 0.

```json
{ "name": "Rahul", "username": "rahul", "avatarUrl": "https://…", "theme": "dark",
  "language": "en", "notifyEmail": true, "notifyPush": false,
  "streakCount": 7, "streakUpdatedOn": "2026-07-26",
  "recoveryPublicKey": "<base64 32B>" }
```

Username: `^[a-z0-9_]{3,30}$`, unique, not reserved. `theme` ∈ `system|light|dark`. → the updated `user` object.

### GET /users/{username}
Public. → `{"id","username","name","avatarUrl"}`. Never email, plan, or settings.

---

## Devices & keys

### GET /devices
→ `{"devices":[{"id","label","platform","publicKey","status","createdAt","lastSeenAt","isCurrent"}]}` — includes `pending` devices so a trusted device can offer approval.

### POST /devices
Adds a device to an already-authenticated account (CLI, etc.). `{"label","platform","publicKey"}` → `201` device object. Device keys are immutable: a new key is a new device.

### GET /devices/{deviceId}/pending-keys
Tells an approving device exactly what to wrap. → `{"deviceId","publicKey","spaces":[{"spaceId","keyEpoch"}]}`.

### POST /devices/{deviceId}/approve
Activates a pending device and files the space keys wrapped to its public key.

```json
{ "recovery": false,
  "wrappedKeys": [ { "spaceId": "…", "keyEpoch": 2, "wrappedKey": "<base64 sealed box>" } ] }
```

Two callers are allowed:
- an **active** device of the same account (after the user compares key fingerprints) — `recovery: false`;
- the **pending device itself** with `recovery: true`, having unwrapped the recovery-key copies of the space keys from the phrase locally.

Keys naming a space the user has left, or an epoch that has since rotated, are silently skipped — refetch and retry. → `200` device object.

### DELETE /devices/{deviceId}
Revokes: refresh tokens die, space keys wrapped to that device are deleted, and its next request is rejected. Rotate the affected space keys afterwards — revocation cannot make a device forget a key it already holds. → `204`.

### GET /keys/{userId}
The key directory an inviter wraps for. → `{"userId","devices":[{"deviceId","publicKey"}],"recoveryPublicKey"}` — active devices only, public keys only.

---

## Spaces & membership

### POST /spaces
No name is accepted — the space name lives sealed inside its workspace document.

```json
{ "wrappedKeys": [ { "deviceId": "…", "wrappedKey": "…" },
                   { "deviceId": null,  "wrappedKey": "<wrapped to recovery key>" } ] }
// 201
{ "id": "…", "role": "owner", "keyEpoch": 1, "headSeq": 0, "workspaceVersion": 0 }
```

`deviceId: null` means the key is wrapped to the account recovery key. A request whose keys match none of your active devices is rejected — a space nobody can decrypt is never created.

### GET /spaces
Query: `includeRecoveryKeys=true` for the recovery flow.

```json
{ "spaces": [ { "id": "…", "role": "owner", "keyEpoch": 2, "headSeq": 1042, "oldestSeq": 1001,
                "workspaceVersion": 7, "memberCount": 3,
                "wrappedKey": "<for the calling device, null if not yet granted>",
                "recoveryWrappedKey": "<only with includeRecoveryKeys=true>" } ] }
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

## Rate limits

Fixed windows, keyed per subject. Exceeding one returns `429` with `Retry-After`.

| Route | Limit | Subject |
|---|---|---|
| POST /auth/session | 10 / min | IP |
| POST /auth/refresh | 30 / min | IP |
| GET …/updates | 120 / min | device |
| POST …/updates, PUT …/workspace | 60 / min | device |
| POST …/snapshot, PUT …/snapshot/blob | 6 / hour | space |
| POST /spaces, member and key routes | 60 / min | user |
| GET /keys/:userId | 60 / min | user |
| PATCH /me | 20 / min | user |
| POST /devices | 10 / hour | user |
| POST /publish, /publish/assets | 5 / hour | user |
| public reads | 300 / min | IP |
