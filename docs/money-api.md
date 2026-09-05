# Ownspce Money API

Base URL `https://api.ownspce.com/v1`. This document covers the money surface only; `docs/api.md` is the reference for everything else and `docs/client-crypto.md` is the normative contract for the encryption these routes assume.

## What this surface moves

Ciphertext, like every other data route in this API. An earlier draft of Kosh stored amounts, categories and notes in the clear so the server could compute budgets and settle-up. That trade is withdrawn: an operator with database access could read a family's ledger, and the arithmetic it bought turned out to belong on the device, where `money-core` already lived.

So a household is a space, its records are sealed under the space key, and the server holds four things per row it can actually read:

| Field | Why the server needs it |
|---|---|
| `spaceId` | Authorisation. Every query is scoped by space membership. |
| `clientId` | Idempotent upserts. The client mints it before the request leaves the device. |
| `occurredOn` (entries only) | A ledger is read by period. Without a date the server would have to ship every row a household ever wrote on every load. |
| `keyEpoch` | Which generation of the space key opens the blob. |

Everything else — amount, type, category, note, who paid, whether it is shared, every budget, bill and holding, and the household's own name and currency — is inside the ciphertext.

Two consequences show up in the route table:

- Money routes sit behind **both** `requireAuth` and `requireActiveDevice`. A device with no wrapped space key cannot open a single row, so letting it through would buy a screen full of ciphertext rather than a ledger.
- There is **no summary endpoint**, no computed budget usage and no search parameter. Those were sums and substring matches over plaintext. Clients compute them after decrypting; `@ownspce/money-core` is the reference implementation.

The money surface hangs off `/money` rather than extending `/spaces/{spaceID}`, because chi mounts a subrouter over an entire subtree and a second mount on that node panics at boot.

## Sealed payloads

Every `ciphertext` field is base64 of:

```
nonce(24) || XChaCha20-Poly1305(padded_plaintext) || tag(16)
```

with `AAD = space_id_bytes || uint32_be(key_epoch)`, exactly as `docs/client-crypto.md` specifies for Tier 2. The binding is what stops a row being lifted from one household into another, or replayed under an old key after a rotation.

**Padding is mandatory and enforced.** Money uses its own bucket ladder, shorter than the Tier 2 one because a ledger row is a handful of numbers rather than a note body:

```
buckets     = [256, 1024, 4096]
padded_len  = smallest bucket >= len(plaintext) + 1     # ISO 7816-4 marker byte
wire_length = padded_len + 40                           # 24B nonce + 16B tag
```

Anything else is rejected with `413 bucket_violation`. A ciphertext length that tracked content length would say plenty on its own: forty bytes is a cup of coffee, three hundred is rent with a note explaining the increase.

## Households

A money household **is** a space. Membership, roles (`owner` / `editor` / `viewer`) and removal are already solved there, and a family that shares notes and a ledger should be one thing to leave, not two.

Read needs `viewer`, write needs `editor`, and settings, invites and key grants need `owner`.

### GET /money/households

Every household the caller belongs to, with the space key wrapped for the **calling device**.

```json
{ "households": [ { "spaceId": "…", "role": "owner", "keyEpoch": 1,
                    "memberCount": 3, "vaultVersion": 4, "wrappedKey": "…" } ] }
```

A `wrappedKey` of `null` means this device has not been given the key for that household yet. It is a waiting state, not an error, and clients should render it as one — an empty ledger in its place reads as lost data.

### POST /money/households

Creates a household in one call: the space, the owner's membership, the space key wrapped for the owner's devices, and the sealed settings document.

```json
{ "spaceId": "<client-minted uuid>",
  "wrappedKeys": [ { "deviceId": "…", "wrappedKey": "…" },
                   { "deviceId": null, "wrappedKey": "…" } ],
  "ciphertext": "…" }
```

The id is **minted by the client**, not the server. The settings document binds it into its AAD, so it has to exist before the document does. A duplicate is `409 space_exists`.

A `deviceId` of `null` wraps to the account recovery key. Include it whenever the account has one: a household created without it can only ever be reopened from a device that already holds the key, and by the time that matters, every such device is gone.

If no wrapped key matches an active device of the caller, the whole thing rolls back with `400` rather than leaving behind a household nobody can open.

→ `201 { "spaceId", "role": "owner", "keyEpoch": 1, "memberCount": 1, "vaultVersion": 1 }`

### POST /money/households/{spaceID}/enable

Adds a ledger to a space that already exists, so a household that already shares notes does not end up with a second membership list to keep in sync. Space owner only.

```json
{ "keyEpoch": 3, "ciphertext": "…" }
```

`keyEpoch` must be the space's current epoch. Already enabled, or a stale epoch → `409 already_enabled_or_stale_epoch`.

## The vault document

One sealed blob per household holding its name, currency, locale and rules. Written under optimistic concurrency, because two members editing household rules at the same moment must not silently overwrite each other.

### GET /money/households/{spaceID}/vault

```json
{ "spaceId": "…", "keyEpoch": 1, "version": 4, "ciphertext": "…", "updatedAt": "…" }
```

### PUT /money/households/{spaceID}/vault

```json
{ "version": 4, "keyEpoch": 1, "ciphertext": "…" }
```

`version` is the one you last read. If it has moved on → `409 version_conflict`: re-read, merge, retry.

## The ledger

### GET /money/households/{spaceID}/entries

Query: `from`, `to` (both required, `YYYY-MM-DD`), `limit` (1–500, default 200), `cursor`.

```json
{ "entries": [ { "id": "…", "clientId": "…", "occurredOn": "2026-08-30",
                 "keyEpoch": 1, "ciphertext": "…", "createdBy": "…",
                 "updatedAt": "…" } ],
  "nextCursor": "2026-08-29|<uuid>" }
```

Keyset pagination on `(occurred_on DESC, id DESC)`. An offset pager would let rows repeat or vanish between pages while a household is logging entries. Follow `nextCursor` until it is empty; a partial ledger produces a total that is quietly wrong rather than visibly missing.

### POST /money/households/{spaceID}/entries

Batch upsert, keyed on `clientId`. Up to 200 records, one transaction.

```json
{ "entries": [ { "clientId": "…", "occurredOn": "2026-08-30", "ciphertext": "…" } ] }
```

Batched because the two writes that matter are a CSV import and a reconciliation after being offline, and doing either one row per request turns a hundred entries into a hundred round trips. Upsert because a retry after a dropped response must update the row it already created rather than logging the same dinner twice.

A `clientId` repeated inside one batch is `400`: two upserts of one key inside a transaction wait on each other forever, and a hung request is worse than an error.

→ `200 { "entries": [ … ] }` — the stored rows.

### DELETE /money/households/{spaceID}/entries/{clientID}

Tombstones the row. Idempotent: deleting twice is `204`, because an offline client replaying its queue must not be told its own successful delete failed.

## Categories, accounts, budgets, bills and holdings

All five live in one table and one pair of routes, because they are small, always needed together, and fetching them separately meant five round trips before the first screen could render a category name.

`kind` is one of `category`, `account`, `budget`, `bill`, `holding`.

### GET /money/households/{spaceID}/objects

Query: `kind` (optional; omit for all).

```json
{ "objects": [ { "id": "…", "kind": "category", "clientId": "…", "sortOrder": 0,
                 "keyEpoch": 1, "ciphertext": "…", "updatedAt": "…" } ] }
```

### POST /money/households/{spaceID}/objects

Batch upsert keyed on `(kind, clientId)`. Up to 200 records.

```json
{ "objects": [ { "kind": "category", "clientId": "…", "sortOrder": 0, "ciphertext": "…" } ] }
```

`sortOrder` is plaintext so the server can return records in a stable order without opening them. It carries no meaning beyond position.

### DELETE /money/households/{spaceID}/objects/{kind}/{clientID}

Tombstones the record. Idempotent.

## Collaboration

An invite makes somebody a member. **It does not give them the ledger.** Membership is permission to be handed the key; a member who already holds it has to wrap it for the new member's devices. This is the part most likely to be got wrong, and the part the API is shaped around.

### GET / POST / DELETE /money/households/{spaceID}/invites

Owner only. `POST` takes `{ "email", "role": "editor" | "viewer" }` and returns the plaintext token **once and never again** — only its SHA-256 is stored, so a dump of `money_invites` yields no working links. An address that already has an open invite is `409 invite_exists`. Invites expire after 14 days.

### POST /money/invites/accept

```json
{ "token": "oski_…" }
```

→ `200 { "spaceId": "…", "awaitingKey": true }`

Mounted outside the household router because the caller is by definition not yet a member. The token is the capability; the invite's email is not checked against the caller's, because requiring both would lock out anyone whose Google address differs from the one a family member typed. Expiry and single use are what bound it.

Anything unknown, expired, revoked or already redeemed is `404`, so none of them can be told apart by probing.

### GET /money/households/{spaceID}/key-gaps

Owner only. Everyone in the household holding no wrapped key at the current epoch: each member's active devices, and their account recovery key.

```json
{ "gaps": [ { "userId": "…", "deviceId": "…", "publicKey": "…",
              "name": "Priya", "username": null, "recovery": false } ] }
```

A `deviceId` of `null` with `recovery: true` is the member's account recovery key.

This returns public keys and names — the same material `GET /keys/{userID}` already gives any active device — never anything sealed. **Show the fingerprint before wrapping.** A server that substituted a key here would be handed the household key wrapped for itself, and nothing in software can catch that; only a person comparing fingerprints out of band can.

### POST /money/households/{spaceID}/keys

Owner only. Files keys wrapped for members who had none.

```json
{ "keyEpoch": 1,
  "wrappedKeys": [ { "userId": "…", "deviceId": "…", "wrappedKey": "…" } ] }
```

Deliberately not a rotation: rotation takes access away and demands complete coverage of every remaining device, while this hands access out one member at a time as invitations are accepted. `keyEpoch` must be current, so a grant computed against a key that has since rotated is `409 stale_epoch` rather than a wrap nobody can use.

Postgres enforces that every named device really is an active device of the named member, so a caller cannot file a wrap against somebody else's device — that is `400`.

→ `200 { "granted": 1, "keyEpoch": 1 }`

### Members, rotation and removal

Use the space routes: `GET /spaces/{spaceID}/members`, `DELETE /spaces/{spaceID}/members/{userID}`, `POST /spaces/{spaceID}/keys`. Removing a member revokes future fetches but cannot unlearn the key they already had, so rotate afterwards and write fresh records at the new epoch.

## New devices

`GET /devices`, `POST /devices/{deviceID}/approve` and `GET /devices/{deviceID}/pending-keys` are the same routes the notes client uses, and they cover money households too — a household is a space.

A person's **first** device is active automatically; every later one lands `pending` and holds no key. Two ways out:

- **Approval.** An active device reads `pending-keys`, wraps each space key to the new device's public key after the person compares fingerprints, and calls `approve`.
- **Recovery phrase.** `GET /recovery/spaces` returns the space keys wrapped to the account recovery key. It is the one read a **pending** device may make, because restoring from a phrase is precisely the situation where no device is trusted — and what it returns is useless without the phrase. The device unwraps locally, re-wraps to itself, and calls `approve` on itself with `recovery: true`.

## Errors

Codes specific to this surface:

| Status | Code | Meaning |
|---|---|---|
| 400 | `bad_request` | A malformed field; the message names it. |
| 403 | `device_pending` | Signed in, but this device is not approved. Not an auth failure — do not sign the user out. |
| 403 | `insufficient_role` | The action needs a higher role in this household. |
| 404 | `not_found` | No household here, or the caller is not a member. The two are deliberately indistinguishable. |
| 409 | `space_exists` | That household id is taken; mint a new one. |
| 409 | `version_conflict` | The vault moved on. Re-read and retry. |
| 409 | `stale_epoch` | The household key rotated mid-grant. Refetch the gaps. |
| 413 | `bucket_violation` | The ciphertext is not a padding bucket plus 40 bytes. |

## What the server can still see

Not amounts, categories, notes, budgets, holdings or the household's name. It does see the shape: how many entries a household has, which calendar days they fall on, how many members and devices, and when rows were written. A ledger with one entry a day looks different from one with forty, and no amount of padding hides that.
