# Client Crypto Contract

The backend is content-blind, so correctness of the encryption scheme lives entirely in the clients. Every client (iOS, macOS, Android, web, CLI) must implement exactly this, or devices will produce blobs their peers cannot open.

Reference implementation target: **libsodium** (swift-sodium, lazysodium, libsodium-wrappers).

## Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Device identity | X25519 keypair | Private key never leaves the device (Keychain / Keystore / non-extractable WebCrypto). A new key is a new device. |
| Account escrow identity | X25519 keypair minted **server-side**, private half sealed under `ESCROW_MASTER_KEY` | Clients only ever see the public half, still delivered as `recoveryPublicKey` for wire compatibility. Clients **cannot** set it; `PATCH /me` accepts and ignores the field. |
| Space key | 32-byte random symmetric key | One per space, per epoch. |
| Payload encryption | XChaCha20-Poly1305 AEAD | 24-byte nonce, 16-byte tag, 40 bytes overhead total. |
| Key wrapping | `crypto_box_seal` (sealed box) to a recipient X25519 public key | ~80 bytes for a 32-byte key. The server stores these and cannot unwrap them. |

**AAD**: bind each payload to its space and epoch — `AAD = space_id_bytes || uint32_be(key_epoch)`. Do **not** put the sequence number in the AAD: the server assigns it after encryption.

**Nonce**: fresh random 24 bytes per payload, prefixed to the ciphertext. Never reuse a nonce under one space key.

**There is no recovery phrase.** It was removed. The account escrow key replaces it: the server mints one per account on first sign-in, wraps nothing itself, and unseals its copy only to re-wrap a space key for a device that has proved the account's email address. Nothing about it is derived on a client, so there is no derivation for clients to agree on.

The consequence is stated in the API README and must be stated in every client's UI: **an operator with the database and the master key can read any space.** Recovery costs one proven email address, and so does compromise.

## Padding buckets — mandatory

Pad the plaintext to a bucket **before** encrypting, so the stored length reveals nothing about the note. The server rejects anything else with `413 bucket_violation`.

```
buckets      = [1024, 4096, 16384, 65536, 262144]
padded_len   = smallest bucket >= len(plaintext)
wire_length  = padded_len + 40          # 24B nonce + 16B tag
```

Use an unambiguous padding scheme (libsodium `sodium_pad` / ISO 7816-4) so the receiver can strip it exactly. A plaintext larger than 262144 bytes must be split across multiple change-sets, or compacted into a snapshot uploaded via `PUT /snapshot/blob`.

**Money records use a shorter ladder.** A ledger row is a handful of numbers and a short note, and the 1 KiB floor above would cost a household with five thousand entries five megabytes to say so:

```
money_buckets = [256, 1024, 4096]
```

Same marker-byte scheme, same `+40` overhead, same `413 bucket_violation` on anything else. Do not use the Tier 2 ladder for money records or the server will reject them.

## What goes in which tier

**Tier 1 — the workspace document** (one sealed blob per space, `PUT /spaces/:id/workspace`): space name, home page name, archive folder name, tag list, page titles, page tree/ordering, pinned pages, per-space preferences. Write it under optimistic concurrency; on `409 version_conflict`, GET, merge locally, retry.

**Tier 2 — the change log** (`POST /spaces/:id/updates`): note bodies, tasks, boards, lane order, matrix scores. One change-set per logical edit, batched.

**Tier 2, money** (`POST /money/households/:id/entries` and `/objects`): every amount, category, note, payer, budget, bill and holding, plus the household's own name and currency in its vault document. One sealed record per row rather than a change log, because a ledger is queried by period and paged, not replayed from the start. The plaintext columns are listed in `docs/money-api.md`; the short version is a space id, a client id, a calendar date and a key epoch. Amounts, categories and notes are **never** Tier 0 fields, and there is no money endpoint that would accept one.

Never send a title, tag, or filename to any Tier 0 field. If a value would help the server index or search, it belongs in Tier 1 or 2.

## Change-set payload

Decrypted, each change-set is a record list the client merges:

```json
{ "records": [
    { "id": "note:9f1c…", "kind": "note", "updatedAt": 1785066343123,
      "deleted": false, "data": { … } } ] }
```

- `updatedAt` is client wall-clock milliseconds and is the **merge input** — it must live inside the ciphertext, because the server cannot read it.
- Merge rule: per record, last-edit-wins on `updatedAt`; break ties with the lexicographically larger `authorDeviceId` (returned alongside each change) so all devices converge on the same winner.
- Deletes are tombstones (`deleted: true`), retained until the next compaction drops them.

## Sync loop

1. On start: `GET /spaces` → per space, unwrap `wrappedKey` with the device private key. A `null` wrappedKey means this device is not yet approved.
2. `GET /spaces/:id/updates?since=<last seq>` every 1–2 s while the space is open, sending `If-None-Match` with the previous `ETag`. Back off when the app is idle or backgrounded.
3. On `resync: true`: load `snapshot` (inline `ciphertext`, or fetch `blobUrl`), decrypt, replace local state, then poll from `nextSince`.
4. Local edits: encrypt, debounce ~2 s, then batch up to 100 change-sets per `POST /updates`. Batching also blunts timing analysis — do not push per keystroke.
5. On `409 stale_epoch`: `GET /spaces` for the new epoch's wrapped key, re-encrypt pending changes at the new epoch, retry.
6. Compaction: when the local log exceeds ~500 change-sets, build a full sealed snapshot and `POST /snapshot` with `uptoSeq` = highest seq included. Inline if it fits a bucket, otherwise `PUT /snapshot/blob` first.

## Collaboration

**Invite**: `GET /keys/:userId` → wrap the space key with `crypto_box_seal` for **every** listed `publicKey` plus the account escrow key returned as `recoveryPublicKey` → `POST /spaces/:id/members` with those wraps.

**Remove a member**: `DELETE …/members/:userId`, then generate a new space key, wrap it for every remaining member device **and** their account escrow keys, `POST /spaces/:id/keys` with `newEpoch = current + 1`. Then write a fresh snapshot at the new epoch so old-epoch ciphertext ages out of the log. Rotation is refused unless coverage is complete, so build the list from a fresh key-directory read.

**Verify keys out of band**: show the recipient's public key fingerprint before wrapping. This is the only defence against a malicious server substituting a key in the directory.

## New device provisioning

**Approval by an existing device** — the new device signs in (lands `pending`) and polls `GET /devices` for its own status. An active device sees it, shows the fingerprint for the user to confirm, reads `GET /devices/{id}/pending-keys`, wraps each space key to the new public key, and calls `POST /devices/{id}/approve`.

**Email code** — the new device signs in (`pending`) and calls **`POST /devices/{id}/verify-email/code`**, which mails six digits to the account's own address. It then calls `POST /devices/{id}/approve` on itself with `{"emailCode": "123456"}` and **no wraps of its own** — the server produces them, by unsealing the account escrow key and re-wrapping every space key it opens.

A code is single-use, expires in ten minutes, is stored only as SHA-256, and is burnt after five wrong guesses. It is bound to the device that asked for it, so one code cannot admit a different device.

`GET /recovery/spaces` is **gone**. The escrow wraps are the server's to hold and are never served to any caller; a route that returned them would hand a pending device the very thing the code exists to gate.

**Sign-in also restores.** When the device registering is the account's only live device it is trusted automatically, as any first device is, and the same escrow re-wrap runs during `POST /auth/session`. That is the lost-every-device path: sign in again, and the ledger is there.

A household whose escrow copy the server cannot open — one created before escrow existed — is skipped rather than failing the activation. The device still gets in; that household lands on the awaiting-key screen, where a member who holds the key can hand it over.

Tell the user plainly: **the mailbox on the account is what guards the ledger.**

## Publishing

Decrypt the page locally, render HTML + block JSON, upload images via `POST /publish/assets`, then `POST /publish`. This uploads plaintext deliberately and is the only content the server can read. Make the consequence explicit in the publish UI.
