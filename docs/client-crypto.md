# Client Crypto Contract

The backend is content-blind, so correctness of the encryption scheme lives entirely in the clients. Every client (iOS, macOS, Android, web, CLI) must implement exactly this, or devices will produce blobs their peers cannot open.

Reference implementation target: **libsodium** (swift-sodium, lazysodium, libsodium-wrappers).

## Primitives

| Purpose | Primitive | Notes |
|---|---|---|
| Device identity | X25519 keypair | Private key never leaves the device (Keychain / Keystore / non-extractable WebCrypto). A new key is a new device. |
| Recovery identity | BIP39 24-word phrase → seed → X25519 keypair | Deterministic; derivation is normative, see below. Only the public half is uploaded (`PATCH /me` → `recoveryPublicKey`). |
| Space key | 32-byte random symmetric key | One per space, per epoch. |
| Payload encryption | XChaCha20-Poly1305 AEAD | 24-byte nonce, 16-byte tag, 40 bytes overhead total. |
| Key wrapping | `crypto_box_seal` (sealed box) to a recipient X25519 public key | ~80 bytes for a 32-byte key. The server stores these and cannot unwrap them. |

**AAD**: bind each payload to its space and epoch — `AAD = space_id_bytes || uint32_be(key_epoch)`. Do **not** put the sequence number in the AAD: the server assigns it after encryption.

**Nonce**: fresh random 24 bytes per payload, prefixed to the ciphertext. Never reuse a nonce under one space key.

**Recovery key derivation** — normative, because a phrase that derives a different key on iOS than in a browser is a recovery that fails at the only moment it was ever needed:

```
seed        = BIP39 mnemonicToSeed(phrase, passphrase = "")     # 64 bytes
private_key = seed[0:32]                                        # X25519 scalar
public_key  = X25519_base(private_key)
```

Normalise the phrase before deriving: trim, lowercase, collapse runs of whitespace to single spaces. Validate the BIP39 checksum first and refuse a phrase that fails it — deriving a key from a mistyped word produces something that looks valid and opens nothing.

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

**Invite**: `GET /keys/:userId` → wrap the space key with `crypto_box_seal` for **every** listed `publicKey` plus `recoveryPublicKey` → `POST /spaces/:id/members` with those wraps.

**Remove a member**: `DELETE …/members/:userId`, then generate a new space key, wrap it for every remaining member device **and** their recovery keys, `POST /spaces/:id/keys` with `newEpoch = current + 1`. Then write a fresh snapshot at the new epoch so old-epoch ciphertext ages out of the log. Rotation is refused unless coverage is complete, so build the list from a fresh key-directory read.

**Verify keys out of band**: show the recipient's public key fingerprint before wrapping. This is the only defence against a malicious server substituting a key in the directory.

## New device provisioning

**Approval by an existing device** — the new device signs in (lands `pending`) and polls `GET /devices` for its own status. An active device sees it, shows the fingerprint for the user to confirm, reads `GET /devices/{id}/pending-keys`, wraps each space key to the new public key, and calls `POST /devices/{id}/approve`.

**Recovery phrase** — the new device signs in (`pending`), the user enters the 24 words, the client derives the recovery keypair, calls **`GET /recovery/spaces`**, unwraps each `recoveryWrappedKey` locally, re-wraps each space key to its own device key, and calls `POST /devices/{id}/approve` on itself with `recovery: true`.

`GET /recovery/spaces` is the one read a pending device may make — restoring from a phrase is precisely the case where no device is trusted — and what it returns is useless without the phrase. `GET /spaces` stays behind device approval.

The self-approval is refused unless the re-wrapped keys **cover every space `GET /recovery/spaces` listed**, and unless the account has a recovery key on file at all. The server cannot check a phrase; it can refuse the trivial lie of claiming recovery and supplying nothing, which is what stops a pending device from activating itself.

Tell the user plainly during onboarding: **all devices lost + phrase lost = data unrecoverable.** There is no server-side copy of any key.

## Publishing

Decrypt the page locally, render HTML + block JSON, upload images via `POST /publish/assets`, then `POST /publish`. This uploads plaintext deliberately and is the only content the server can read. Make the consequence explicit in the publish UI.
