# Login flow

How somebody gets from "not signed in" to "reading their own encrypted data", across
`api.ownspce.com`, `app.ownspce.com` and `money.ownspce.com`.

Two gates are being removed: device approval, and the household approver. This
document is the design that replaces them.

## The one mechanism

`space_keys` rows with `device_id IS NULL` are the account's **escrow copy** of a
space key — the space key sealed to that user's escrow public key, whose private
half the server holds sealed under `ESCROW_MASTER_KEY` (see `pkg/escrow`).

Everything below is the same move: make sure that row exists as early as
possible, then let `admitDevice()` fan it out to whatever device just signed in.
No new key concept, no new table for keys.

```
                    escrow row (space_keys, device_id NULL)
                                   |
        created by ...             |            ... consumed by
   +---------------------+         |         +--------------------------+
   | createSpace         |         |         | admitDevice() at sign-in |
   | createHousehold     |---------+-------->| rewrapFromEscrow()       |
   | createInvite (new)  |                   | -> space_keys(device_id) |
   +---------------------+                   +--------------------------+
```

## 1. Device approval is gone

`RegisterDevice` inserts `status = 'active'` with `approved_via = NULL`. A device
that has just proved the account — Google, Apple, a mailed code, or the shared
cookie — is trusted from that moment, and `admitDevice()` immediately rewraps
every escrow copy for it.

`approved_via = NULL` now reads as "signed in". Rows carrying the old values stay
as historical record.

**Rollout.** No backfill of `devices.status`. A device left `pending` by the old
flow is cleared by its own next sign-in, which is the only moment the account is
freshly proved. Backfilling would silently activate devices an owner had
deliberately declined to approve.

**What is kept.** `POST /devices/{id}/approve` and `GET /devices/{id}/pending-keys`
stay mounted and working: clients in the wild still call them, and a no-op 404
would break a released app. They become the manual escape hatch for a space with
no escrow copy (one created before escrow existed).

**Trust change, stated plainly.** Account takeover is now data takeover — whoever
can pass Google or receive the mailed code reads the ledger on a new device with
no second factor. The escrow key already meant the server could decrypt any
household, so this does not widen who *can* read; it widens what a stolen inbox
is worth. Accepted deliberately: the alternative stranded anyone who lost every
device on a screen polling a status nothing would ever change.

## 2. The household approver is gone

Today: invite → accept → `awaitingKey: true` → the invitee waits for an owner to
open Money and run `grantKeys`. The invitee is a member who can read nothing.

New: the key is wrapped **at invite time**, to an escrow identity the server
provisions for the invited address.

```
POST /money/households/{spaceID}/invites   { email, role }
  -> server: UpsertUserByEmail(email)            (shell row, no provider sub)
             ensureEscrowKey(shellUser.ID)       (mints the keypair)
  <- 201 { inviteId, token, userId, escrowPublicKey, keyEpoch }

owner's client: wrapped = sealAnonymous(householdKey, escrowPublicKey)

POST /money/households/{spaceID}/invites/{inviteID}/key   { keyEpoch, wrappedKey }
  -> server, one transaction:
       space_members  (space_id, user_id=invitee, role)
       space_keys     (space_id, user_id=invitee, device_id=NULL, wrapped_key)
       money_invites.accepted_at = now()
  <- 204
```

The invitee then just signs in. `UpsertUserByProvider` already adopts an existing
row by email, so Google, Apple and the mailed code all land on the shell row;
`admitDevice()` finds the escrow copy and rewraps it for the new device. The
ledger opens on first paint.

- `POST /money/invites/accept` keeps working for tokens minted before this ships,
  and for the link as a *navigation* affordance. It no longer decides membership.
- `/key-gaps` and `POST .../keys` stay for repair: a member whose escrow row was
  lost to a key rotation still needs an owner to refill it.
- `awaitingKey` is dropped from the accept response, and the `awaiting-key` gate
  from both clients.

**Two-call shape, on purpose.** The server cannot wrap the household key itself —
it does not hold it. So the invite must be created before the owner can wrap, and
the wrap filed afterwards. An invite whose second call never lands is an invite
with no key: it expires like any other, and `/invites` marks it so the owner can
resend rather than leaving the invitee to guess.

**Shell rows.** A pre-provisioned user is an ordinary `users` row with no
`google_sub`/`apple_sub` and no device. It costs one row per invited address.
Consequence to accept: `isNewUser` is `false` on that person's first real
sign-in, so onboarding must key off "has no space" rather than off that flag.

**Consent moves to the exit.** Anyone can type any address into an invite box, so
a person can now find themselves in a household they never agreed to join. Two
things follow and both are required, not optional: every client offers **Leave
this household** to a non-owner, and the client opens **your own** household in
preference to one somebody added you to — the API lists them oldest first, which
would otherwise let a stranger's household become the one the app opens on.

## 3. One session across the surfaces

`app.ownspce.com` and `money.ownspce.com` are one product. Signing in on either
signs in on both.

**Cookie.** `os_session`, set by `/auth/session` and `/auth/refresh`, cleared by
`/auth/logout`:

```
Domain=.ownspce.com; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=<refresh TTL>
```

It carries a refresh token in its own family — never the access token, never
anything a script can read. `api.`, `app.` and `money.` share the registrable
domain, so `SameSite=Lax` still sends it on the sibling XHR, and the CORS
middleware already answers `Access-Control-Allow-Credentials: true`.

**`POST /auth/continue`.** Mounted beside `/auth/session`, unauthenticated,
`credentials: 'include'`. Reads the cookie, rotates it, registers the calling
device's public key against the account it names, admits it, and returns the same
`sessionResponse` every other door returns. Rate-limited as `AuthRefresh`.

**Only app surfaces may spend it.** `SESSION_ORIGINS` names them, and it is a
shorter list than the CORS allowlist on purpose: that list has to include the
origin serving published pages, which is HTML somebody else wrote. One XSS there,
against an endpoint that mints a device from an ambient cookie, would put an
attacker's own device on the victim's account with every space key re-wrapped for
it — and the attacker would not even need to read the response. So the origin is
checked before the cookie is read, and a stranger origin gets `403
origin_not_permitted` and is never handed a cookie in the first place.

A surface with no session of its own tries this once before painting a sign-in
screen. It costs one 401 for a browser that has never signed in anywhere.

**Logout is cross-surface too.** Clearing the cookie on `/auth/logout` is
deliberate: signing out of Money and staying silently signed in on app is worse
than signing out of both.

## 4. The sign-in screen

One screen for sign-in and sign-up. Two doors, neither preferred — email code
and Google — plus a **last used** badge on whichever door this browser used
before (`ownspce.lastDoor` / `ownspce.lastEmail` in `localStorage`, no network),
and a returning-user row when an address is remembered. Apple is left off both
clients until it is registered: a button that fails at the last step is worse
than no button.

Built twice, once per repo, sharing nothing but design tokens. `ownspce-web` is
Vite + React and `ownspce-money` is Next; a shared package across two monorepos
would be more plumbing than the screen it carries.

Gone from the web client with this screen: `PendingDevice`, `RecoverySetup`, the
24-word phrase, and the `device_pending` / `needs_recovery_setup` auth phases.
`AuthPhase` becomes `loading | signed_out | space_locked | ready`, where
`space_locked` is reachable only for a space created before escrow existed —
whose key the server genuinely holds no copy of, and which must be said out loud
rather than rendered as an empty workspace.

## 5. The app switcher

A persistent pill in each surface's header naming the *other* app, in the shape
Zomato uses to cross into District: the current product's mark, the other
product's name, and a swap affordance.

It is a plain `<a href="https://money.ownspce.com">` (and back). No token in the
URL, no handoff parameter — the `.ownspce.com` cookie is the handoff, and
`/auth/continue` spends it. That is the whole reason section 3 comes first.

## Migration

`000012_signed_in_is_the_gate.up.sql`, additive only — 000011's lesson is that a
migration has to be safe to apply *before* the code that needs it ships.

```sql
ALTER TABLE money_invites ADD COLUMN IF NOT EXISTS invitee_user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE money_invites ADD COLUMN IF NOT EXISTS key_filed_at timestamptz;
```

No change to `devices.status`, `space_keys` or `users`. The `pending` value stays
legal in the CHECK constraint so a rollback to the previous binary still starts.

**Rollback.** Drop the two columns. The previous binary reads neither, files
devices as `pending` again, and the escrow rows written in the meantime are
exactly what its own `restoreFromEscrow` already knew how to spend.

## Failure and idempotency

| Step | Retry behaviour |
|---|---|
| `POST /auth/session`, `/auth/continue` | `RegisterDevice` is keyed on the public key, so a retry returns the same device rather than minting a second |
| `admitDevice` | Counts held keys first; a device that already has them costs one query and no escrow open |
| invite key filing | `uq_space_keys` makes the insert idempotent per `(space, epoch, user)`; a replay is a no-op, not a duplicate member |
| escrow open fails | Logged and swallowed — signed in with nothing readable beats not signed in |
| cookie absent or stale | `/auth/continue` answers 401 and the surface paints its sign-in screen |
