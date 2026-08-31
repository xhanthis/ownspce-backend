# Ownspce Money API

Base URL `https://api.ownspce.com/v1`. This document covers the money surface only; `docs/api.md` is the reference for everything else.

## What is different about this surface

Every other data route in this API moves ciphertext. **These routes move readable values.** Budgets, category splits, household settle-up and portfolio valuation are arithmetic performed over the amounts themselves, and a server that cannot read a number cannot add two of them together.

The consequence, stated rather than buried: an operator with database access can read a household's ledger. What still holds is access control — every statement is scoped by space membership, and no money row is reachable without a role on its space.

Two design points follow from this:

- Money routes sit behind `requireAuth` but **not** `requireActiveDevice`. Device approval exists to gate the delivery of wrapped space keys; a money row needs no key to read, so requiring an approved device would lock a returning user out of their own ledger the first time they open the web app while buying no confidentiality the database does not already lack.
- The money surface hangs off `/money` rather than extending `/spaces/{spaceID}`, because chi mounts a subrouter over an entire subtree and a second mount on that node panics at boot.

## Money and amounts

Every amount on the wire is an object, never a decimal:

```json
{ "minor": 248000, "currency": "INR" }
```

`minor` is an integer count of the currency's smallest unit — paise for INR, so `248000` is ₹2,480.00. No float ever crosses the boundary in either direction, so no client can reintroduce a rounding error the server was careful to avoid. Request bodies take the same values as bare integers named `amountMinor`, `limitMinor`, `sipMinor` and so on.

A single entry is capped at `100000000000` minor units (₹1,000,000,000), matching the digit limit the entry keypad enforces.

Dates are calendar dates (`2026-08-31`), never timestamps. An entry belongs to the day the household says it happened and must not slide because a member opened the app from another timezone.

## Households

A money household **is** a space. Membership, roles (`owner` / `editor` / `viewer`) and removal are already solved there, and a family that shares notes and a ledger should be one thing to leave, not two. A space becomes a household the first time money is enabled on it.

Read needs `viewer`, write needs `editor`, and settings and invites need `owner`.

### GET /money/households
Every money-enabled household the caller belongs to.

```json
{ "households": [ { "spaceId": "…", "role": "owner", "memberCount": 3, "currency": "INR",
                    "locale": "en-IN", "sharedByDefault": true,
                    "approvalThreshold": { "minor": 2000000, "currency": "INR" },
                    "monthlyCloseDay": 1 } ] }
```

### POST /money/households/{spaceID}/enable
Owner only. Turns an existing space into a household and seeds the seventeen default categories in the same transaction, so the first entry can be logged without setting anything up. Enabling twice returns the existing settings unchanged — it never resets them or duplicates the seed. → `201`.

### GET · PATCH /money/households/{spaceID}/settings
`PATCH` is owner only and takes any subset of `currency`, `locale`, `sharedByDefault`, `approvalThresholdMinor`, `monthlyCloseDay` (1–28).

## Categories

### GET /money/households/{spaceID}/categories
Query `includeArchived=true` to include retired ones.

```json
{ "categories": [ { "id": "…", "name": "Groceries", "emoji": "🛒", "color": "#5FAF9F",
                    "kind": "expense", "sortOrder": 0, "archived": false } ] }
```

### POST · PATCH /money/households/{spaceID}/categories[/{categoryID}]
`name` 1–40 chars and unique within the household, compared case-insensitively — `Food` and `food` collide with `409 category_exists`. `kind` ∈ `expense | income`. `color` is a six-digit hex. `PATCH` accepts `archived` to retire a category without breaking the entries that reference it.

## Accounts

### GET · POST · PATCH /money/households/{spaceID}/accounts[/{accountID}]
`kind` ∈ `bank | cash | card | wallet | loan | investment`. `currency` defaults to the household's.

## Transactions

### GET /money/households/{spaceID}/transactions
`from` and `to` are **required** inclusive dates. A missing bound would silently scan a household's whole history and return a figure the caller did not ask for, which on a spending total is worse than an error.

| Query | Meaning |
|---|---|
| `from`, `to` | required, `yyyy-mm-dd`, inclusive |
| `scope` | `household` (default) or `mine` — entries this member paid for |
| `search` | matches the note or the category name, case-insensitively |
| `limit` | defaults to 100, clamps at 200 |
| `cursor` | opaque; a malformed value is rejected with `409 invalid_cursor` rather than silently restarting the walk |

```json
{ "transactions": [ { "id": "…", "clientId": "…", "accountId": null, "categoryId": "…",
                      "type": "expense", "amount": { "minor": 248000, "currency": "INR" },
                      "occurredOn": "2026-08-31", "note": "Weekly big shop", "isShared": true,
                      "paidBy": "…", "createdBy": "…", "createdAt": "…", "updatedAt": "…" } ],
  "nextCursor": "" }
```

### POST /money/households/{spaceID}/transactions

```json
{ "clientId": "<uuid minted by the client>", "categoryId": "…", "type": "expense",
  "amountMinor": 248000, "occurredOn": "2026-08-31", "note": "Weekly big shop",
  "isShared": true, "paidBy": "<optional, must be a household member>" }
```

`clientId` is what makes a retry safe: the client mints it once per entry, and resending returns the transaction the first attempt created rather than charging the household twice. A category or account belonging to another household is refused with `403 cross_household`, and a `paidBy` who is not a member is a `400` — otherwise a member could pin their own spending onto a stranger and have it appear in that household's settle-up column.

### PATCH · DELETE /money/households/{spaceID}/transactions/{transactionID}
Delete is a soft delete, and deleting twice is not an error. The row is kept so a member who deletes an entry the rest of the household has already reconciled against leaves a trace, and so a replayed create cannot resurrect it under the same client id.

### GET /money/households/{spaceID}/summary
Every aggregate the insights screen renders, in one round trip — computed in SQL because a household's history is unbounded and paging it to the client only to add it up there gets slower every month.

```json
{ "from": "2026-08-01", "to": "2026-08-31", "currency": "INR",
  "spent": { "minor": 14320000, "currency": "INR" },
  "income": { "minor": 28400000, "currency": "INR" },
  "net": { "minor": 14080000, "currency": "INR" }, "count": 42,
  "categories": [ { "categoryId": "…", "name": "Groceries", "emoji": "🛒", "color": "#5FAF9F",
                    "amount": { "minor": 2480000, "currency": "INR" }, "count": 7 } ],
  "members":    [ { "userId": "…", "name": "Priya",
                    "spent": { "minor": 6400000, "currency": "INR" },
                    "sharedSpent": { "minor": 5100000, "currency": "INR" } } ],
  "days":       [ { "day": "2026-08-01", "amount": { "minor": 320000, "currency": "INR" } } ] }
```

`members` is always the whole household regardless of `scope`, because settle-up needs every payer. `sharedSpent` is the half of it that counts against the household rather than one person, and is what the settlement column divides.

## Budgets

### GET /money/households/{spaceID}/budgets?from=&to=
Returns each ceiling with what has been spent against it over the window.

```json
{ "budgets": [ { "id": "…", "categoryId": "…", "name": "Groceries", "emoji": "🛒",
                 "color": "#5FAF9F", "period": "monthly",
                 "limit":     { "minor": 2400000, "currency": "INR" },
                 "used":      { "minor": 900000,  "currency": "INR" },
                 "remaining": { "minor": 1500000, "currency": "INR" } } ] }
```

`remaining` goes negative when a budget is overrun; that is the signal the screen colours red, not an error.

### PUT · DELETE /money/households/{spaceID}/budgets[/{budgetID}]
`PUT` takes `{categoryId, limitMinor}` and is an upsert — one ceiling per category per period, so re-putting updates rather than duplicating.

## Bills

### GET · POST · PATCH /money/households/{spaceID}/bills[/{billID}]
`dayOfMonth` is 1–28 so a recurring charge lands in every month, February included.

## Holdings

### GET · POST · PATCH /money/households/{spaceID}/holdings[/{holdingID}]
`assetType` ∈ `mutual_fund | stocks | gold | retirement | debt | cash | other`. `units` is a **decimal string** with up to six places — fractional mutual-fund units are normal, and carrying them as a string end to end means no float ever rounds a position. `dayChangeBps` is basis points, so `62` is `+0.62%`; a percentage stored as a float would not survive a round trip.

```json
{ "id": "…", "name": "Nifty 50 Index Fund", "badge": "IDX", "assetType": "mutual_fund",
  "units": "2840.000000",
  "avgCost":    { "minor": 16840,    "currency": "INR" },
  "lastPrice":  { "minor": 21490,    "currency": "INR" },
  "value":      { "minor": 61031600, "currency": "INR" },
  "cost":       { "minor": 47825600, "currency": "INR" },
  "unrealised": { "minor": 13206000, "currency": "INR" },
  "dayChangeBps": 62, "sip": { "minor": 2500000, "currency": "INR" }, "pricedAt": "…" }
```

`value` is `units × lastPrice` computed with exact rationals and rounded once, halves away from zero. A large retirement balance times a six-place unit count exceeds the range where float64 represents consecutive integers, and a portfolio that disagrees with the sum of its own rows is a support ticket. Updating `lastPriceMinor` restamps `pricedAt`, so a stale quote is visible rather than silent.

## Invites

Household invites exist alongside the encrypted product's own member flow rather than reusing it. That flow requires the inviter to wrap a space key for the invitee's devices, which presumes the invitee already has an account and a device key — a household inviting a parent who has never opened the app has neither, and money rows need no key to read.

### GET · POST · DELETE /money/households/{spaceID}/invites[/{inviteID}]
Owner only, because the list is a set of email addresses belonging to people not yet in the account.

`POST {email, role}` where `role` ∈ `editor | viewer` → `201` carrying `token`. **The plaintext token is returned once and is never recoverable** — only its SHA-256 is stored, so a dump of `money_invites` yields no working links. One open invite per address per household; a second is `409 invite_exists`.

### POST /money/invites/accept
`{token}` → `200 {spaceId}`. Mounted outside the household router because the caller is by definition not yet a member, so no space-scoped middleware could authorize them.

The invite's email is deliberately **not** checked against the caller's: the token is the capability, and requiring both would lock out anyone whose Google address differs from the one a family member typed. Expiry (14 days) and single use are what bound it. An unknown, expired, revoked or already-redeemed token all answer `404` identically, so none can be told apart by probing.

## Status codes

Adds to the shared table in `docs/api.md`:

| Status | Code | Meaning |
|---|---|---|
| 403 | `cross_household` | that category or account belongs to another household |
| 409 | `category_exists` | a category with that name already exists here |
| 409 | `invite_exists` | that address already has an open invite |
| 409 | `invalid_cursor` | the paging cursor is unreadable; start the walk again |

`404 not_found` covers a household that does not exist, has money disabled, or that the caller is not a member of — deliberately indistinguishable, so space ids cannot be probed.

## Rate limits

| Route | Limit | Subject |
|---|---|---|
| money reads | 240 / min | user |
| money writes | 120 / min | user |
| POST invites | 20 / hour | user |

## Migration

`db/migrations/000008_money.up.sql` adds eight tables — `money_settings`, `money_accounts`, `money_categories`, `money_transactions`, `money_budgets`, `money_bills`, `money_holdings`, `money_invites` — and touches none of the existing ones. Apply with `go run ./cmd/migrate up` against `DATABASE_URL_UNPOOLED`; the deploy does not run migrations.
