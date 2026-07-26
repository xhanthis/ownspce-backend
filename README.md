# Ownspce Backend

Zero-knowledge sync backend for Ownspce. Go on Vercel serverless functions, Neon Postgres, Vercel Blob. The server stores and moves **ciphertext only** — it can never read a user's notes, tasks, or boards.

## The rule everything else follows

The server is a content-blind relay. It orders, stores, and authorizes access to sealed blobs. It never parses content. Two identities keep that true:

| Identity | Source | Decides | Recoverable |
|---|---|---|---|
| Auth | Google/Apple ID token → our JWT | what a user may **fetch** | yes |
| Encryption | X25519 keypair generated on-device | what a user may **decrypt** | only via recovery phrase |

A stolen Google account yields a session and a pile of ciphertext. Losing every device **and** the recovery phrase means the data is gone — by design, with no admin unlock.

### Data tiers

| Tier | Storage | Contents |
|---|---|---|
| 0 — readable | real columns | user id, email, name, username, avatar, plan, device **public** keys, space ids, membership, roles, streak, theme, language, notification toggles |
| 1 — sealed | `workspace_docs.ciphertext` | home page name, archive folder name, tags, page titles + tree, pinned pages, per-space preferences |
| 2 — sealed | `space_changes.ciphertext`, `space_snapshots` | note bodies, tasks, boards, lane order, matrix scores |

No plaintext titles, no readable tags, no content-derived object names, and every sealed payload is padded into a size bucket before encryption so stored lengths leak nothing.

## Layout

```
api/index.go              single Vercel entrypoint; vercel.json rewrites every path here
internal/httpapi/         router, middleware, handlers (auth, profile, devices, spaces, sync, publish)
internal/auth/            Google/Apple ID-token verification, Ed25519 session tokens
internal/store/           every SQL statement in the project
internal/seal/            the server's only content knowledge: permitted ciphertext SHAPE
internal/blob/            Vercel Blob client for large sealed snapshots + published assets
internal/ratelimit/       Postgres fixed-window limiter (no Redis in this stack)
internal/config/          environment loading and validation
db/migrations/            embedded golang-migrate SQL
cmd/migrate               apply migrations (no CLI install needed)
cmd/dev                   run the same router on localhost
cmd/keygen                generate the Ed25519 session keypair
```

`docs/api.md` is the full endpoint reference. `docs/client-crypto.md` is the contract client teams must implement.

## Local setup

```bash
cp .env.example .env          # fill in DATABASE_URL and the Google client ids
go run ./cmd/keygen           # paste the two lines into .env
go run ./cmd/migrate up       # uses DATABASE_URL_UNPOOLED
go run ./cmd/dev              # http://localhost:8080/v1
curl localhost:8080/v1/health
```

`DATABASE_URL` must be the Neon **pooled** (PgBouncer) URL — serverless functions would otherwise exhaust connections. Migrations use `DATABASE_URL_UNPOOLED`, because transaction pooling breaks the advisory locks golang-migrate relies on.

## Tests

```bash
go vet ./...
go test ./...                                  # unit tests only; DB tests skip
OWNSPCE_TEST_DB=1 go test -race ./... -count=1 # full suite against Neon
```

The integration suite creates its own users and deletes them afterwards (deletion cascades to devices, spaces, logs, and publishes). Point it at a Neon branch if you don't want writes on the main database.

`go build ./...` fails on `./api` with "function main is undeclared" — expected. The Vercel Go runtime generates the `main` shim around the exported `Handler`. Build `./internal/... ./cmd/...` locally and let `go vet ./...` cover the entrypoint.

## Deploy

1. Link the repo to a Vercel project and add `api.ownspce.com` as a domain.
2. Set env vars from `.env.example` in Vercel (all environments): `DATABASE_URL`, `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `GOOGLE_CLIENT_IDS`, `APPLE_BUNDLE_ID`, `BLOB_READ_WRITE_TOKEN`, `PUBLIC_SITE_ORIGIN`, `ENV=production`.
3. Create a Vercel Blob store and copy its token in. Without it, snapshot-blob upload and publishing return `503` and everything else works.
4. Run `go run ./cmd/migrate up` against `DATABASE_URL_UNPOOLED` on deploy (see `.github/workflows/ci.yml`).

Public pages are served by the separate **ownspce.com** frontend project at `/@username/slug`; it reads `GET /v1/public/pages/:username/:slug` from this API and streams the HTML blob.

## Build order

Each stage is independently deployable, and this is the order the code is organized in:

1. **Tier 0** — auth, profile, devices, key directory (`internal/auth`, `httpapi/auth.go`, `profile.go`, `devices.go`)
2. **Encrypted change log + sync** — spaces, append/poll, snapshots, compaction (`httpapi/sync.go`, `store/sync.go`)
3. **Tier 1 workspace doc** — sealed page tree under optimistic concurrency
4. **Collaboration** — members, wrapped keys, epoch rotation, device approval (`httpapi/spaces.go`, `store/spaces.go`)
5. **Publishing** — the one readable surface, with quotas and moderation intake (`httpapi/publish.go`)
