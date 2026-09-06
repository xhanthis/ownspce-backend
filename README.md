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

`docs/api.md` is the full endpoint reference. `docs/client-crypto.md` is the contract client teams must implement. `docs/ownspce.postman_collection.json` is an importable Postman collection covering all 33 endpoints — import it plus `docs/ownspce-local.postman_environment.json` to point at a local server.

## Local setup

```bash
cp .env.example .env          # fill in DATABASE_URL and the Google client ids
go run ./cmd/keygen           # paste the two lines into .env
go run ./cmd/migrate up       # uses DATABASE_URL_UNPOOLED
go run ./cmd/dev              # http://localhost:5001/v1
curl localhost:5001/v1/health
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

Live at **https://api.ownspce.com/v1** (Vercel project `ownspce-backend`, scope `xhanthis-projects`), also reachable at `https://ownspce-backend.vercel.app/v1`.

```bash
vercel --prod                                   # build + deploy
./scripts/smoke.sh https://api.ownspce.com/v1   # unauthenticated surface
go run ./cmd/e2e                                # full encrypted sync cycle, needs DATABASE_URL + JWT_PRIVATE_KEY
```

Production env vars already set: `DATABASE_URL` (pooled Neon), `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `GOOGLE_CLIENT_IDS`, `PUBLIC_SITE_ORIGIN`, `ENV=production`, `BLOB_READ_WRITE_TOKEN` (store `ownspce-blob-api`). `APPLE_BUNDLE_ID` is unset until Apple Sign-In is registered — until then that provider returns `503 unavailable` and Google works normally.

`ALLOWED_ORIGINS` is the browser CORS allowlist beyond the public site. `PUBLIC_SITE_ORIGIN` (`https://ownspce.com`) is always included automatically and is now also where the web client lives, so this only needs the other surfaces — `https://money.ownspce.com`, and `https://app.ownspce.com` for as long as the old hostname is still reachable. Any `http://localhost` origin is accepted outside production. The web client also needs its Google **Web** OAuth client id added to `GOOGLE_CLIENT_IDS`, with `https://ownspce.com` as an authorised JavaScript origin.

`SESSION_COOKIE_DOMAIN` and `SESSION_ORIGINS` turn on the cross-surface session — one sign-in across the app and Money. **Both must be set or the feature is silently off**, and each surface asks for its own sign-in:

```bash
vercel env add SESSION_COOKIE_DOMAIN production   # ownspce.com
vercel env add SESSION_ORIGINS production         # https://ownspce.com,https://money.ownspce.com
```

See `docs/api.md` for why that list must stay shorter than the CORS allowlist, and for the sandbox rule that published pages depend on.

Three deployment facts worth knowing before changing anything:

- `api/index.go` must be **`package handler`**, and the packages it imports must not live under `internal/` — the Vercel Go builder compiles `api/` as a synthetic module, so `internal/` would be unreachable. That is why shared code sits in `pkg/`.
- Vercel Deployment Protection (SSO) is **off** for this project. It is on by default and makes every route answer `302` to a login page, which would break the API for clients.
- Migrations are not run by the deploy. Run `go run ./cmd/migrate up` against `DATABASE_URL_UNPOOLED` (see `.github/workflows/ci.yml`).

### DNS and TLS for api.ownspce.com

`ownspce.com` uses GoDaddy nameservers, so records are managed at the registrar. `api` points at Vercel (`CNAME → 8049648088092b2f.vercel-dns-017.com`) and the domain is verified on this project.

If the domain ever serves the wrong app or an invalid certificate, it is stale edge state from a previous owner of the hostname, not a DNS problem. Confirm the domain is attached and configured, then force certificate issuance:

```bash
vercel domains inspect api.ownspce.com
vercel certs issue api.ownspce.com
echo | openssl s_client -connect api.ownspce.com:443 -servername api.ownspce.com 2>/dev/null \
  | openssl x509 -noout -subject     # expect CN=api.ownspce.com
```

Public pages are served at `ownspce.com/@username/slug`, by the same frontend project that serves the marketing page and the app; it reads `GET /v1/public/pages/:username/:slug` from this API and streams the HTML blob.

That page is HTML somebody else wrote, on an origin that holds the `os_session` cookie. It **must** be rendered inside an `<iframe sandbox>` without `allow-same-origin` — see `docs/api.md`. Nothing serves it today; this is the constraint on whoever builds it.

## Build order

Each stage is independently deployable, and this is the order the code is organized in:

1. **Tier 0** — auth, profile, devices, key directory (`internal/auth`, `httpapi/auth.go`, `profile.go`, `devices.go`)
2. **Encrypted change log + sync** — spaces, append/poll, snapshots, compaction (`httpapi/sync.go`, `store/sync.go`)
3. **Tier 1 workspace doc** — sealed page tree under optimistic concurrency
4. **Collaboration** — members, wrapped keys, epoch rotation, device approval (`httpapi/spaces.go`, `store/spaces.go`)
5. **Publishing** — the one readable surface, with quotas and moderation intake (`httpapi/publish.go`)
