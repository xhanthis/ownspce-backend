// Package httpapi is the entire HTTP surface of the Ownspce API. Handlers move
// ciphertext and Tier 0 metadata; none of them can decrypt anything, and none
// parse a sealed payload.
package httpapi

import (
	"context"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/blob"
	"github.com/ownspce/backend/pkg/config"
	"github.com/ownspce/backend/pkg/ratelimit"
	"github.com/ownspce/backend/pkg/store"
)

// Body size caps. Sealed payloads are bucket-padded, so these are generous
// enough for the largest bucket plus base64 expansion and JSON envelope.
const (
	maxSmallBody    = 1 << 20
	maxSyncBody     = 6 << 20
	maxSnapshotBody = 6 << 20
	maxPublishBody  = 4 << 20
	maxAssetBody    = 5 << 20
)

type Server struct {
	cfg      *config.Config
	store    *store.Store
	limiter  *ratelimit.Limiter
	verifier *auth.Verifier
	signer   *auth.Signer
	blob     *blob.Client
	handler  http.Handler
}

// New wires the server from already-constructed dependencies.
func New(cfg *config.Config, st *store.Store) *Server {
	s := &Server{
		cfg:      cfg,
		store:    st,
		limiter:  ratelimit.New(st.Pool()),
		verifier: auth.NewVerifier(cfg.GoogleClientIDs, cfg.AppleAudiences),
		signer:   auth.NewSigner(cfg.JWTPrivateKey, cfg.JWTPublicKey),
		blob:     blob.New(cfg.BlobToken),
	}
	s.handler = s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(s.cors)

	r.Get("/", s.handleRoot)

	r.Route("/v1", func(r chi.Router) {
		r.Get("/", s.handleRoot)
		r.Get("/health", s.handleHealth)
		r.Get("/.well-known/jwks.json", s.handleJWKS)

		r.Group(func(r chi.Router) {
			r.With(s.rateLimit(ratelimit.AuthSession, subjectIP)).Post("/auth/session", s.handleAuthSession)
			r.With(s.rateLimit(ratelimit.AuthRefresh, subjectIP)).Post("/auth/refresh", s.handleAuthRefresh)
			r.With(s.rateLimit(ratelimit.PublicRead, subjectIP)).Get("/users/{username}", s.handleGetUserByUsername)
			r.With(s.rateLimit(ratelimit.PublicRead, subjectIP)).Get("/public/pages/{username}/{slug}", s.handlePublicPage)
			r.With(s.rateLimit(ratelimit.PublicRead, subjectIP)).Post("/public/pages/{username}/{slug}/report", s.handlePublicReport)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)

			r.Post("/auth/logout", s.handleAuthLogout)
			r.Get("/me", s.handleGetMe)
			r.With(s.rateLimit(ratelimit.ProfileWrite, subjectUser)).Patch("/me", s.handlePatchMe)

			r.Get("/devices", s.handleListDevices)
			r.With(s.rateLimit(ratelimit.DeviceRegister, subjectUser)).Post("/devices", s.handleRegisterDevice)
			r.Get("/devices/{deviceID}/pending-keys", s.handlePendingKeys)
			r.Post("/devices/{deviceID}/approve", s.handleApproveDevice)
			r.Delete("/devices/{deviceID}", s.handleRevokeDevice)

			r.Group(func(r chi.Router) {
				r.Use(s.requireActiveDevice)
				r.With(s.rateLimit(ratelimit.KeyDirectory, subjectUser)).Get("/keys/{userID}", s.handleKeyDirectory)

				r.Get("/spaces", s.handleListSpaces)
				r.With(s.rateLimit(ratelimit.SpaceWrite, subjectUser)).Post("/spaces", s.handleCreateSpace)

				r.Route("/spaces/{spaceID}", func(r chi.Router) {
					r.With(s.requireSpaceRole(store.RoleViewer)).Get("/members", s.handleListMembers)
					r.With(s.requireSpaceRole(store.RoleOwner), s.rateLimit(ratelimit.SpaceWrite, subjectUser)).Post("/members", s.handleAddMember)
					r.With(s.requireSpaceRole(store.RoleViewer), s.rateLimit(ratelimit.SpaceWrite, subjectUser)).Delete("/members/{userID}", s.handleRemoveMember)
					r.With(s.requireSpaceRole(store.RoleOwner), s.rateLimit(ratelimit.SpaceWrite, subjectUser)).Post("/keys", s.handleRotateSpaceKey)

					r.With(s.requireSpaceRole(store.RoleEditor), s.rateLimit(ratelimit.SyncPush, subjectDevice)).Post("/updates", s.handlePostUpdates)
					r.With(s.requireSpaceRole(store.RoleViewer), s.rateLimit(ratelimit.SyncPull, subjectDevice)).Get("/updates", s.handleGetUpdates)

					r.With(s.requireSpaceRole(store.RoleEditor), s.rateLimit(ratelimit.SnapshotWrite, subjectSpace)).Post("/snapshot", s.handlePostSnapshot)
					r.With(s.requireSpaceRole(store.RoleEditor), s.rateLimit(ratelimit.SnapshotWrite, subjectSpace)).Put("/snapshot/blob", s.handleUploadSnapshotBlob)
					r.With(s.requireSpaceRole(store.RoleViewer)).Get("/snapshot", s.handleGetSnapshot)

					r.With(s.requireSpaceRole(store.RoleViewer)).Get("/workspace", s.handleGetWorkspace)
					r.With(s.requireSpaceRole(store.RoleEditor), s.rateLimit(ratelimit.SyncPush, subjectDevice)).Put("/workspace", s.handlePutWorkspace)
				})

				r.Get("/publish", s.handleListPublishes)
				r.With(s.rateLimit(ratelimit.PublishWrite, subjectUser)).Post("/publish", s.handlePublish)
				r.With(s.rateLimit(ratelimit.PublishWrite, subjectUser)).Post("/publish/assets", s.handlePublishAsset)
				r.Delete("/publish/{slug}", s.handleUnpublish)
			})
		})
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, errNotFound("no such endpoint"))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, apiError{status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "method not allowed for this endpoint"})
	})
	return r
}

// handleRoot answers the bare domain with service metadata instead of a bare
// 404, so anyone who opens api.ownspce.com in a browser can see what this is and
// where to go next. Static strings only — nothing about any user.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"service":     "ownspce-api",
		"description": "Zero-knowledge sync API. The server stores and moves ciphertext only; it cannot read your notes.",
		"env":         s.cfg.Env,
		"endpoints": map[string]string{
			"health": "/v1/health",
			"jwks":   "/v1/.well-known/jwks.json",
			"signIn": "POST /v1/auth/session",
		},
		"docs": s.cfg.PublicSiteOrigin + "/docs/api",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if err := s.store.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "database": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "env": s.cfg.Env})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSON(w, http.StatusOK, s.signer.JWKS())
}

var (
	sharedOnce sync.Once
	sharedSrv  *Server
	sharedErr  error
)

// Shared builds the Server once per serverless instance so warm invocations reuse
// the connection pool and the JWKS cache.
// Args: ctx (used for the initial database connect)
// Returns: process-wide *Server, or the configuration/connect error
func Shared(ctx context.Context) (*Server, error) {
	sharedOnce.Do(func() {
		cfg, err := config.Load()
		if err != nil {
			sharedErr = err
			return
		}
		st, err := store.Shared(ctx, cfg.DatabaseURL)
		if err != nil {
			sharedErr = err
			return
		}
		sharedSrv = New(cfg, st)
	})
	return sharedSrv, sharedErr
}
