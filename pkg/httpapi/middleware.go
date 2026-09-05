package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/ratelimit"
	"github.com/ownspce/backend/pkg/store"
)

type ctxKey int

const (
	ctxKeyCaller ctxKey = iota
	ctxKeyRole
	ctxKeyDaemon
)

// caller is the authenticated identity of a request: which user, and critically
// which device, since encryption keys and revocation are both per-device.
type caller struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID
	Status   string
}

func callerFrom(ctx context.Context) caller {
	c, _ := ctx.Value(ctxKeyCaller).(caller)
	return c
}

func roleFrom(ctx context.Context) string {
	role, _ := ctx.Value(ctxKeyRole).(string)
	return role
}

// daemonCaller is the authenticated identity of a paired local agent. It carries
// the owning user so daemon routes can scope every query without a second lookup.
type daemonCaller struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Name      string
	CreatedAt time.Time
}

func daemonFrom(ctx context.Context) daemonCaller {
	d, _ := ctx.Value(ctxKeyDaemon).(daemonCaller)
	return d
}

// daemonTokenPattern is checked before any database hit, so a user JWT or a
// mistyped secret on a daemon route costs nothing but a string match.
var daemonTokenPattern = regexp.MustCompile(`^ospd_[A-Za-z0-9_-]{43}$`)

// requireDaemon authenticates a paired daemon by its opaque token, re-reading the
// row on every request so revoking a daemon takes effect immediately rather than
// at some expiry. It performs no writes: liveness is stamped by register and
// claim instead, which halves the write volume of a five-second poll.
func (s *Server) requireDaemon(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, errUnauthorized("missing bearer token"))
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if !daemonTokenPattern.MatchString(raw) {
			writeError(w, errUnauthorized("daemon token is not valid or has been revoked"))
			return
		}

		daemon, err := s.store.DaemonByToken(r.Context(), raw)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, errUnauthorized("daemon token is not valid or has been revoked"))
				return
			}
			writeError(w, err)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyDaemon, daemonCaller{ID: daemon.ID, UserID: daemon.UserID, Name: daemon.Name, CreatedAt: daemon.CreatedAt})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAuth verifies the bearer access token and re-checks the device row on
// every request, which is what makes device revocation take effect immediately
// instead of at token expiry.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, errUnauthorized("missing bearer token"))
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if raw == "" {
			writeError(w, errUnauthorized("missing bearer token"))
			return
		}

		verified, err := s.signer.Verify(raw)
		if err != nil {
			writeError(w, errUnauthorized("access token is not valid"))
			return
		}

		device, err := s.store.LiveDevice(r.Context(), verified.DeviceID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, errUnauthorized("device has been revoked"))
				return
			}
			writeError(w, err)
			return
		}
		if device.UserID != verified.UserID {
			writeError(w, errUnauthorized("token does not match device owner"))
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyCaller, caller{UserID: verified.UserID, DeviceID: verified.DeviceID, Status: device.Status})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireActiveDevice blocks pending devices from every data path. A pending
// device can authenticate (it must, to poll for approval) but holds no space key
// and is denied ciphertext until an existing device or the recovery phrase
// activates it.
func (s *Server) requireActiveDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callerFrom(r.Context()).Status != store.DeviceStatusActive {
			writeError(w, errForbidden("device_pending", "this device is awaiting approval from an existing device or the recovery phrase"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSpaceRole authorizes a space-scoped route, resolving the caller's
// membership role once and putting it in the request context.
func (s *Server) requireSpaceRole(minRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
			if err != nil {
				writeError(w, err)
				return
			}

			role, err := s.store.SpaceRole(r.Context(), spaceID, callerFrom(r.Context()).UserID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeError(w, errNotFound("space not found"))
					return
				}
				writeError(w, err)
				return
			}
			if !store.RoleAtLeast(role, minRole) {
				writeError(w, errForbidden("insufficient_role", fmt.Sprintf("this action requires the %s role", minRole)))
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRole, role)))
		})
	}
}

// subjectFunc derives the rate-limit subject for a request.
type subjectFunc func(*http.Request) string

func subjectIP(r *http.Request) string { return clientIP(r) }

func subjectDevice(r *http.Request) string {
	return callerFrom(r.Context()).DeviceID.String()
}

func subjectUser(r *http.Request) string {
	return callerFrom(r.Context()).UserID.String()
}

func subjectSpace(r *http.Request) string { return chi.URLParam(r, "spaceID") }

func subjectDaemon(r *http.Request) string { return daemonFrom(r.Context()).ID.String() }

// rateLimit enforces a rule, failing open if the limiter itself errors so a
// limiter outage cannot take down the API.
func (s *Server) rateLimit(rule ratelimit.Rule, subject subjectFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, err := s.limiter.Allow(r.Context(), rule, subject(r))
			if err != nil {
				log.Printf("rate limiter unavailable for %s: %v", rule.Name, err)
			} else if !result.Allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(result.RetryAfter.Seconds())+1))
				writeError(w, apiError{status: http.StatusTooManyRequests, Code: "rate_limited", Message: "too many requests, slow down"})
				return
			}
			if rand.Intn(100) == 0 {
				go func() { _ = s.limiter.Sweep(context.Background()) }()
			}
			next.ServeHTTP(w, r)
		})
	}
}

// cors allows the app origins to call the API from a browser.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match, X-Device-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed matches a browser Origin against the configured allowlist:
// PUBLIC_SITE_ORIGIN plus anything in ALLOWED_ORIGINS, which is how the web app
// at app.ownspce.com is permitted alongside the marketing site. Outside
// production, any localhost origin is allowed so cmd/dev works with a local
// Vite server.
func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	if !s.cfg.IsProduction() && strings.HasPrefix(origin, "http://localhost") {
		return true
	}
	return false
}

// securityHeaders sets conservative defaults; the API returns JSON only.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if idx := strings.IndexByte(fwd, ','); idx > 0 {
			return strings.TrimSpace(fwd[:idx])
		}
		return strings.TrimSpace(fwd)
	}
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	host := r.RemoteAddr
	if idx := strings.LastIndexByte(host, ':'); idx > 0 {
		host = host[:idx]
	}
	return host
}
