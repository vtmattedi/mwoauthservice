package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	defaultCookieName = "mw_oauth_admin_session"
	sessionTTL        = 7 * 24 * time.Hour
	tokenBytes        = 32
	csrfHeader        = "X-CSRF-Token"
)

var ErrUnauthorized = errors.New("unauthorized")

type Options struct {
	Origins       []string
	CheckSPHost   bool
	SPHost        string
	CookieName    string
	SecureCookies bool
}

type Service struct {
	store         Store
	origins       map[string]struct{}
	checkSPHost   bool
	spHost        string
	cookieName    string
	secureCookies bool
}

type AuthContext struct {
	User    domain.AdminUser
	Session domain.AdminSession
}

type contextKey int

const authContextKey contextKey = iota + 1

func NewService(store Store, opts Options) *Service {
	origins := make(map[string]struct{}, len(opts.Origins))
	for _, origin := range opts.Origins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins[origin] = struct{}{}
		}
	}

	cookieName := strings.TrimSpace(opts.CookieName)
	if cookieName == "" {
		cookieName = defaultCookieName
	}

	return &Service{
		store:         store,
		origins:       origins,
		checkSPHost:   opts.CheckSPHost,
		spHost:        normalizeHost(opts.SPHost),
		cookieName:    cookieName,
		secureCookies: opts.SecureCookies,
	}
}

func (s *Service) Login(
	ctx context.Context,
	email string,
	password string,
) (
	domain.AdminUser,
	string,
	string,
	time.Time,
	error,
) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.store.GetAdminUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return domain.AdminUser{}, "", "", time.Time{}, ErrUnauthorized
		}
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	if !user.Enabled || !VerifyPassword(user.PasswordHash, password) {
		return domain.AdminUser{}, "", "", time.Time{}, ErrUnauthorized
	}

	sessionToken, err := randomToken()
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	csrfToken, err := randomToken()
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(sessionTTL)

	if err := s.store.DeleteExpiredAdminSessions(
		ctx,
		now.Unix(),
	); err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	_, err = s.store.CreateAdminSession(
		ctx,
		user.ID,
		hashToken(sessionToken),
		hashToken(csrfToken),
		expiresAt.Unix(),
	)
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	user.PasswordHash = ""

	return user, sessionToken, csrfToken, expiresAt, nil
}

func (s *Service) RotateCSRF(
	ctx context.Context,
	tokenHash string,
) (string, error) {
	csrfToken, err := randomToken()
	if err != nil {
		return "", err
	}

	if err := s.store.UpdateAdminSessionCSRF(
		ctx,
		tokenHash,
		hashToken(csrfToken),
	); err != nil {
		return "", err
	}

	return csrfToken, nil
}

func (s *Service) Logout(
	ctx context.Context,
	tokenHash string,
) error {
	return s.store.DeleteAdminSession(ctx, tokenHash)
}

func (s *Service) SessionOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, err := s.authenticate(r)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		ctx := context.WithValue(
			r.Context(),
			authContextKey,
			authCtx,
		)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Service) SessionAndCSRF(next http.Handler) http.Handler {
	return s.SessionOnly(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCtx, ok := Current(r.Context())
			if !ok {
				writeAuthError(
					w,
					http.StatusUnauthorized,
					"unauthorized",
				)
				return
			}

			raw := strings.TrimSpace(r.Header.Get(csrfHeader))
			if raw == "" || !constantTokenHashEqual(
				hashToken(raw),
				authCtx.Session.CSRFHash,
			) {
				writeAuthError(
					w,
					http.StatusForbidden,
					"invalid csrf token",
				)
				return
			}

			next.ServeHTTP(w, r)
		}),
	)
}

func (s *Service) Conceal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.checkSPHost {
			if normalizeHost(r.Host) != s.spHost {
				http.NotFound(w, r)
				return
			}
		}

		// Origin concealment protects local browser requests. A server-to-server
		// Authorization request is authenticated by federation middleware.
		if len(s.origins) > 0 && len(r.Header.Values("Authorization")) == 0 {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if _, allowed := s.origins[origin]; !allowed {
				http.NotFound(w, r)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if _, allowed := s.origins[origin]; allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set(
				"Access-Control-Allow-Headers",
				"Content-Type, X-CSRF-Token, X-MW-WebAuthn-Ceremony",
			)
			w.Header().Set(
				"Access-Control-Allow-Methods",
				"GET, POST, PATCH, PUT, DELETE, OPTIONS",
			)
			w.Header().Add("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) SetSessionCookie(
	w http.ResponseWriter,
	token string,
	expiresAt time.Time,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/admin/api",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/admin/api",
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
	})
}

func (s *Service) authenticate(
	r *http.Request,
) (AuthContext, error) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil || cookie.Value == "" {
		return AuthContext{}, ErrUnauthorized
	}

	tokenHash := hashToken(cookie.Value)

	session, err := s.store.GetAdminSessionByTokenHash(
		r.Context(),
		tokenHash,
	)
	if err != nil {
		return AuthContext{}, ErrUnauthorized
	}

	if !session.User.Enabled {
		return AuthContext{}, ErrUnauthorized
	}

	if time.Now().UTC().Unix() >= session.ExpiresAt {
		_ = s.store.DeleteAdminSession(r.Context(), tokenHash)
		return AuthContext{}, ErrUnauthorized
	}

	session.TokenHash = tokenHash
	session.User.PasswordHash = ""

	return AuthContext{
		User:    session.User,
		Session: session,
	}, nil
}

func Current(ctx context.Context) (AuthContext, bool) {
	value, ok := ctx.Value(authContextKey).(AuthContext)
	return value, ok
}

func randomToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func constantTokenHashEqual(a string, b string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(a),
		[]byte(b),
	) == 1
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		return strings.TrimSpace(strings.ToLower(host))
	}

	return strings.TrimSuffix(raw, ".")
}

func writeAuthError(
	w http.ResponseWriter,
	status int,
	message string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(
		w,
		`{"error":%q}`,
		message,
	)
}

func (s *Service) CreateSessionForUser(
	ctx context.Context,
	adminUserID int64,
) (
	domain.AdminUser,
	string,
	string,
	time.Time,
	error,
) {
	user, err := s.store.GetAdminUserByID(
		ctx,
		adminUserID,
	)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return domain.AdminUser{}, "", "", time.Time{}, ErrUnauthorized
		}
		return domain.AdminUser{}, "", "", time.Time{}, err
	}
	if !user.Enabled {
		return domain.AdminUser{}, "", "", time.Time{}, ErrUnauthorized
	}

	sessionToken, err := randomToken()
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	csrfToken, err := randomToken()
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(sessionTTL)

	if err := s.store.DeleteExpiredAdminSessions(
		ctx,
		now.Unix(),
	); err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	_, err = s.store.CreateAdminSession(
		ctx,
		user.ID,
		hashToken(sessionToken),
		hashToken(csrfToken),
		expiresAt.Unix(),
	)
	if err != nil {
		return domain.AdminUser{}, "", "", time.Time{}, err
	}

	user.PasswordHash = ""

	return user, sessionToken, csrfToken, expiresAt, nil
}

func (s *Service) VerifyPasswordForUser(
	ctx context.Context,
	adminUserID int64,
	password string,
) error {
	user, err := s.store.GetAdminUserByID(
		ctx,
		adminUserID,
	)
	if err != nil {
		return ErrUnauthorized
	}

	if !user.Enabled ||
		!VerifyPassword(user.PasswordHash, password) {
		return ErrUnauthorized
	}

	return nil
}
