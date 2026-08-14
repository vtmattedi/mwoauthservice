package federation

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

type Mode string

const (
	ModeLocal     Mode = "local"
	ModeHybrid    Mode = "hybrid"
	ModeFederated Mode = "federated"
)

func ParseMode(raw string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", ModeLocal:
		return ModeLocal, nil
	case ModeHybrid:
		return ModeHybrid, nil
	case ModeFederated:
		return ModeFederated, nil
	default:
		return "", fmt.Errorf("invalid ADMIN_AUTH_MODE %q", raw)
	}
}

type Authenticator struct {
	mode     Mode
	audience string
	client   IntrospectionClient
}

func NewAuthenticator(mode Mode, audience string, client IntrospectionClient) (*Authenticator, error) {
	if mode != ModeLocal && (client == nil || strings.TrimSpace(audience) == "") {
		return nil, fmt.Errorf("federated authentication configuration is required")
	}
	return &Authenticator{mode: mode, audience: strings.TrimSpace(audience), client: client}, nil
}

func (a *Authenticator) Mode() Mode { return a.mode }

// Require selects federated auth whenever Authorization is present. local is
// invoked only when no Authorization header was supplied and the mode permits it.
func (a *Authenticator) Require(requiredScope string, local http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizations := r.Header.Values("Authorization")
		if len(authorizations) == 0 {
			if a.mode == ModeFederated {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			local.ServeHTTP(w, r)
			return
		}

		if a.mode == ModeLocal {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if len(authorizations) != 1 {
			a.logFailure(r.Context(), "federation.token_malformed")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		rawToken, err := parseBearer(strings.TrimSpace(authorizations[0]))
		if err != nil {
			a.logFailure(r.Context(), "federation.token_malformed")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		token, err := a.client.Introspect(r.Context(), rawToken)
		if err != nil || !token.Active || strings.TrimSpace(token.Subject) == "" {
			reason := "federation.introspection_failed"
			if err == nil && !token.Active {
				reason = "federation.token_inactive"
			}
			if err == nil && token.Active && strings.TrimSpace(token.Subject) == "" {
				reason = "federation.subject_missing"
			}
			a.logFailure(r.Context(), reason)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if !contains(token.Audience, a.audience) {
			a.logFailure(r.Context(), "federation.audience_mismatch")
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if !hasScope(token.Scopes, requiredScope) {
			a.logFailure(r.Context(), "federation.scope_missing")
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}

		subject := strings.TrimSpace(token.Subject)
		principal := Principal{
			Source: SourceFederated, IdentitySubject: &subject, Audience: a.audience,
			Scopes: append([]string(nil), token.Scopes...), AuthTime: token.AuthTime,
			AMR: append([]string(nil), token.AMR...),
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
	})
}

func parseBearer(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrMalformedBearer
	}
	return parts[1], nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (a *Authenticator) logFailure(ctx context.Context, reason string) {
	slog.WarnContext(ctx, "federated admin authentication rejected", "reason", reason)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, message)
}
