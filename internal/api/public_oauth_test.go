package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

func TestPublicGoogleAuthorizeRejectsInvalidAPIKeyAndAudits(t *testing.T) {
	store, err := sqlite.Open(
		filepath.Join(t.TempDir(), "oauth.db"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectService := project.NewService(store, nil)

	key := bytes.Repeat([]byte{0x22}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	transactionCipher, err := transactioncrypto.New(encoded)
	if err != nil {
		t.Fatal(err)
	}

	oauthService, err := oauth.NewService(
		store,
		projectService,
		transactionCipher,
		oauth.Options{
			GoogleClientID:    "client-id",
			GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	auditService := audit.NewService(store)

	handler := RequestID(
		PublicGoogleAuthorize(
			oauthService,
			auditService,
		),
	)

	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/oauth/google/authorize",
		bytes.NewReader([]byte(`{}`)),
	)
	req.Header.Set(
		"Authorization",
		"Bearer mw_live_invalid",
	)
	req.Header.Set("Content-Type", "application/json")

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf(
			"status = %d body=%s",
			res.Code,
			res.Body.String(),
		)
	}

	var response publicOAuthErrorResponse
	if err := json.Unmarshal(
		res.Body.Bytes(),
		&response,
	); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "invalid_api_key" {
		t.Fatalf(
			"error code = %q",
			response.Error.Code,
		)
	}

	page, err := auditService.List(
		context.Background(),
		domain.AuditFilters{
			Limit:  50,
			Offset: 0,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if page.Pagination.Total != 1 {
		t.Fatalf(
			"audit total = %d; want 1",
			page.Pagination.Total,
		)
	}
	if page.Items[0].EventType !=
		"oauth.request.rejected.invalid_api_key" {
		t.Fatalf(
			"event type = %q",
			page.Items[0].EventType,
		)
	}
}
