// MW_OAUTH_STEP_01
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/api"
	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/config"
	"github.com/vtmattedi/mw-oauth-service/internal/delivery"
	"github.com/vtmattedi/mw-oauth-service/internal/envfile"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/providers/google"
	"github.com/vtmattedi/mw-oauth-service/internal/refresh"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

func main() {
	if err := envfile.LoadDevelopment(); err != nil {
		slog.Error(
			"development .env load failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: cfg.LogLevel,
		}),
	)
	slog.SetDefault(logger)

	store, err := sqlite.Open(cfg.DatabasePath)
	if err != nil {
		slog.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			slog.Error("database close failed", "error", err)
		}
	}()

	transactionCipher, err := transactioncrypto.New(
		cfg.TokenEncryptionKey,
	)
	if err != nil {
		slog.Error(
			"transaction encryption configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	callbackSecrets, err := secretbox.NewKeyring(
		cfg.CallbackSecretKeys,
		cfg.CallbackSecretActiveKeyVersion,
	)
	if err != nil {
		slog.Error(
			"callback secret keyring configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	// Every project authorizes with its own Google OAuth client, stored
	// encrypted under this keyring. There is no shared global client, so the
	// keyring is required.
	if cfg.GoogleClientSecretKeys == "" {
		slog.Error(
			"google client secret keyring configuration failed",
			"error", "GOOGLE_CLIENT_SECRET_KEYS is required",
		)
		os.Exit(1)
	}
	for name, other := range map[string]string{
		"CALLBACK_SECRET_KEYS":     cfg.CallbackSecretKeys,
		"WEBAUTHN_CREDENTIAL_KEYS": cfg.WebAuthnCredentialKeys,
		"TOKEN_ENCRYPTION_KEY":     cfg.TokenEncryptionKey,
	} {
		if err := secretbox.EnsureIndependentGoogleCredentialKeys(
			cfg.GoogleClientSecretKeys,
			name,
			other,
		); err != nil {
			slog.Error("google client secret keyring configuration failed", "error", err)
			os.Exit(1)
		}
	}

	googleCredentialKeys, err := secretbox.NewGoogleCredentialKeyring(
		cfg.GoogleClientSecretKeys,
		cfg.GoogleClientSecretActiveKeyVersion,
	)
	if err != nil {
		slog.Error("google client secret keyring configuration failed", "error", err)
		os.Exit(1)
	}

	auditService := audit.NewService(store)

	projectService := project.NewService(
		store,
		callbackSecrets,
	)

	appAuthService := appauth.NewService(store, cfg.AppAccessTokenTTL)

	// Per-project Google clients. A stored credential that cannot be
	// decrypted is reported as unusable; there is no other client to use.
	googleCredentials := googlecred.NewService(store, googleCredentialKeys)

	oauthService, err := oauth.NewService(
		store,
		projectService,
		transactionCipher,
		oauth.Options{
			GoogleRedirectURI: cfg.GoogleRedirectURI,
			Credentials:       googleCredentials,
		},
	)
	if err != nil {
		slog.Error(
			"OAuth service configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	googleProvider, err := google.NewClient(
		google.Options{
			RedirectURI: cfg.GoogleRedirectURI,
		},
	)
	if err != nil {
		slog.Error(
			"Google OAuth provider configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	refreshService, err := refresh.NewService(refresh.Options{
		Credentials: googleCredentials,
		Projects:    projectService,
		Google:      googleProvider,
		Limits:      refresh.DefaultLimits(),
	})
	if err != nil {
		slog.Error("Google refresh configuration failed", "error", err)
		os.Exit(1)
	}

	signedDeliverer, err := delivery.NewSignedDeliverer(
		projectService,
		delivery.Options{},
	)
	if err != nil {
		slog.Error(
			"signed callback delivery configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	callbackService, err := oauth.NewCallbackService(
		store,
		transactionCipher,
		googleProvider,
		signedDeliverer,
		oauth.WithCredentials(googleCredentials),
	)
	if err != nil {
		slog.Error(
			"OAuth callback service configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	adminService := admin.NewService(
		store,
		admin.Options{
			Origins:       cfg.AdminOrigins,
			CheckSPHost:   cfg.CheckSPHost,
			SPHost:        cfg.SPHost,
			CookieName:    cfg.AdminSessionCookie,
			SecureCookies: cfg.AppEnv != "development",
		},
	)

	var introspectionClient federation.IntrospectionClient
	if cfg.AdminAuthMode != federation.ModeLocal {
		client, err := federation.NewClient(federation.ClientOptions{
			BaseURL:      cfg.IdentityInternalBaseURL,
			ClientID:     cfg.IdentityIntrospectionClientID,
			ClientSecret: cfg.IdentityIntrospectionClientSecret,
			Timeout:      cfg.IdentityHTTPTimeout,
		})
		if err != nil {
			slog.Error("Identity introspection configuration failed", "error", err)
			os.Exit(1)
		}
		introspectionClient = client
	}

	federatedAdmin, err := federation.NewAuthenticator(
		cfg.AdminAuthMode,
		cfg.IdentityAudience,
		introspectionClient,
	)
	if err != nil {
		slog.Error("admin federation configuration failed", "error", err)
		os.Exit(1)
	}

	adminWebAuthnService, err := adminwebauthn.NewService(
		store,
		adminwebauthn.Options{
			RPID:                       cfg.WebAuthnRPID,
			RPName:                     cfg.WebAuthnRPName,
			Origins:                    cfg.WebAuthnOrigins,
			CredentialKeys:             cfg.WebAuthnCredentialKeys,
			CredentialActiveKeyVersion: cfg.WebAuthnCredentialActiveKeyVersion,
		},
	)
	if err != nil {
		slog.Error(
			"admin WebAuthn configuration failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	handler := api.NewRouter(api.Dependencies{
		Build:         buildinfo.Current(),
		Health:        store,
		Admin:         adminService,
		AdminWebAuthn: adminWebAuthnService,
		Projects:      projectService,
		Audit:         auditService,
		OAuth:         oauthService,
		OAuthCallback: callbackService,
		AppAuth:       appAuthService,
		Refresh:       refreshService,

		GoogleCredentials: googleCredentials,
		TokenLimits:       api.DefaultTokenLimits(),
		Federation:        federatedAdmin,
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Purge expired MW access tokens in the background until shutdown.
	cleanupCtx, stopCleanup := context.WithCancel(context.Background())
	defer stopCleanup()
	go appAuthService.RunCleanup(
		cleanupCtx,
		appauth.DefaultCleanupInterval,
		appauth.DefaultTokenRetention,
		func(deleted int64, err error) {
			if err != nil {
				slog.Error("expired access token cleanup failed", "error", err)
				return
			}
			if deleted > 0 {
				slog.Info("expired access tokens removed", "count", deleted)
			}
		},
	)

	errCh := make(chan error, 1)

	go func() {
		slog.Info(
			"server starting",
			"service", buildinfo.ServiceName,
			"version", buildinfo.Version,
			"port", cfg.Port,
			"environment", cfg.AppEnv,
		)

		if err := server.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		slog.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		slog.Error("http server failed", "error", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}
