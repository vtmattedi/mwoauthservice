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
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/config"
	"github.com/vtmattedi/mw-oauth-service/internal/delivery"
	"github.com/vtmattedi/mw-oauth-service/internal/envfile"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/providers/google"
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

	auditService := audit.NewService(store)

	projectService := project.NewService(
		store,
		callbackSecrets,
	)

	oauthService, err := oauth.NewService(
		store,
		projectService,
		transactionCipher,
		oauth.Options{
			GoogleClientID:    cfg.GoogleClientID,
			GoogleRedirectURI: cfg.GoogleRedirectURI,
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
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURI:  cfg.GoogleRedirectURI,
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
		Federation:    federatedAdmin,
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

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
