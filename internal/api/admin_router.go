package api

import (
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/adminwebauthn"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/federation"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

func newAdminRouter(
	service *admin.Service,
	webAuthnService *adminwebauthn.Service,
	projects *project.Service,
	auditService *audit.Service,
	build buildinfo.Info,
	federatedAdmin *federation.Authenticator,
	credentials AdminCredentialDeps,
) http.Handler {
	if federatedAdmin == nil {
		federatedAdmin, _ = federation.NewAuthenticator(
			federation.ModeLocal,
			"",
			nil,
		)
	}
	mux := http.NewServeMux()

	localAuthEnabled := federatedAdmin == nil || federatedAdmin.Mode() != federation.ModeFederated
	if localAuthEnabled {
		mux.HandleFunc(
			"POST /admin/api/auth/login",
			adminLocalOnly(federatedAdmin, AdminLogin(service)).ServeHTTP,
		)

		mux.Handle(
			"GET /admin/api/auth/me",
			adminLocalOnly(federatedAdmin, service.SessionOnly(
				AdminMe(),
			)),
		)

		mux.Handle(
			"POST /admin/api/auth/csrf",
			adminLocalOnly(federatedAdmin, service.SessionOnly(
				AdminCSRF(service),
			)),
		)

		mux.Handle(
			"POST /admin/api/auth/logout",
			adminLocalOnly(federatedAdmin, service.SessionAndCSRF(
				AdminLogout(service),
			)),
		)
	}

	if webAuthnService != nil && localAuthEnabled {
		mux.Handle(
			"GET /admin/api/auth/webauthn",
			adminLocalOnly(federatedAdmin, service.SessionOnly(
				AdminWebAuthnList(webAuthnService),
			)),
		)

		mux.Handle(
			"POST /admin/api/auth/webauthn/register/options",
			adminLocalOnly(federatedAdmin, service.SessionAndCSRF(
				AdminWebAuthnRegisterOptions(
					webAuthnService,
					auditService,
				),
			)),
		)

		mux.Handle(
			"POST /admin/api/auth/webauthn/register/verify",
			adminLocalOnly(federatedAdmin, service.SessionAndCSRF(
				AdminWebAuthnRegisterVerify(
					webAuthnService,
					auditService,
				),
			)),
		)

		mux.Handle(
			"DELETE /admin/api/auth/webauthn/{credential_id}",
			adminLocalOnly(federatedAdmin, service.SessionAndCSRF(
				AdminWebAuthnDelete(
					webAuthnService,
					service,
					auditService,
				),
			)),
		)

		mux.HandleFunc(
			"POST /admin/api/auth/webauthn/login/options",
			adminLocalOnly(federatedAdmin, AdminWebAuthnLoginOptions(
				webAuthnService,
				auditService,
			)).ServeHTTP,
		)

		mux.HandleFunc(
			"POST /admin/api/auth/webauthn/login/verify",
			adminLocalOnly(federatedAdmin, AdminWebAuthnLoginVerify(
				webAuthnService,
				service,
				auditService,
			)).ServeHTTP,
		)
	}

	if projects != nil {
		mux.Handle(
			"GET /admin/api/projects",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeProjectsRead, false,
				AdminProjectsList(projects),
			),
		)

		mux.Handle(
			"POST /admin/api/projects",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeProjectsWrite, true,
				AdminProjectCreate(projects),
			),
		)

		mux.Handle(
			"PATCH /admin/api/projects/{id}",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeProjectsWrite, true,
				AdminProjectUpdate(projects),
			),
		)

		mux.Handle(
			"DELETE /admin/api/projects/{id}",
			adminAuthorized(
				federatedAdmin,
				service,
				nil,
				federation.ScopeProjectsDelete,
				true,
				AdminProjectDelete(projects),
			),
		)

		mux.Handle(
			"POST /admin/api/projects/{id}/rotate-callback-secret",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeCredentialsRotate, true,
				AdminProjectRotateCallbackSecret(projects),
			),
		)

		mux.Handle(
			"GET /admin/api/projects/{id}/oauth/google",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopePolicyRead, false,
				AdminProjectGoogleConfigGet(projects),
			),
		)

		mux.Handle(
			"PUT /admin/api/projects/{id}/oauth/google",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopePolicyWrite, true,
				AdminProjectGoogleConfigPut(projects),
			),
		)

		if credentials.AppAuth != nil {
			credentials.Projects = projects
			credentials.Audit = auditService
			registerClientRoutes(mux, federatedAdmin, service, auditService, credentials)
		}
		if credentials.Google != nil {
			credentials.Projects = projects
			credentials.Audit = auditService
			registerGoogleClientRoutes(mux, federatedAdmin, service, auditService, credentials)
		}
		if credentials.Google != nil {
			mux.Handle(
				"GET /admin/api/projects/summary",
				adminAuthorized(federatedAdmin, service, auditService, federation.ScopeProjectsRead, false,
					AdminProjectsSummary(AdminCredentialDeps{
						Projects: projects, Google: credentials.Google,
					}),
				),
			)
		}
	}

	mux.Handle(
		"GET /admin/api/server",
		adminAuthorized(federatedAdmin, service, auditService, federation.ScopeServerRead, false,
			AdminServer(build),
		),
	)

	mux.Handle(
		"GET /admin/api/docs",
		adminAuthorized(federatedAdmin, service, auditService, federation.ScopeServerRead, false,
			AdminDocsList(),
		),
	)

	mux.Handle(
		"GET /admin/api/docs/{version}",
		adminAuthorized(federatedAdmin, service, auditService, federation.ScopeServerRead, false,
			AdminDocsGet(),
		),
	)

	if auditService != nil {
		mux.Handle(
			"GET /admin/api/audit",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeAuditRead, false,
				AdminAuditList(auditService),
			),
		)

		mux.Handle(
			"GET /admin/api/audit/{id}",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeAuditRead, false,
				AdminAuditGet(auditService),
			),
		)

		mux.Handle(
			"GET /admin/api/metrics",
			adminAuthorized(federatedAdmin, service, auditService, federation.ScopeMetricsRead, false,
				AdminOAuthMetrics(auditService),
			),
		)
	}

	return service.Conceal(
		service.CORS(mux),
	)
}

func registerClientRoutes(
	mux *http.ServeMux,
	fed *federation.Authenticator,
	service *admin.Service,
	auditService *audit.Service,
	deps AdminCredentialDeps,
) {
	const base = "/admin/api/projects/{id}/client"

	mux.Handle("GET "+base,
		adminAuthorized(fed, service, auditService, federation.ScopeCredentialsRead, false,
			AdminClientGet(deps)))
	mux.Handle("POST "+base+"/credentials",
		adminAuthorized(fed, service, auditService, federation.ScopeCredentialsRotate, true,
			AdminClientSecretCreate(deps)))
	mux.Handle("DELETE "+base+"/credentials/{credentialID}",
		adminAuthorized(fed, service, auditService, federation.ScopeCredentialsRotate, true,
			AdminClientSecretRevoke(deps)))
	mux.Handle("POST "+base+"/tokens/revoke",
		adminAuthorized(fed, service, auditService, federation.ScopeCredentialsRotate, true,
			AdminClientTokensRevoke(deps)))
}

func registerGoogleClientRoutes(
	mux *http.ServeMux,
	fed *federation.Authenticator,
	service *admin.Service,
	auditService *audit.Service,
	deps AdminCredentialDeps,
) {
	const base = "/admin/api/projects/{id}/oauth/google/client"

	mux.Handle("GET "+base,
		adminAuthorized(fed, service, auditService, federation.ScopeProviderCredentialsRead, false,
			AdminGoogleClientGet(deps)))
	mux.Handle("PUT "+base,
		adminAuthorized(fed, service, auditService, federation.ScopeProviderCredentialsManage, true,
			AdminGoogleClientPut(deps)))
	mux.Handle("GET "+base+"/{credentialRef}/impact",
		adminAuthorized(fed, service, auditService, federation.ScopeProviderCredentialsRead, false,
			AdminGoogleClientImpact(deps)))
	mux.Handle("POST "+base+"/{credentialRef}/retire",
		adminAuthorized(fed, service, auditService, federation.ScopeProviderCredentialsManage, true,
			AdminGoogleClientRetire(deps)))
	mux.Handle("POST "+base+"/{credentialRef}/disable",
		adminAuthorized(fed, service, auditService, federation.ScopeProviderCredentialsManage, true,
			AdminGoogleClientDisable(deps)))
}
