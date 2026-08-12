package api

import (
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/buildinfo"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

func newAdminRouter(
	service *admin.Service,
	projects *project.Service,
	auditService *audit.Service,
	build buildinfo.Info,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc(
		"POST /admin/api/auth/login",
		AdminLogin(service),
	)

	mux.Handle(
		"GET /admin/api/auth/me",
		service.SessionOnly(
			AdminMe(),
		),
	)

	mux.Handle(
		"POST /admin/api/auth/csrf",
		service.SessionOnly(
			AdminCSRF(service),
		),
	)

	mux.Handle(
		"POST /admin/api/auth/logout",
		service.SessionAndCSRF(
			AdminLogout(service),
		),
	)

	if projects != nil {
		mux.Handle(
			"GET /admin/api/projects",
			service.SessionOnly(
				AdminProjectsList(projects),
			),
		)

		mux.Handle(
			"POST /admin/api/projects",
			service.SessionAndCSRF(
				AdminProjectCreate(projects),
			),
		)

		mux.Handle(
			"PATCH /admin/api/projects/{id}",
			service.SessionAndCSRF(
				AdminProjectUpdate(projects),
			),
		)

		mux.Handle(
			"POST /admin/api/projects/{id}/rotate-key",
			service.SessionAndCSRF(
				AdminProjectRotateAPIKey(projects),
			),
		)

		mux.Handle(
			"POST /admin/api/projects/{id}/rotate-callback-secret",
			service.SessionAndCSRF(
				AdminProjectRotateCallbackSecret(projects),
			),
		)

		mux.Handle(
			"GET /admin/api/projects/{id}/oauth/google",
			service.SessionOnly(
				AdminProjectGoogleConfigGet(projects),
			),
		)

		mux.Handle(
			"PUT /admin/api/projects/{id}/oauth/google",
			service.SessionAndCSRF(
				AdminProjectGoogleConfigPut(projects),
			),
		)
	}

	mux.Handle(
		"GET /admin/api/server",
		service.SessionOnly(
			AdminServer(build),
		),
	)

	mux.Handle(
		"GET /admin/api/docs",
		service.SessionOnly(
			AdminDocsList(),
		),
	)

	mux.Handle(
		"GET /admin/api/docs/{version}",
		service.SessionOnly(
			AdminDocsGet(),
		),
	)

	if auditService != nil {
		mux.Handle(
			"GET /admin/api/audit",
			service.SessionOnly(
				AdminAuditList(auditService),
			),
		)

		mux.Handle(
			"GET /admin/api/audit/{id}",
			service.SessionOnly(
				AdminAuditGet(auditService),
			),
		)

		mux.Handle(
			"GET /admin/api/metrics",
			service.SessionOnly(
				AdminOAuthMetrics(auditService),
			),
		)
	}

	return service.Conceal(
		service.CORS(mux),
	)
}
