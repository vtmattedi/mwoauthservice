package api

import (
	"net/http"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
)

func newAdminRouter(service *admin.Service) http.Handler {
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

	return service.Conceal(
		service.CORS(mux),
	)
}
