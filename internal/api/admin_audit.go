package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
)

func AdminAuditList(
	service *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filters, err := parseAuditFilters(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		page, err := service.List(r.Context(), filters)
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not load audit events",
			)
			return
		}

		writeJSON(w, http.StatusOK, page)
	}
}

func AdminAuditGet(
	service *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.PathValue("id"))
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			writeError(w, http.StatusBadRequest, "invalid audit id")
			return
		}

		event, err := service.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, audit.ErrNotFound) {
				writeError(
					w,
					http.StatusNotFound,
					"audit event not found",
				)
				return
			}

			writeError(
				w,
				http.StatusInternalServerError,
				"could not load audit event",
			)
			return
		}

		writeJSON(w, http.StatusOK, event)
	}
}

func AdminOAuthMetrics(
	service *audit.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filters, err := parseAuditFilters(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		metrics, err := service.Metrics(
			r.Context(),
			filters,
		)
		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not load metrics",
			)
			return
		}

		writeJSON(w, http.StatusOK, metrics)
	}
}
