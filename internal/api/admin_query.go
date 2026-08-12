package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	adminDefaultLimit = 50
	adminMaxLimit     = 200
)

func parseAuditFilters(
	r *http.Request,
) (domain.AuditFilters, error) {
	query := r.URL.Query()

	filters := domain.AuditFilters{
		Limit: adminDefaultLimit,
	}

	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filters, fmt.Errorf(
				"from must be RFC3339",
			)
		}
		unix := parsed.UTC().Unix()
		filters.FromUnix = &unix
	}

	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filters, fmt.Errorf(
				"to must be RFC3339",
			)
		}
		unix := parsed.UTC().Unix()
		filters.ToUnix = &unix
	}

	if filters.FromUnix != nil &&
		filters.ToUnix != nil &&
		*filters.FromUnix > *filters.ToUnix {
		return filters, fmt.Errorf(
			"from must be before or equal to to",
		)
	}

	if raw := strings.TrimSpace(
		query.Get("project_id"),
	); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			return filters, fmt.Errorf(
				"project_id must be a positive integer",
			)
		}
		filters.ProjectID = &id
	}

	filters.Status = strings.TrimSpace(query.Get("status"))
	if len(filters.Status) > 64 {
		return filters, fmt.Errorf("status is too long")
	}

	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil ||
			value <= 0 ||
			value > adminMaxLimit {
			return filters, fmt.Errorf(
				"limit must be between 1 and %d",
				adminMaxLimit,
			)
		}
		filters.Limit = value
	}

	if raw := strings.TrimSpace(query.Get("offset")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return filters, fmt.Errorf(
				"offset must be zero or greater",
			)
		}
		filters.Offset = value
	}

	return filters, nil
}
