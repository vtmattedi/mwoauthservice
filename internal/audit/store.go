package audit

import (
	"context"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

type Store interface {
	InsertAuditEvent(
		ctx context.Context,
		event domain.AuditEvent,
	) (domain.AuditEvent, error)

	ListAuditEvents(
		ctx context.Context,
		filters domain.AuditFilters,
	) (domain.AuditPage, error)

	GetAuditEvent(
		ctx context.Context,
		id int64,
	) (domain.AuditEvent, error)

	OAuthMetrics(
		ctx context.Context,
		filters domain.AuditFilters,
	) (domain.OAuthMetricsPage, error)
}
