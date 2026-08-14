package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

const (
	maxEventTypeLength  = 160
	maxStatusLength     = 64
	maxSeverityLength   = 32
	maxReasonCodeLength = 160
	maxRequestIDLength  = 160
)

var forbiddenMetadataKeys = map[string]struct{}{
	"access_token":       {},
	"refresh_token":      {},
	"authorization_code": {},
	"code":               {},
	"api_key":            {},
	"callback_secret":    {},
	"state":              {},
	"code_verifier":      {},
	"client_secret":      {},
	"token":              {},
	"password":           {},
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Record(
	ctx context.Context,
	event domain.AuditEvent,
) (domain.AuditEvent, error) {
	normalized, err := NormalizeEvent(event)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	stored, err := s.store.InsertAuditEvent(ctx, normalized)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	slog.InfoContext(
		ctx,
		"audit event",
		"event_type", stored.EventType,
		"status", stored.Status,
		"severity", stored.Severity,
		"project_id", stored.ProjectID,
		"transaction_id", stored.TransactionID,
		"request_id", stored.RequestID,
		"reason_code", stored.ReasonCode,
		"http_status", stored.HTTPStatus,
	)

	return stored, nil
}

func (s *Service) List(
	ctx context.Context,
	filters domain.AuditFilters,
) (domain.AuditPage, error) {
	return s.store.ListAuditEvents(ctx, filters)
}

func (s *Service) Get(
	ctx context.Context,
	id int64,
) (domain.AuditEvent, error) {
	return s.store.GetAuditEvent(ctx, id)
}

func (s *Service) Metrics(
	ctx context.Context,
	filters domain.AuditFilters,
) (domain.OAuthMetricsPage, error) {
	return s.store.OAuthMetrics(ctx, filters)
}

func FingerprintAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

// NormalizeEvent validates and removes sensitive audit metadata before storage.
func NormalizeEvent(
	event domain.AuditEvent,
) (domain.AuditEvent, error) {
	event.EventType = strings.TrimSpace(event.EventType)
	event.Status = strings.TrimSpace(event.Status)
	event.Severity = strings.TrimSpace(event.Severity)
	event.TransactionID = strings.TrimSpace(event.TransactionID)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.Method = strings.TrimSpace(event.Method)
	event.Path = strings.TrimSpace(event.Path)
	event.Origin = strings.TrimSpace(event.Origin)
	event.RemoteIP = strings.TrimSpace(event.RemoteIP)
	event.ReasonCode = strings.TrimSpace(event.ReasonCode)

	if event.EventType == "" ||
		len(event.EventType) > maxEventTypeLength {
		return domain.AuditEvent{}, fmt.Errorf(
			"invalid audit event_type",
		)
	}
	if event.Status == "" ||
		len(event.Status) > maxStatusLength {
		return domain.AuditEvent{}, fmt.Errorf(
			"invalid audit status",
		)
	}
	if event.Severity == "" ||
		len(event.Severity) > maxSeverityLength {
		return domain.AuditEvent{}, fmt.Errorf(
			"invalid audit severity",
		)
	}
	if event.RequestID == "" ||
		len(event.RequestID) > maxRequestIDLength {
		return domain.AuditEvent{}, fmt.Errorf(
			"invalid audit request_id",
		)
	}
	if len(event.ReasonCode) > maxReasonCodeLength {
		return domain.AuditEvent{}, fmt.Errorf(
			"invalid audit reason_code",
		)
	}

	if event.AttemptCount <= 0 {
		event.AttemptCount = 1
	}

	event.Metadata = sanitizeMetadata(event.Metadata)

	return event, nil
}

func sanitizeMetadata(
	metadata map[string]any,
) map[string]any {
	if len(metadata) == 0 {
		return map[string]any{}
	}

	sanitized := make(map[string]any, len(metadata))

	for key, value := range metadata {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if _, forbidden := forbiddenMetadataKeys[normalizedKey]; forbidden {
			continue
		}

		sanitized[key] = sanitizeValue(value)
	}

	return sanitized
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return sanitizeMetadata(typed)
	case []any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, sanitizeValue(item))
		}
		return result
	case json.RawMessage:
		return "[redacted-json]"
	default:
		return typed
	}
}
