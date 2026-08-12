package domain

type AuditEvent struct {
	ID            int64          `json:"id"`
	EventType     string         `json:"event_type"`
	Status        string         `json:"status"`
	Severity      string         `json:"severity"`
	ProjectID     *int64         `json:"project_id,omitempty"`
	TransactionID string         `json:"transaction_id,omitempty"`
	RequestID     string         `json:"request_id"`
	Method        string         `json:"method,omitempty"`
	Path          string         `json:"path,omitempty"`
	HTTPStatus    *int           `json:"http_status,omitempty"`
	Origin        string         `json:"origin,omitempty"`
	RemoteIP      string         `json:"remote_ip,omitempty"`
	ReasonCode    string         `json:"reason_code,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	AttemptCount  int            `json:"attempt_count"`
	CreatedAt     string         `json:"created_at"`
}

type AuditFilters struct {
	FromUnix  *int64
	ToUnix    *int64
	ProjectID *int64
	Status    string
	Limit     int
	Offset    int
}

type Pagination struct {
	Limit   int   `json:"limit"`
	Offset  int   `json:"offset"`
	Count   int   `json:"count"`
	Total   int64 `json:"total"`
	HasMore bool  `json:"has_more"`
}

type AuditPage struct {
	Items      []AuditEvent `json:"items"`
	Pagination Pagination   `json:"pagination"`
}

type OAuthMetricSummary struct {
	Total     int64 `json:"total"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Denied    int64 `json:"denied"`
	Rejected  int64 `json:"rejected"`
}

type OAuthMetricProject struct {
	ProjectID   int64  `json:"project_id"`
	ProjectName string `json:"project_name"`

	Total     int64 `json:"total"`
	Completed int64 `json:"completed"`
	Failed    int64 `json:"failed"`
	Denied    int64 `json:"denied"`
	Rejected  int64 `json:"rejected"`
}

type OAuthMetricsPage struct {
	Summary    OAuthMetricSummary   `json:"summary"`
	Items      []OAuthMetricProject `json:"items"`
	Pagination Pagination           `json:"pagination"`
}
