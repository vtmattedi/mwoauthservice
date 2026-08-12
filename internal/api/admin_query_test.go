package api

import (
	"net/http/httptest"
	"testing"
)

func TestParseAuditFilters(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"/admin/api/audit?from=2026-08-01T00:00:00Z"+
			"&to=2026-08-12T23:59:59Z"+
			"&project_id=4"+
			"&status=failed"+
			"&limit=25"+
			"&offset=50",
		nil,
	)

	filters, err := parseAuditFilters(req)
	if err != nil {
		t.Fatal(err)
	}

	if filters.ProjectID == nil || *filters.ProjectID != 4 {
		t.Fatal("project_id was not parsed")
	}
	if filters.Status != "failed" {
		t.Fatalf("status = %q; want failed", filters.Status)
	}
	if filters.Limit != 25 {
		t.Fatalf("limit = %d; want 25", filters.Limit)
	}
	if filters.Offset != 50 {
		t.Fatalf("offset = %d; want 50", filters.Offset)
	}
}

func TestParseAuditFiltersRejectsBadRange(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"/admin/api/audit?from=2026-08-12T00:00:00Z"+
			"&to=2026-08-01T00:00:00Z",
		nil,
	)

	if _, err := parseAuditFilters(req); err == nil {
		t.Fatal("expected invalid date range")
	}
}

func TestParseAuditFiltersCapsLimit(t *testing.T) {
	req := httptest.NewRequest(
		"GET",
		"/admin/api/audit?limit=201",
		nil,
	)

	if _, err := parseAuditFilters(req); err == nil {
		t.Fatal("expected excessive limit to fail")
	}
}
