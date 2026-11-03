package sqlite

import (
	"context"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/audit"
	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

func TestAuditPaginationAndMetrics(t *testing.T) {
	store, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	projectRow, err := store.CreateProject(
		context.Background(),
		testProjectRecord("Audit Project"),
	)
	if err != nil {
		t.Fatal(err)
	}

	projectID := projectRow.ID
	status200 := 200

	service := audit.NewService(store)

	for _, status := range []string{
		"completed",
		"failed",
		"denied",
		"rejected",
	} {
		_, err := service.Record(
			context.Background(),
			domain.AuditEvent{
				EventType:    "oauth.test",
				Status:       status,
				Severity:     "info",
				ProjectID:    &projectID,
				RequestID:    "req_" + status,
				HTTPStatus:   &status200,
				AttemptCount: 1,
				Metadata: map[string]any{
					"safe":         "value",
					"access_token": "must-not-store",
				},
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	page, err := service.List(
		context.Background(),
		domain.AuditFilters{
			ProjectID: &projectID,
			Limit:     2,
			Offset:    0,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if page.Pagination.Total != 4 {
		t.Fatalf(
			"audit total = %d; want 4",
			page.Pagination.Total,
		)
	}
	if page.Pagination.Count != 2 {
		t.Fatalf(
			"audit count = %d; want 2",
			page.Pagination.Count,
		)
	}
	if !page.Pagination.HasMore {
		t.Fatal("expected has_more=true")
	}

	if _, exists := page.Items[0].Metadata["access_token"]; exists {
		t.Fatal("forbidden metadata was persisted")
	}

	metrics, err := service.Metrics(
		context.Background(),
		domain.AuditFilters{
			ProjectID: &projectID,
			Limit:     50,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if metrics.Summary.Total != 4 {
		t.Fatalf(
			"metric total = %d; want 4",
			metrics.Summary.Total,
		)
	}
	if metrics.Summary.Completed != 1 ||
		metrics.Summary.Failed != 1 ||
		metrics.Summary.Denied != 1 ||
		metrics.Summary.Rejected != 1 {
		t.Fatalf(
			"unexpected metric summary: %+v",
			metrics.Summary,
		)
	}
}

func testProjectRecord(name string) project.CreateRecord {
	return project.CreateRecord{
		Name:                     name,
		Enabled:                  true,
		CallbackSecretCiphertext: "ciphertext",
		CallbackSecretNonce:      "nonce",
		CallbackSecretKeyVersion: 1,
	}
}
