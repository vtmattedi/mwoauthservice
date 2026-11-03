package audit

import "testing"

func TestSanitizeMetadataRemovesSecrets(t *testing.T) {
	sanitized := sanitizeMetadata(map[string]any{
		"safe":          "value",
		"access_token":  "secret",
		"refresh_token": "secret",
		"nested": map[string]any{
			"code_verifier": "secret",
			"detail":        "ok",
		},
	})

	if sanitized["safe"] != "value" {
		t.Fatal("safe metadata disappeared")
	}

	if _, exists := sanitized["access_token"]; exists {
		t.Fatal("access_token was not removed")
	}

	nested, ok := sanitized["nested"].(map[string]any)
	if !ok {
		t.Fatal("nested metadata missing")
	}

	if _, exists := nested["code_verifier"]; exists {
		t.Fatal("nested code_verifier was not removed")
	}
	if nested["detail"] != "ok" {
		t.Fatal("safe nested metadata disappeared")
	}
}
