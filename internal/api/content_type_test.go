package api

import "testing"

func TestIsJSONContentType(t *testing.T) {
	accepted := []string{
		"application/json",
		"application/json; charset=utf-8",
		"Application/JSON",
	}

	for _, value := range accepted {
		if !isJSONContentType(value) {
			t.Fatalf("expected %q to be accepted", value)
		}
	}

	rejected := []string{
		"",
		"text/plain",
		"application/x-www-form-urlencoded",
		"not a content type",
	}

	for _, value := range rejected {
		if isJSONContentType(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
