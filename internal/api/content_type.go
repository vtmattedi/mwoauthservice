package api

import (
	"mime"
	"strings"
)

func isJSONContentType(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return false
	}

	return strings.EqualFold(mediaType, "application/json")
}
