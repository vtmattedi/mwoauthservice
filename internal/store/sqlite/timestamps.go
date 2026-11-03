package sqlite

import (
	"fmt"
	"time"
)

// unixFromTimestamp parses the store's UTC millisecond timestamps.
func unixFromTimestamp(value string) (int64, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	if err != nil {
		return 0, fmt.Errorf("parse timestamp %q: %w", value, err)
	}
	return parsed.Unix(), nil
}
