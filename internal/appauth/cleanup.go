package appauth

import (
	"context"
	"time"
)

const (
	// DefaultCleanupInterval is how often expired tokens are purged.
	DefaultCleanupInterval = 10 * time.Minute
	// DefaultTokenRetention keeps expired tokens briefly after expiry so
	// recent activity can still be explained, then removes them.
	DefaultTokenRetention = time.Hour
)

// RunCleanup deletes expired access tokens every interval until ctx is
// cancelled. report, if set, receives each pass's outcome. It runs one pass
// immediately so a restart after a long outage clears the backlog.
func (s *Service) RunCleanup(
	ctx context.Context,
	interval time.Duration,
	retention time.Duration,
	report func(deleted int64, err error),
) {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}

	pass := func() {
		deleted, err := s.CleanupExpired(ctx, retention)
		if report != nil && ctx.Err() == nil {
			report(deleted, err)
		}
	}

	pass()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pass()
		}
	}
}
