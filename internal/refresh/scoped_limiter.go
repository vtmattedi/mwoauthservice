package refresh

import (
	"sync"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
)

// ScopedLimiter keeps a separate bounded limiter for every project. When a
// limiter's key space is exhausted its overflow bucket is shared by the keys
// of that one project only, so one project flooding it with junk keys cannot
// throttle another project's refreshes.
//
// Scopes are created only for authenticated, existing projects, so the number
// of scopes is bounded by the number of projects.
type ScopedLimiter struct {
	limit   int
	window  time.Duration
	maxKeys int

	mu     sync.Mutex
	scopes map[int64]*appauth.Limiter
}

// NewScopedLimiter allows limit events per key per window inside each
// project, tracking at most maxKeys keys per project.
func NewScopedLimiter(limit int, window time.Duration, maxKeys int) *ScopedLimiter {
	return &ScopedLimiter{
		limit:   limit,
		window:  window,
		maxKeys: maxKeys,
		scopes:  make(map[int64]*appauth.Limiter),
	}
}

// Allow records one event for key inside projectID's scope.
func (l *ScopedLimiter) Allow(projectID int64, key string) (bool, time.Duration) {
	return l.scope(projectID).Allow(key)
}

func (l *ScopedLimiter) scope(projectID int64) *appauth.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, ok := l.scopes[projectID]
	if !ok {
		limiter = appauth.NewLimiter(l.limit, l.window, l.maxKeys)
		l.scopes[projectID] = limiter
	}
	return limiter
}
