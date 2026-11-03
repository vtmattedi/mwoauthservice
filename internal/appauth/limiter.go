package appauth

import (
	"sync"
	"time"
)

// overflowKey is the shared bucket used once the limiter is tracking its
// maximum number of distinct keys, so attacker-chosen keys cannot grow memory
// without bound.
const overflowKey = "\x00overflow"

// Limiter is a bounded in-memory fixed-window rate limiter. State is per
// process and resets on restart; it is a flood guard, not an accounting
// system.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	window  time.Duration
	limit   int
	maxKeys int
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

// NewLimiter allows limit events per key per window, tracking at most maxKeys
// keys at once.
func NewLimiter(limit int, window time.Duration, maxKeys int) *Limiter {
	if limit <= 0 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 10000
	}
	return &Limiter{
		now:     time.Now,
		window:  window,
		limit:   limit,
		maxKeys: maxKeys,
		buckets: make(map[string]*bucket),
	}
}

// WithClock replaces the time source (for tests).
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Allow records one event for key and reports whether it is within the limit.
// When it is not, retryAfter says how long until the window resets.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	b, exists := l.buckets[key]
	if exists && !now.Before(b.resetAt) {
		delete(l.buckets, key)
		exists = false
	}

	if !exists {
		if len(l.buckets) >= l.maxKeys {
			l.evictExpired(now)
		}
		if len(l.buckets) >= l.maxKeys {
			key = overflowKey
			b, exists = l.buckets[key]
			if exists && !now.Before(b.resetAt) {
				delete(l.buckets, key)
				exists = false
			}
		}
		if !exists {
			b = &bucket{resetAt: now.Add(l.window)}
			l.buckets[key] = b
		}
	}

	b.count++
	if b.count > l.limit {
		return false, b.resetAt.Sub(now)
	}
	return true, 0
}

// Exceeded reports whether key has already used up its allowance in the
// current window, without recording an event.
func (l *Limiter) Exceeded(key string) (exceeded bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok || !now.Before(b.resetAt) {
		return false, 0
	}
	if b.count >= l.limit {
		return true, b.resetAt.Sub(now)
	}
	return false, 0
}

// Reset forgets a key, for example after a successful authentication.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *Limiter) evictExpired(now time.Time) {
	for k, b := range l.buckets {
		if !now.Before(b.resetAt) {
			delete(l.buckets, k)
		}
	}
}
