package appauth_test

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRunCleanupRemovesExpiredTokensPeriodicallyAndStops(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, f.p1)
	f.token(t, c)
	f.clock.Advance(3 * time.Hour) // expired, past the 1h retention

	var (
		mu      sync.Mutex
		deleted int64
		passes  int
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.svc.RunCleanup(ctx, 5*time.Millisecond, time.Hour, func(n int64, err error) {
			if err != nil {
				t.Errorf("cleanup error: %v", err)
			}
			mu.Lock()
			deleted += n
			passes++
			mu.Unlock()
		})
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		enough := passes >= 3
		mu.Unlock()
		if enough {
			break
		}
		select {
		case <-deadline:
			t.Fatal("cleanup did not run repeatedly")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup did not stop after cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	if deleted != 1 {
		t.Fatalf("deleted = %d; want 1", deleted)
	}
}
