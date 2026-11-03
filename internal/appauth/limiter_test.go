package appauth

import (
	"fmt"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestLimiterAllowsUpToLimitThenBlocks(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := NewLimiter(3, time.Minute, 10).WithClock(clk.now)

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("event %d should be allowed", i)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > time.Minute {
		t.Fatalf("over limit: ok=%v retry=%v", ok, retry)
	}

	// Other keys are independent.
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key must not be limited")
	}

	// The window resets.
	clk.t = clk.t.Add(time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("window should have reset")
	}
}

func TestLimiterExceededDoesNotRecord(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := NewLimiter(2, time.Minute, 10).WithClock(clk.now)

	for i := 0; i < 5; i++ {
		if exceeded, _ := l.Exceeded("a"); exceeded {
			t.Fatal("peeking must not consume the allowance")
		}
	}

	l.Allow("a")
	l.Allow("a")
	exceeded, retry := l.Exceeded("a")
	if !exceeded || retry <= 0 {
		t.Fatalf("exceeded=%v retry=%v", exceeded, retry)
	}

	clk.t = clk.t.Add(2 * time.Minute)
	if exceeded, _ := l.Exceeded("a"); exceeded {
		t.Fatal("should reset with the window")
	}
}

func TestLimiterReset(t *testing.T) {
	l := NewLimiter(1, time.Minute, 10)
	l.Allow("a")
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("should be blocked")
	}
	l.Reset("a")
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("reset should clear the key")
	}
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	l := NewLimiter(1, time.Minute, 50).WithClock(clk.now)

	for i := 0; i < 5000; i++ {
		l.Allow(fmt.Sprintf("attacker-%d", i))
	}
	l.mu.Lock()
	size := len(l.buckets)
	l.mu.Unlock()
	if size > 51 {
		t.Fatalf("tracked %d keys; limit is 50 plus the overflow bucket", size)
	}

	// Once full, new keys share one bucket and are throttled together, but a
	// tracked key keeps its own allowance.
	if ok, _ := l.Allow("brand-new-key"); ok {
		t.Fatal("overflow bucket should already be spent")
	}

	// Expired entries are reclaimed.
	clk.t = clk.t.Add(2 * time.Minute)
	if ok, _ := l.Allow("fresh"); !ok {
		t.Fatal("expired entries should be evicted to make room")
	}
}

func TestLimiterDefaults(t *testing.T) {
	l := NewLimiter(0, 0, 0)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first event must pass with defaults")
	}
}
