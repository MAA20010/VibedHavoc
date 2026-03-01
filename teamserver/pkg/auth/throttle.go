package auth

import (
	"sync"
	"time"
)

// ipRecord tracks failed authentication attempts from a single IP address.
// All state is in-memory only — no database writes, no persistent lockouts.
// Entries auto-expire after DecayAfter of inactivity.
type ipRecord struct {
	Failures  int       // consecutive failed attempts (reset on success)
	LastFail  time.Time // timestamp of most recent failure
}

// AuthThrottle implements per-IP exponential backoff for failed auth attempts.
//
// Design decisions:
//   - Per-IP, NOT per-username — prevents adversary from locking out operators
//     by spamming bad passwords for known usernames.
//   - No account lockout — legitimate operators from a different IP are never affected.
//   - Memory-only — survives no restart, so temporary issues self-heal.
//   - Auto-decay — entries expire after inactivity (default 15 minutes).
//   - Exponential backoff — 0s, 2s, 4s, 8s, 16s, 30s, 60s cap.
//     At max delay, attacker gets ~1440 attempts/day per IP.
type AuthThrottle struct {
	mu       sync.Mutex
	records  map[string]*ipRecord // key = client IP

	// Configurable parameters
	MaxDelay   time.Duration // ceiling for backoff delay (default 60s)
	BaseDelay  time.Duration // initial delay after first failure (default 2s)
	DecayAfter time.Duration // clear record after this much inactivity (default 15m)
}

// NewAuthThrottle creates a throttle with sane defaults and starts the
// background cleanup goroutine.
func NewAuthThrottle() *AuthThrottle {
	t := &AuthThrottle{
		records:    make(map[string]*ipRecord),
		MaxDelay:   60 * time.Second,
		BaseDelay:  2 * time.Second,
		DecayAfter: 15 * time.Minute,
	}
	go t.cleanupLoop()
	return t
}

// Delay returns how long the caller should sleep before processing an auth
// request from this IP. Returns 0 if the IP has no failures on record.
// The caller is responsible for actually sleeping (time.Sleep or timer).
func (t *AuthThrottle) Delay(clientIP string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, exists := t.records[clientIP]
	if !exists || rec.Failures == 0 {
		return 0
	}

	// Auto-decay: if enough time passed since last failure, clear the record
	if time.Since(rec.LastFail) > t.DecayAfter {
		delete(t.records, clientIP)
		return 0
	}

	return t.calcDelay(rec.Failures)
}

// RecordFailure increments the failure count for an IP.
func (t *AuthThrottle) RecordFailure(clientIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec, exists := t.records[clientIP]
	if !exists {
		rec = &ipRecord{}
		t.records[clientIP] = rec
	}

	rec.Failures++
	rec.LastFail = time.Now()
}

// RecordSuccess resets the failure count for an IP (legitimate operator logged in).
func (t *AuthThrottle) RecordSuccess(clientIP string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.records, clientIP)
}

// calcDelay computes exponential backoff: BaseDelay * 2^(failures-1), capped at MaxDelay.
// failures=1 → BaseDelay, failures=2 → 2*BaseDelay, etc.
func (t *AuthThrottle) calcDelay(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}

	delay := t.BaseDelay
	for i := 1; i < failures; i++ {
		delay *= 2
		if delay > t.MaxDelay {
			return t.MaxDelay
		}
	}
	return delay
}

// cleanupLoop periodically purges expired IP records to prevent unbounded
// memory growth. Runs every 5 minutes.
func (t *AuthThrottle) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		t.mu.Lock()
		now := time.Now()
		for ip, rec := range t.records {
			if now.Sub(rec.LastFail) > t.DecayAfter {
				delete(t.records, ip)
			}
		}
		t.mu.Unlock()
	}
}
