package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/httperr"
)

// RateLimiter defines the interface for rate limiting. The in-memory implementation
// can be swapped for Redis without changing the middleware layer.
type RateLimiter interface {
	// AllowIP checks if a request from the given IP is allowed under the IP rate limit.
	AllowIP(ip string) (bool, time.Duration)
	// AllowAccount checks if a request for the given account key is allowed.
	AllowAccount(key string) (bool, time.Duration)
	// AllowEmail checks whether an email-sending action for the given email is allowed.
	// This enforces a strict per-email limit on register and resend-verification to
	// prevent email bombing.
	AllowEmail(email string) (bool, time.Duration)
}

// slidingWindowEntry tracks requests in a sliding time window.
type slidingWindowEntry struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// inMemoryRateLimiter implements RateLimiter with an in-memory sliding window.
type inMemoryRateLimiter struct {
	ipEntries      sync.Map
	accountEntries sync.Map
	emailEntries   sync.Map
	ipMax          int
	ipWindow       time.Duration
	accountMax     int
	accountWindow  time.Duration
	emailMax       int
	emailWindow    time.Duration
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter.
func NewInMemoryRateLimiter(ipMax int, ipWindow time.Duration, accountMax int, accountWindow time.Duration, emailMax int, emailWindow time.Duration) RateLimiter {
	rl := &inMemoryRateLimiter{
		ipMax:         ipMax,
		ipWindow:      ipWindow,
		accountMax:    accountMax,
		accountWindow: accountWindow,
		emailMax:      emailMax,
		emailWindow:   emailWindow,
	}

	// Background cleanup goroutine to prevent memory leak from expired entries.
	go rl.cleanup()

	return rl
}

func (rl *inMemoryRateLimiter) AllowIP(ip string) (bool, time.Duration) {
	return rl.allow(&rl.ipEntries, ip, rl.ipMax, rl.ipWindow)
}

func (rl *inMemoryRateLimiter) AllowAccount(key string) (bool, time.Duration) {
	return rl.allow(&rl.accountEntries, key, rl.accountMax, rl.accountWindow)
}

func (rl *inMemoryRateLimiter) AllowEmail(email string) (bool, time.Duration) {
	return rl.allow(&rl.emailEntries, email, rl.emailMax, rl.emailWindow)
}

func (rl *inMemoryRateLimiter) allow(entries *sync.Map, key string, max int, window time.Duration) (bool, time.Duration) {
	now := time.Now()
	cutoff := now.Add(-window)

	val, _ := entries.LoadOrStore(key, &slidingWindowEntry{})
	entry := val.(*slidingWindowEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Prune expired timestamps.
	valid := make([]time.Time, 0, len(entry.timestamps))
	for _, ts := range entry.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	entry.timestamps = valid

	if len(entry.timestamps) >= max {
		// Calculate retry-after from the oldest entry in the window.
		retryAfter := entry.timestamps[0].Add(window).Sub(now)
		if retryAfter < 0 {
			retryAfter = time.Second
		}
		return false, retryAfter
	}

	entry.timestamps = append(entry.timestamps, now)
	return true, 0
}

// cleanup periodically removes expired entries to prevent memory leaks.
func (rl *inMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cleanMap := func(entries *sync.Map, window time.Duration) {
			entries.Range(func(key, value interface{}) bool {
				entry := value.(*slidingWindowEntry)
				entry.mu.Lock()
				cutoff := now.Add(-window)
				valid := make([]time.Time, 0)
				for _, ts := range entry.timestamps {
					if ts.After(cutoff) {
						valid = append(valid, ts)
					}
				}
				entry.timestamps = valid
				empty := len(valid) == 0
				entry.mu.Unlock()
				if empty {
					entries.Delete(key)
				}
				return true
			})
		}
		cleanMap(&rl.ipEntries, rl.ipWindow)
		cleanMap(&rl.accountEntries, rl.accountWindow)
		cleanMap(&rl.emailEntries, rl.emailWindow)
	}
}

// RateLimit creates an HTTP middleware that applies IP-based rate limiting.
func RateLimit(limiter RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ExtractIP(r)

			allowed, retryAfter := limiter.AllowIP(ip)
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
				httperr.Write(w, domain.ErrRateLimited)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ExtractIP gets the client IP from the request, checking X-Forwarded-For first.
func ExtractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Use the first IP in the chain (client IP).
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr (strip port).
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// EmailRateLimit creates an HTTP middleware that enforces a strict per-email rate limit
// on email-sending endpoints (register, resend-verification). It reads the "email" field
// from the JSON body, re-encodes it for the next handler, and blocks if the limit is exceeded.
// If the email field is missing or empty, the request is passed through (field validation
// is the responsibility of the handler).
func EmailRateLimit(limiter RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Peek at the body to read the email field without consuming it.
			body, err := peekBody(r)
			if err != nil || body == nil {
				next.ServeHTTP(w, r)
				return
			}

			var payload struct {
				Email string `json:"email"`
			}
			// Best-effort decode — if it fails, pass through.
			_ = json.NewDecoder(bytes.NewReader(body)).Decode(&payload)

			email := strings.TrimSpace(strings.ToLower(payload.Email))
			if email == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed, retryAfter := limiter.AllowEmail(email)
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
				httperr.Write(w, domain.ErrRateLimited)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// peekBody reads the full request body and resets r.Body so downstream handlers can
// read it again. Returns nil if the body is empty or exceeds 1 MB.
func peekBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	const maxPeek = 1 << 20 // 1 MiB — consistent with BodyLimit middleware
	b, err := io.ReadAll(io.LimitReader(r.Body, maxPeek))
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}
