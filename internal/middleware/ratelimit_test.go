package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewInMemoryRateLimiter(5, 1*time.Minute, 3, 1*time.Minute, 3, 10*time.Minute)

	for i := 0; i < 5; i++ {
		allowed, _ := rl.AllowIP("127.0.0.1")
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewInMemoryRateLimiter(3, 1*time.Minute, 3, 1*time.Minute, 3, 10*time.Minute)

	for i := 0; i < 3; i++ {
		rl.AllowIP("127.0.0.1")
	}

	allowed, retryAfter := rl.AllowIP("127.0.0.1")
	if allowed {
		t.Error("4th request should be blocked")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := NewInMemoryRateLimiter(2, 1*time.Minute, 2, 1*time.Minute, 3, 10*time.Minute)

	rl.AllowIP("1.1.1.1")
	rl.AllowIP("1.1.1.1")

	// 1.1.1.1 is at limit.
	allowed, _ := rl.AllowIP("1.1.1.1")
	if allowed {
		t.Error("1.1.1.1 should be blocked")
	}

	// 2.2.2.2 should still be allowed.
	allowed, _ = rl.AllowIP("2.2.2.2")
	if !allowed {
		t.Error("2.2.2.2 should be allowed")
	}
}

func TestRateLimiter_AccountLimit(t *testing.T) {
	rl := NewInMemoryRateLimiter(100, 1*time.Minute, 2, 1*time.Minute, 3, 10*time.Minute)

	rl.AllowAccount("user@example.com")
	rl.AllowAccount("user@example.com")

	allowed, _ := rl.AllowAccount("user@example.com")
	if allowed {
		t.Error("3rd account request should be blocked")
	}
}

func TestRateLimitMiddleware_Returns429(t *testing.T) {
	rl := NewInMemoryRateLimiter(1, 1*time.Minute, 1, 1*time.Minute, 1, 10*time.Minute)

	handler := RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request should pass.
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "127.0.0.1:12345"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", rec1.Code)
	}

	// Second request should be rate limited.
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "127.0.0.1:12346"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", rec2.Code)
	}

	retryAfter := rec2.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xri        string
		remoteAddr string
		expected   string
	}{
		{"X-Forwarded-For single", "1.2.3.4", "", "5.6.7.8:1234", "1.2.3.4"},
		{"X-Forwarded-For chain", "1.2.3.4, 5.6.7.8", "", "9.0.0.1:1234", "1.2.3.4"},
		{"X-Real-IP", "", "1.2.3.4", "5.6.7.8:1234", "1.2.3.4"},
		{"RemoteAddr", "", "", "5.6.7.8:1234", "5.6.7.8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			ip := ExtractIP(req)
			if ip != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, ip)
			}
		})
	}
}

func TestRateLimiter_EmailLimit(t *testing.T) {
	rl := NewInMemoryRateLimiter(100, 1*time.Minute, 100, 1*time.Minute, 2, 10*time.Minute)

	// First two allowed.
	for i := 0; i < 2; i++ {
		allowed, _ := rl.AllowEmail("bomb@example.com")
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// Third should be blocked.
	allowed, retryAfter := rl.AllowEmail("bomb@example.com")
	if allowed {
		t.Error("3rd email request should be blocked")
	}
	if retryAfter <= 0 {
		t.Error("retryAfter should be positive")
	}

	// Different email should be independent.
	allowed, _ = rl.AllowEmail("other@example.com")
	if !allowed {
		t.Error("different email should not be blocked")
	}
}
