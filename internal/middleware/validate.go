package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/httperr"
)

const maxBodySize = 1 << 20 // 1 MB

// emailRegex is an RFC 5322-simplified pattern for validating email addresses.
// Intentionally simple: real validation comes from the email verification OTP flow.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail checks whether email is a non-empty, properly formatted address.
// Returns domain.ErrBadRequest for empty and domain.ErrInvalidEmail for malformed.
func ValidateEmail(email string) error {
	if email == "" {
		return domain.ErrBadRequest
	}
	if !emailRegex.MatchString(email) {
		return domain.ErrInvalidEmail
	}
	return nil
}

// BodyLimit restricts the request body size to prevent large payload attacks.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		}
		next.ServeHTTP(w, r)
	})
}

// DecodeJSON reads the request body as JSON into the given destination.
// Returns a domain error on failure so the caller can pass it to httperr.Write.
func DecodeJSON(r *http.Request, dst interface{}) error {
	if r.Body == nil {
		return domain.ErrBadRequest
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return domain.ErrBadRequest
	}

	return nil
}

// SecurityHeaders adds common security headers to every response.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// HandleError maps an error to an HTTP response. If the error is nil, does nothing.
func HandleError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	httperr.Write(w, err)
	return true
}

// AccountRateLimit creates an HTTP middleware that enforces a per-account (email) rate
// limit on the login endpoint to prevent credential-stuffing attacks. It peeks the
// request body to read the email field and applies AllowAccount. The body is restored
// so the downstream handler can still read it.
//
// This is distinct from EmailRateLimit: EmailRateLimit guards mail-sending endpoints;
// AccountRateLimit guards authentication endpoints.
func AccountRateLimit(limiter RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := peekBody(r)
			if err != nil || body == nil {
				next.ServeHTTP(w, r)
				return
			}

			var payload struct {
				Email string `json:"email"`
			}
			_ = json.NewDecoder(bytes.NewReader(body)).Decode(&payload)

			email := strings.TrimSpace(strings.ToLower(payload.Email))
			if email == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Restore body — DecodeJSON in the handler must still be able to read it.
			r.Body = io.NopCloser(bytes.NewReader(body))

			allowed, retryAfter := limiter.AllowAccount(email)
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
				httperr.Write(w, domain.ErrRateLimited)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
