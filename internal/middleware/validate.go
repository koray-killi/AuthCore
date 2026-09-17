package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/httperr"
)

const maxBodySize = 1 << 20 // 1 MB

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
