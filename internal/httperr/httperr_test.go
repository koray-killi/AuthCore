package httperr

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koray-killi/AuthCore/internal/domain"
)

func TestWrite_DomainError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"invalid credentials", domain.ErrInvalidCredentials, 401, "INVALID_CREDENTIALS"},
		{"account locked", domain.ErrAccountLocked, 403, "ACCOUNT_LOCKED"},
		{"email not verified", domain.ErrEmailNotVerified, 403, "EMAIL_NOT_VERIFIED"},
		{"email exists", domain.ErrEmailAlreadyExists, 409, "EMAIL_ALREADY_EXISTS"},
		{"user not found", domain.ErrUserNotFound, 404, "USER_NOT_FOUND"},
		{"weak password", domain.ErrWeakPassword, 400, "WEAK_PASSWORD"},
		{"token expired", domain.ErrTokenExpired, 401, "TOKEN_EXPIRED"},
		{"token invalid", domain.ErrTokenInvalid, 401, "TOKEN_INVALID"},
		{"token revoked", domain.ErrTokenRevoked, 401, "TOKEN_REVOKED"},
		{"otp expired", domain.ErrOTPExpired, 400, "OTP_EXPIRED"},
		{"otp invalid", domain.ErrOTPInvalid, 400, "OTP_INVALID"},
		{"otp max attempts", domain.ErrOTPMaxAttempts, 429, "OTP_MAX_ATTEMPTS"},
		{"rate limited", domain.ErrRateLimited, 429, "RATE_LIMITED"},
		{"unauthorized", domain.ErrUnauthorized, 401, "UNAUTHORIZED"},
		{"forbidden", domain.ErrForbidden, 403, "FORBIDDEN"},
		{"bad request", domain.ErrBadRequest, 400, "BAD_REQUEST"},
		{"internal", domain.ErrInternal, 500, "INTERNAL_ERROR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Write(rec, tt.err)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			contentType := rec.Header().Get("Content-Type")
			if contentType != "application/json; charset=utf-8" {
				t.Errorf("content-type = %q, want application/json; charset=utf-8", contentType)
			}

			body := rec.Body.String()
			if body == "" {
				t.Error("expected non-empty body")
			}
		})
	}
}

func TestWrite_UnknownError(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, errors.New("something unexpected"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}

	body := rec.Body.String()
	// Should NOT contain the original error message.
	if contains(body, "something unexpected") {
		t.Error("unknown error message should not leak in response")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
