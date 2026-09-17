package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/middleware"
	"github.com/koray-killi/AuthCore/internal/service"
	"go.uber.org/zap"
)

// testRouter creates a full router with fake dependencies for handler testing.
func testRouter() (http.Handler, *service.FakeMailer) {
	userRepo := service.NewFakeUserRepo()
	sessionRepo := service.NewFakeSessionRepo()
	otpRepo := service.NewFakeOTPRepo()
	auditRepo := service.NewFakeAuditRepo()
	ml := service.NewFakeMailer()

	jwtCfg := config.JWTConfig{
		Secret:        "test-secret-key-for-handler-tests",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	cfg := &config.Config{
		ServerPort:         8080,
		CORSAllowedOrigins: []string{"*"},
		JWT:                jwtCfg,
		RateLimit: config.RateLimitConfig{
			IPRequests:      1000,
			IPWindow:        1 * time.Minute,
			AccountRequests: 1000,
			AccountWindow:   1 * time.Minute,
		},
	}

	tokenSvc := service.NewTokenService(jwtCfg, sessionRepo)
	otpSvc := service.NewOTPService(otpRepo)
	auditSvc := service.NewAuditService(auditRepo)
	authSvc := service.NewAuthService(userRepo, tokenSvc, otpSvc, auditSvc, ml, jwtCfg)

	rl := middleware.NewInMemoryRateLimiter(
		cfg.RateLimit.IPRequests,
		cfg.RateLimit.IPWindow,
		cfg.RateLimit.AccountRequests,
		cfg.RateLimit.AccountWindow,
	)

	logger, _ := zap.NewDevelopment()

	// Pass nil pool since we won't use health check in handler tests.
	router := NewRouter(authSvc, tokenSvc, auditSvc, (*pgxpool.Pool)(nil), cfg, logger, rl)
	return router, ml
}

func postJSON(router http.Handler, path string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func getWithAuth(router http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postWithAuth(router http.Handler, path, token string, body interface{}) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postWithAuthAndCookie(router http.Handler, path, token, cookieName, cookieValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postWithCookie(router http.Handler, path, cookieName, cookieValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestHandler_Register(t *testing.T) {
	tests := []struct {
		name       string
		body       interface{}
		wantStatus int
	}{
		{
			name:       "success",
			body:       RegisterRequest{Email: "user@example.com", Password: "securepassword1"},
			wantStatus: http.StatusCreated,
		},
		{
			name:       "weak password",
			body:       RegisterRequest{Email: "user@example.com", Password: "short"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty email",
			body:       RegisterRequest{Email: "", Password: "securepassword1"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, _ := testRouter()
			rec := postJSON(router, "/api/v1/auth/register", tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d. body: %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestHandler_RegisterDuplicate(t *testing.T) {
	router, _ := testRouter()

	rec1 := postJSON(router, "/api/v1/auth/register", RegisterRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first register: status = %d, want 201", rec1.Code)
	}

	rec2 := postJSON(router, "/api/v1/auth/register", RegisterRequest{
		Email: "user@example.com", Password: "securepassword2",
	})
	if rec2.Code != http.StatusConflict {
		t.Errorf("duplicate register: status = %d, want 409", rec2.Code)
	}
}

func TestHandler_LoginFlow(t *testing.T) {
	router, ml := testRouter()

	// Register.
	rec := postJSON(router, "/api/v1/auth/register", RegisterRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d", rec.Code)
	}

	// Login without verification should fail.
	rec = postJSON(router, "/api/v1/auth/login", LoginRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("login unverified: status = %d, want 403", rec.Code)
	}

	// Verify email.
	code := ml.GetLastCode()
	rec = postJSON(router, "/api/v1/auth/verify-email", VerifyEmailRequest{
		Email: "user@example.com", Code: code,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body: %s", rec.Code, rec.Body.String())
	}

	// Login should succeed now.
	rec = postJSON(router, "/api/v1/auth/login", LoginRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status = %d, body: %s", rec.Code, rec.Body.String())
	}

	// Check response has access_token.
	var tokenResp TokenResponse
	json.NewDecoder(rec.Body).Decode(&tokenResp)
	if tokenResp.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if tokenResp.TokenType != "Bearer" {
		t.Errorf("expected token_type 'Bearer', got %q", tokenResp.TokenType)
	}

	// Check refresh token cookie is set.
	cookies := rec.Result().Cookies()
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "refresh_token" {
			refreshCookie = c
			break
		}
	}
	if refreshCookie == nil {
		t.Fatal("expected refresh_token cookie")
	}
	if !refreshCookie.HttpOnly {
		t.Error("refresh_token cookie should be httpOnly")
	}
}

func TestHandler_MeEndpoint(t *testing.T) {
	router, ml := testRouter()

	// Register and verify.
	postJSON(router, "/api/v1/auth/register", RegisterRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	code := ml.GetLastCode()
	postJSON(router, "/api/v1/auth/verify-email", VerifyEmailRequest{
		Email: "user@example.com", Code: code,
	})

	// Login.
	rec := postJSON(router, "/api/v1/auth/login", LoginRequest{
		Email: "user@example.com", Password: "securepassword1",
	})
	var tokenResp TokenResponse
	json.NewDecoder(rec.Body).Decode(&tokenResp)

	// Get /auth/me.
	rec = getWithAuth(router, "/api/v1/auth/me", tokenResp.AccessToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth/me: status = %d, body: %s", rec.Code, rec.Body.String())
	}

	var userResp UserResponse
	json.NewDecoder(rec.Body).Decode(&userResp)
	if userResp.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %q", userResp.Email)
	}

	// Verify no sensitive fields in JSON.
	body := rec.Body.String()
	for _, field := range []string{"password_hash", "otp_hash", "token_hash"} {
		if bytes.Contains([]byte(body), []byte(field)) {
			t.Errorf("response body contains sensitive field %q", field)
		}
	}
}

func TestHandler_MeWithoutAuth(t *testing.T) {
	router, _ := testRouter()

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /auth/me without auth: status = %d, want 401", rec.Code)
	}
}

func TestHandler_ForgotPassword_AlwaysReturns202(t *testing.T) {
	router, _ := testRouter()

	// Non-existent user should still get 202.
	rec := postJSON(router, "/api/v1/auth/forgot-password", ForgotPasswordRequest{
		Email: "nobody@example.com",
	})
	if rec.Code != http.StatusAccepted {
		t.Errorf("forgot-password: status = %d, want 202", rec.Code)
	}
}

func TestHandler_SecurityHeaders(t *testing.T) {
	router, _ := testRouter()

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":       "DENY",
		"Referrer-Policy":       "strict-origin-when-cross-origin",
	}

	for header, expected := range expectedHeaders {
		got := rec.Header().Get(header)
		if got != expected {
			t.Errorf("header %s: got %q, want %q", header, got, expected)
		}
	}
}
