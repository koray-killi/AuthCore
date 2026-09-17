//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/database"
	"github.com/koray-killi/AuthCore/internal/handler"
	"github.com/koray-killi/AuthCore/internal/mailer"
	"github.com/koray-killi/AuthCore/internal/middleware"
	"github.com/koray-killi/AuthCore/internal/repository"
	"github.com/koray-killi/AuthCore/internal/service"
	"go.uber.org/zap"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type mailhogResponse struct {
	Items []struct {
		Content struct {
			Body string `json:"Body"`
		} `json:"Content"`
	} `json:"items"`
}

func TestE2E_FullAuthenticationFlow(t *testing.T) {
	// Change working directory to project root so database migrations can find "file://migrations"
	if err := os.Chdir("../../"); err != nil {
		t.Fatalf("Failed to chdir to project root: %v", err)
	}

	// 1. Setup Test App
	logger := zap.NewNop()
	cfg := &config.Config{
		ServerPort:            8080,
		DatabaseURL:           "postgres://authcore:authcore@localhost:5433/authcore_test?sslmode=disable",
		JWT: config.JWTConfig{
			Secret:        "test-secret",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 7 * 24 * time.Hour,
		},
		SMTP: config.SMTPConfig{
			Host: "localhost",
			Port: 1026,
			From: "test@authcore.local",
		},
		RateLimit: config.RateLimitConfig{
			IPRequests:      1000,
			IPWindow:        1 * time.Minute,
			AccountRequests: 1000,
			AccountWindow:   1 * time.Minute,
		},
	}

	// Connect DB and run migrations
	pool, err := database.Connect(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("Failed to connect to test db: %v", err)
	}
	defer pool.Close()
	if err := database.RunMigrations(cfg.DatabaseURL); err != nil {
		t.Fatalf("Failed to run migrations: %v", err)
	}
	// Clean DB for the test (truncate all tables)
	_, _ = pool.Exec(context.Background(), "TRUNCATE users, refresh_sessions, otp_codes, audit_logs CASCADE")

	// Repositories
	userRepo := repository.NewUserRepo(pool)
	sessionRepo := repository.NewSessionRepo(pool)
	otpRepo := repository.NewOTPRepo(pool)
	auditRepo := repository.NewAuditRepo(pool)

	// Services
	smtpMailer := mailer.NewSMTPMailer(cfg.SMTP)
	auditSvc := service.NewAuditService(auditRepo)
	tokenSvc := service.NewTokenService(cfg.JWT, sessionRepo)
	otpSvc := service.NewOTPService(otpRepo)
	authSvc := service.NewAuthService(userRepo, tokenSvc, otpSvc, auditSvc, smtpMailer, cfg.JWT)

	// Rate limiter
	rateLimiter := middleware.NewInMemoryRateLimiter(
		cfg.RateLimit.IPRequests,
		cfg.RateLimit.IPWindow,
		cfg.RateLimit.AccountRequests,
		cfg.RateLimit.AccountWindow,
	)

	// Router
	r := handler.NewRouter(
		authSvc,
		tokenSvc,
		auditSvc,
		pool,
		cfg,
		logger,
		rateLimiter,
	)

	ts := httptest.NewServer(r)
	defer ts.Close()

	baseURL := ts.URL + "/api/v1"
	mailhogURL := "http://localhost:8026/api/v2/messages"

	client := ts.Client()

	email := "e2e_user@example.com"
	password := "supersecure1"

	// 2. Clear MailHog
	req, _ := http.NewRequest(http.MethodDelete, "http://localhost:8026/api/v1/messages", nil)
	client.Do(req)

	// 3. Register
	t.Log("Registering user...")
	regBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	resp, err := client.Post(baseURL+"/auth/register", "application/json", bytes.NewBuffer(regBody))
	if err != nil {
		t.Fatalf("Register request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created for register, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// 4. Fetch OTP from MailHog
	t.Log("Fetching OTP from MailHog...")
	time.Sleep(1 * time.Second) // Give MailHog a moment to receive the email
	resp, err = client.Get(mailhogURL)
	if err != nil {
		t.Fatalf("Failed to fetch emails: %v", err)
	}
	defer resp.Body.Close()

	var mhResp mailhogResponse
	if err := json.NewDecoder(resp.Body).Decode(&mhResp); err != nil {
		t.Fatalf("Failed to decode MailHog response: %v", err)
	}
	if len(mhResp.Items) == 0 {
		t.Fatal("No emails received in MailHog")
	}

	bodyText := mhResp.Items[0].Content.Body
	re := regexp.MustCompile(`\b\d{6}\b`)
	otp := re.FindString(bodyText)
	if otp == "" {
		t.Fatalf("Could not find 6-digit OTP in email body: %s", bodyText)
	}
	t.Logf("Extracted OTP: %s", otp)

	// 5. Verify Email
	t.Log("Verifying email...")
	verifyBody, _ := json.Marshal(map[string]string{
		"email": email,
		"code":  otp,
	})
	resp, err = client.Post(baseURL+"/auth/verify-email", "application/json", bytes.NewBuffer(verifyBody))
	if err != nil {
		t.Fatalf("Verify request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK for verify, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// 6. Login
	t.Log("Logging in...")
	loginBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	resp, err = client.Post(baseURL+"/auth/login", "application/json", bytes.NewBuffer(loginBody))
	if err != nil {
		t.Fatalf("Login request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK for login, got %d. Body: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("Failed to decode login response: %v", err)
	}
	accessToken := tr.AccessToken
	if accessToken == "" {
		t.Fatal("Access token is empty")
	}

	var refreshTokenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "refresh_token" {
			refreshTokenCookie = c
			break
		}
	}
	if refreshTokenCookie == nil {
		t.Fatal("refresh_token cookie not found in login response")
	}

	// 7. Test /me endpoint
	t.Log("Testing /auth/me...")
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Me request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for /me, got %d", resp.StatusCode)
	}

	// 8. Refresh Token
	t.Log("Refreshing token...")
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/auth/refresh", nil)
	req.AddCookie(refreshTokenCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Refresh request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK for refresh, got %d. Body: %s", resp.StatusCode, string(body))
	}

	var newTr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&newTr); err != nil {
		t.Fatalf("Failed to decode refresh response: %v", err)
	}
	newAccessToken := newTr.AccessToken
	if newAccessToken == "" {
		t.Fatal("New access token is empty")
	}

	var newRefreshTokenCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "refresh_token" {
			newRefreshTokenCookie = c
			break
		}
	}
	if newRefreshTokenCookie == nil {
		t.Fatal("New refresh_token cookie not found in refresh response")
	}

	// 9. Logout
	t.Log("Logging out...")
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+newAccessToken)
	req.AddCookie(newRefreshTokenCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Logout request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK for logout, got %d. Body: %s", resp.StatusCode, string(body))
	}

	// 10. Verify Logout (Try to refresh again with revoked token)
	t.Log("Verifying logout by attempting refresh...")
	req, _ = http.NewRequest(http.MethodPost, baseURL+"/auth/refresh", nil)
	req.AddCookie(newRefreshTokenCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Verification refresh request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for refresh after logout, got %d", resp.StatusCode)
	}

	t.Log("E2E Authentication Flow Completed Successfully! ✅")
}
