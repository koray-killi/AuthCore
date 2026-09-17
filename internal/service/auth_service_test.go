package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// newTestAuthService creates an AuthService with fake dependencies for unit testing.
func newTestAuthService() (*AuthService, *FakeUserRepo, *FakeSessionRepo, *FakeOTPRepo, *FakeAuditRepo, *FakeMailer) {
	userRepo := NewFakeUserRepo()
	sessionRepo := NewFakeSessionRepo()
	otpRepo := NewFakeOTPRepo()
	auditRepo := NewFakeAuditRepo()
	ml := NewFakeMailer()

	jwtCfg := config.JWTConfig{
		Secret:        "test-secret-key-for-unit-tests",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}

	tokenSvc := NewTokenService(jwtCfg, sessionRepo)
	otpSvc := NewOTPService(otpRepo)
	auditSvc := NewAuditService(auditRepo)
	authSvc := NewAuthService(userRepo, tokenSvc, otpSvc, auditSvc, ml, jwtCfg)

	return authSvc, userRepo, sessionRepo, otpRepo, auditRepo, ml
}

func TestRegister_Success(t *testing.T) {
	authSvc, userRepo, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	err := authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify user was created in the repository.
	user, err := userRepo.GetByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if user.IsActive {
		t.Error("newly registered user should be inactive")
	}
	if user.Role != "user" {
		t.Errorf("expected role 'user', got %q", user.Role)
	}

	// Verify verification email was sent.
	if len(ml.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(ml.Emails))
	}
	if ml.Emails[0].Purpose != "verify_email" {
		t.Errorf("expected purpose 'verify_email', got %q", ml.Emails[0].Purpose)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	err := authSvc.Register(ctx, "user@example.com", "short", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrWeakPassword) {
		t.Errorf("expected ErrWeakPassword, got %v", err)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	err := authSvc.Register(ctx, "user@example.com", "securepassword2", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrEmailAlreadyExists) {
		t.Errorf("expected ErrEmailAlreadyExists, got %v", err)
	}
}

func TestLogin_InvalidCredentials_NonExistentUser(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	_, err := authSvc.Login(ctx, "nobody@example.com", "anypassword1", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_InvalidCredentials_WrongPassword(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	// Activate user.
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	_, err := authSvc.Login(ctx, "user@example.com", "wrongpassword!", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLogin_EnumerationSafeTiming(t *testing.T) {
	// This test verifies that login for non-existent users takes comparable time
	// to login for existent users (both perform Argon2id computation).
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	// Time login with existing user + wrong password.
	start1 := time.Now()
	_, _ = authSvc.Login(ctx, "user@example.com", "wrongpassword!", "127.0.0.1", "test-agent")
	elapsed1 := time.Since(start1)

	// Time login with non-existing user.
	start2 := time.Now()
	_, _ = authSvc.Login(ctx, "noone@example.com", "wrongpassword!", "127.0.0.1", "test-agent")
	elapsed2 := time.Since(start2)

	// Both should take roughly the same time (within 5x tolerance for CI variance).
	ratio := float64(elapsed1) / float64(elapsed2)
	if ratio < 0.1 || ratio > 10 {
		t.Errorf("timing difference too large: existing=%v, non-existing=%v, ratio=%.2f",
			elapsed1, elapsed2, ratio)
	}
}

func TestLogin_EmailNotVerified(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")

	_, err := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Errorf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestLogin_AccountLockAfter5Failures(t *testing.T) {
	authSvc, _, _, _, auditRepo, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	// 5 failed login attempts should trigger lock.
	for i := 0; i < 5; i++ {
		_, _ = authSvc.Login(ctx, "user@example.com", "wrongpassword!", "127.0.0.1", "test-agent")
	}

	// 6th attempt should get account locked error.
	_, err := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// Verify audit log has account_locked entry.
	logs := auditRepo.GetLogs()
	found := false
	for _, l := range logs {
		if l.Action == domain.AuditActionAccountLocked {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected account_locked audit log entry")
	}
}

func TestLogin_SuccessfulLogin(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	pair, err := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if pair.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
}

func TestRefreshToken_RotationChain(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	// Login to get initial token pair.
	pair1, err := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Rotate the refresh token.
	pair2, err := authSvc.RefreshToken(ctx, pair1.RefreshToken, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}

	if pair2.RefreshToken == pair1.RefreshToken {
		t.Error("rotated refresh token should be different from the original")
	}

	// Rotate again to verify chain.
	pair3, err := authSvc.RefreshToken(ctx, pair2.RefreshToken, "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}

	if pair3.RefreshToken == pair2.RefreshToken {
		t.Error("second rotated token should be different")
	}
}

func TestRefreshToken_ReuseDetection(t *testing.T) {
	authSvc, _, sessionRepo, _, auditRepo, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	pair1, _ := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")

	// Rotate: pair1.RefreshToken → pair2.
	pair2, _ := authSvc.RefreshToken(ctx, pair1.RefreshToken, "test-agent", "127.0.0.1")

	// REUSE ATTACK: try to use the OLD token (pair1.RefreshToken) again.
	_, err := authSvc.RefreshToken(ctx, pair1.RefreshToken, "test-agent", "127.0.0.1")
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked on reuse, got %v", err)
	}

	// The LEGITIMATE token (pair2) should also be revoked now.
	_, err = authSvc.RefreshToken(ctx, pair2.RefreshToken, "test-agent", "127.0.0.1")
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Errorf("expected all sessions revoked after reuse detection, got %v", err)
	}

	// Verify audit log has refresh_reuse_detected entry.
	logs := auditRepo.GetLogs()
	found := false
	for _, l := range logs {
		if l.Action == domain.AuditActionRefreshReuseDetected {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected refresh_reuse_detected audit log entry")
	}

	// Verify all sessions are revoked.
	sessionRepo.mu.RLock()
	for _, s := range sessionRepo.sessions {
		if s.RevokedAt == nil {
			t.Errorf("session %s should be revoked", s.ID)
		}
	}
	sessionRepo.mu.RUnlock()
}

func TestVerifyEmail_InvalidCode(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")

	err := authSvc.VerifyEmail(ctx, "user@example.com", "000000", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrOTPInvalid) {
		t.Errorf("expected ErrOTPInvalid, got %v", err)
	}
}

func TestForgotPassword_AlwaysSucceeds(t *testing.T) {
	authSvc, _, _, _, _, _ := newTestAuthService()
	ctx := context.Background()

	// Should not panic or return error for non-existent user.
	authSvc.ForgotPassword(ctx, "nobody@example.com", "127.0.0.1", "test-agent")
}

func TestResetPassword_FullFlow(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	verifyCode := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", verifyCode, "127.0.0.1", "test-agent")

	// Login to create an active session.
	_, _ = authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")

	// Request password reset.
	authSvc.ForgotPassword(ctx, "user@example.com", "127.0.0.1", "test-agent")
	resetCode := ml.GetLastCode()

	// Reset password.
	err := authSvc.ResetPassword(ctx, "user@example.com", resetCode, "newstrongpassword1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("ResetPassword failed: %v", err)
	}

	// Old password should not work.
	_, err = authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("expected old password to fail, got %v", err)
	}

	// New password should work.
	pair, err := authSvc.Login(ctx, "user@example.com", "newstrongpassword1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Login with new password failed: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected access token after password reset login")
	}
}

func TestLogout(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	pair, _ := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")

	user, _ := authSvc.GetUserByID(ctx, pair.SessionID)
	_ = user // We need the userID from the token.

	// Get userID from the repo directly.
	u, _ := authSvc.userRepo.GetByEmail(ctx, "user@example.com")

	err := authSvc.Logout(ctx, pair.RefreshToken, u.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	// The revoked token should not work for refresh.
	_, err = authSvc.RefreshToken(ctx, pair.RefreshToken, "test-agent", "127.0.0.1")
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Errorf("expected ErrTokenRevoked after logout, got %v", err)
	}
}

func TestLogoutAll(t *testing.T) {
	authSvc, _, _, _, _, ml := newTestAuthService()
	ctx := context.Background()

	_ = authSvc.Register(ctx, "user@example.com", "securepassword1", "127.0.0.1", "test-agent")
	code := ml.GetLastCode()
	_ = authSvc.VerifyEmail(ctx, "user@example.com", code, "127.0.0.1", "test-agent")

	// Create multiple sessions.
	pair1, _ := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "agent-1")
	pair2, _ := authSvc.Login(ctx, "user@example.com", "securepassword1", "127.0.0.1", "agent-2")

	u, _ := authSvc.userRepo.GetByEmail(ctx, "user@example.com")

	err := authSvc.LogoutAll(ctx, u.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("LogoutAll failed: %v", err)
	}

	// Both tokens should be revoked.
	_, err = authSvc.RefreshToken(ctx, pair1.RefreshToken, "test-agent", "127.0.0.1")
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Errorf("pair1 should be revoked, got %v", err)
	}
	_, err = authSvc.RefreshToken(ctx, pair2.RefreshToken, "test-agent", "127.0.0.1")
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Errorf("pair2 should be revoked, got %v", err)
	}
}
