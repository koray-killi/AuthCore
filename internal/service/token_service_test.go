package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/config"
)

func newTestTokenService() (*TokenService, *FakeSessionRepo) {
	sessionRepo := NewFakeSessionRepo()
	jwtCfg := config.JWTConfig{
		Secret:        "test-secret-key-for-unit-tests",
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 7 * 24 * time.Hour,
	}
	return NewTokenService(jwtCfg, sessionRepo), sessionRepo
}

func TestGenerateAndValidateAccessToken(t *testing.T) {
	tokenSvc, _ := newTestTokenService()
	userID := uuid.New()

	token, err := tokenSvc.GenerateAccessToken(userID, "user")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	parsedID, role, err := tokenSvc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if parsedID != userID {
		t.Errorf("expected userID %s, got %s", userID, parsedID)
	}
	if role != "user" {
		t.Errorf("expected role 'user', got %q", role)
	}
}

func TestValidateAccessToken_InvalidToken(t *testing.T) {
	tokenSvc, _ := newTestTokenService()

	_, _, err := tokenSvc.ValidateAccessToken("invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestValidateAccessToken_WrongSecret(t *testing.T) {
	sessionRepo := NewFakeSessionRepo()
	tokenSvc1 := NewTokenService(config.JWTConfig{
		Secret:       "secret-1",
		AccessExpiry: 15 * time.Minute,
	}, sessionRepo)
	tokenSvc2 := NewTokenService(config.JWTConfig{
		Secret:       "secret-2",
		AccessExpiry: 15 * time.Minute,
	}, sessionRepo)

	token, _ := tokenSvc1.GenerateAccessToken(uuid.New(), "user")
	_, _, err := tokenSvc2.ValidateAccessToken(token)
	if err == nil {
		t.Error("expected error when validating with wrong secret")
	}
}

func TestIssueTokenPair(t *testing.T) {
	tokenSvc, sessionRepo := newTestTokenService()
	ctx := context.Background()
	userID := uuid.New()

	pair, err := tokenSvc.IssueTokenPair(ctx, userID, "user", "test-agent", "127.0.0.1")
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if pair.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}

	// Verify session was created in the repository.
	sessionRepo.mu.RLock()
	if len(sessionRepo.sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessionRepo.sessions))
	}
	sessionRepo.mu.RUnlock()
}

func TestHashToken_Deterministic(t *testing.T) {
	token := "test-refresh-token"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

	if hash1 != hash2 {
		t.Error("HashToken should be deterministic")
	}

	hash3 := HashToken("different-token")
	if hash1 == hash3 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "securepassword1"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should return true for correct password")
	}

	if VerifyPassword("wrongpassword!", hash) {
		t.Error("VerifyPassword should return false for wrong password")
	}
}

func TestPasswordHashing_UniqueHashesForSamePassword(t *testing.T) {
	password := "securepassword1"

	hash1, _ := HashPassword(password)
	hash2, _ := HashPassword(password)

	if hash1 == hash2 {
		t.Error("same password should produce different hashes (due to random salt)")
	}

	// Both should verify correctly.
	if !VerifyPassword(password, hash1) {
		t.Error("hash1 should verify correctly")
	}
	if !VerifyPassword(password, hash2) {
		t.Error("hash2 should verify correctly")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		password string
		wantErr  bool
	}{
		{"short", true},
		{"123456789", true},  // 9 chars
		{"1234567890", false}, // 10 chars
		{"a-long-secure-password", false},
	}

	for _, tt := range tests {
		err := ValidatePasswordStrength(tt.password)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePasswordStrength(%q): got err=%v, wantErr=%v", tt.password, err, tt.wantErr)
		}
	}
}
