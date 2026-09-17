package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
)

func TestOTPService_GenerateAndValidate(t *testing.T) {
	otpRepo := NewFakeOTPRepo()
	otpSvc := NewOTPService(otpRepo)
	ctx := context.Background()
	userID := uuid.New()

	code, err := otpSvc.Generate(ctx, userID, domain.OTPPurposeVerifyEmail)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("expected 6-digit code, got %q (len=%d)", code, len(code))
	}

	// Validate should succeed with the correct code.
	err = otpSvc.Validate(ctx, userID, domain.OTPPurposeVerifyEmail, code)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Should not validate again (already consumed).
	err = otpSvc.Validate(ctx, userID, domain.OTPPurposeVerifyEmail, code)
	if err == nil {
		t.Error("expected error when validating consumed OTP")
	}
}

func TestOTPService_WrongCode(t *testing.T) {
	otpRepo := NewFakeOTPRepo()
	otpSvc := NewOTPService(otpRepo)
	ctx := context.Background()
	userID := uuid.New()

	_, err := otpSvc.Generate(ctx, userID, domain.OTPPurposeVerifyEmail)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	err = otpSvc.Validate(ctx, userID, domain.OTPPurposeVerifyEmail, "999999")
	if !errors.Is(err, domain.ErrOTPInvalid) {
		t.Errorf("expected ErrOTPInvalid, got %v", err)
	}
}

func TestOTPService_Expired(t *testing.T) {
	otpRepo := NewFakeOTPRepo()
	otpSvc := NewOTPService(otpRepo)
	ctx := context.Background()
	userID := uuid.New()

	_, err := otpSvc.Generate(ctx, userID, domain.OTPPurposeVerifyEmail)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Manually expire the OTP.
	otpRepo.mu.Lock()
	for _, o := range otpRepo.otps {
		if o.UserID == userID {
			expired := time.Now().Add(-1 * time.Hour)
			o.ExpiresAt = expired
		}
	}
	otpRepo.mu.Unlock()

	err = otpSvc.Validate(ctx, userID, domain.OTPPurposeVerifyEmail, "000000")
	if !errors.Is(err, domain.ErrOTPExpired) {
		t.Errorf("expected ErrOTPExpired, got %v", err)
	}
}

func TestOTPService_MaxAttempts(t *testing.T) {
	otpRepo := NewFakeOTPRepo()
	otpSvc := NewOTPService(otpRepo)
	ctx := context.Background()
	userID := uuid.New()

	_, err := otpSvc.Generate(ctx, userID, domain.OTPPurposeVerifyEmail)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Manually set attempt count to max.
	otpRepo.mu.Lock()
	for _, o := range otpRepo.otps {
		if o.UserID == userID {
			o.AttemptCount = domain.OTPMaxAttempts
		}
	}
	otpRepo.mu.Unlock()

	err = otpSvc.Validate(ctx, userID, domain.OTPPurposeVerifyEmail, "000000")
	if !errors.Is(err, domain.ErrOTPMaxAttempts) {
		t.Errorf("expected ErrOTPMaxAttempts, got %v", err)
	}
}
