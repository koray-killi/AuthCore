package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/mailer"
	"github.com/koray-killi/AuthCore/internal/repository"
)

const (
	maxFailedLogins = 5
	lockDuration    = 15 * time.Minute
)

// AuthService orchestrates authentication workflows.
// It coordinates between repositories, token service, OTP service, audit service, and mailer.
type AuthService struct {
	userRepo repository.UserRepository
	tokenSvc *TokenService
	otpSvc   *OTPService
	auditSvc *AuditService
	mailer   mailer.Mailer
	jwtCfg   config.JWTConfig
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	userRepo repository.UserRepository,
	tokenSvc *TokenService,
	otpSvc *OTPService,
	auditSvc *AuditService,
	ml mailer.Mailer,
	jwtCfg config.JWTConfig,
) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		tokenSvc: tokenSvc,
		otpSvc:   otpSvc,
		auditSvc: auditSvc,
		mailer:   ml,
		jwtCfg:   jwtCfg,
	}
}

// Register creates a new user account or sends a new OTP for an inactive one.
// The account is inactive until email verification.
func (s *AuthService) Register(ctx context.Context, email, password, ip, userAgent string) error {
	if err := ValidatePasswordStrength(password); err != nil {
		return err
	}

	// Check if user already exists.
	if existing, err := s.userRepo.GetByEmail(ctx, email); err == nil {
		if existing.IsActive {
			return domain.ErrEmailAlreadyExists
		}
		// User exists but inactive. Resend OTP.
		return s.sendVerificationOTP(ctx, existing, ip, userAgent)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	now := time.Now()
	user := &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: hash,
		Role:         "user",
		IsActive:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return err
	}

	return s.sendVerificationOTP(ctx, user, ip, userAgent)
}

// sendVerificationOTP invalidates pending OTPs, generates a new one, and sends the email.
func (s *AuthService) sendVerificationOTP(ctx context.Context, user *domain.User, ip, userAgent string) error {
	_ = s.otpSvc.InvalidatePending(ctx, user.ID, domain.OTPPurposeVerifyEmail)

	code, err := s.otpSvc.Generate(ctx, user.ID, domain.OTPPurposeVerifyEmail)
	if err != nil {
		return fmt.Errorf("generate verification otp: %w", err)
	}

	if err := s.mailer.SendVerificationEmail(user.Email, code); err != nil {
		s.auditSvc.Log(ctx, "email_send_failed", &user.ID, ip, userAgent, map[string]interface{}{
			"purpose": "verify_email",
			"error":   err.Error(),
		})
	}

	s.auditSvc.Log(ctx, domain.AuditActionRegister, &user.ID, ip, userAgent, nil)
	return nil
}

// ResendVerification sends a new verification OTP.
// Returns silently if user is active or not found (enumeration safe).
func (s *AuthService) ResendVerification(ctx context.Context, email, ip, userAgent string) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return
	}
	if user.IsActive {
		return
	}

	_ = s.sendVerificationOTP(ctx, user, ip, userAgent)
	s.auditSvc.Log(ctx, "resend_verification", &user.ID, ip, userAgent, nil)
}

// VerifyEmail validates the OTP code and activates the user account.
func (s *AuthService) VerifyEmail(ctx context.Context, email, code, ip, userAgent string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return domain.ErrOTPInvalid
	}

	if err := s.otpSvc.Validate(ctx, user.ID, domain.OTPPurposeVerifyEmail, code); err != nil {
		return err
	}

	if err := s.userRepo.ActivateUser(ctx, user.ID); err != nil {
		return fmt.Errorf("activate user: %w", err)
	}

	s.auditSvc.Log(ctx, domain.AuditActionVerifyEmail, &user.ID, ip, userAgent, nil)
	return nil
}

// Login authenticates a user and returns a token pair. It enforces:
// - Enumeration safety: performs a dummy hash comparison for non-existent users.
// - Account lock after 5 failed attempts (15 minute window).
// - Email verification check.
func (s *AuthService) Login(ctx context.Context, email, password, ip, userAgent string) (*TokenPair, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// Enumeration defense: always run Argon2id verification to keep constant timing.
		_ = VerifyPassword(password, dummyHash)
		return nil, domain.ErrInvalidCredentials
	}

	// Check account lock.
	if user.IsLocked() {
		// Still perform hash comparison to prevent timing leak.
		_ = VerifyPassword(password, user.PasswordHash)
		return nil, domain.ErrAccountLocked
	}

	// Verify password with constant-time comparison.
	if !VerifyPassword(password, user.PasswordHash) {
		count, _ := s.userRepo.IncrementFailedLogin(ctx, user.ID)

		if count >= maxFailedLogins {
			lockUntil := time.Now().Add(lockDuration)
			_ = s.userRepo.LockUntil(ctx, user.ID, lockUntil)
			s.auditSvc.Log(ctx, domain.AuditActionAccountLocked, &user.ID, ip, userAgent, map[string]interface{}{
				"locked_until": lockUntil.Format(time.RFC3339),
			})
		}

		s.auditSvc.Log(ctx, domain.AuditActionLoginFailed, &user.ID, ip, userAgent, map[string]interface{}{
			"failed_count": count,
		})
		return nil, domain.ErrInvalidCredentials
	}

	// Check email verification.
	if !user.IsActive {
		return nil, domain.ErrEmailNotVerified
	}

	// Reset failed login counter on success.
	_ = s.userRepo.ResetFailedLogin(ctx, user.ID)

	pair, err := s.tokenSvc.IssueTokenPair(ctx, user.ID, user.Role, userAgent, ip)
	if err != nil {
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	s.auditSvc.Log(ctx, domain.AuditActionLogin, &user.ID, ip, userAgent, nil)
	return pair, nil
}

// RefreshToken rotates the refresh token. On reuse detection, all user sessions are revoked.
func (s *AuthService) RefreshToken(ctx context.Context, oldRawToken, userAgent, ip string) (*TokenPair, error) {
	pair, userID, err := s.tokenSvc.RotateRefreshToken(ctx, oldRawToken, userAgent, ip)
	if err != nil {
		if errors.Is(err, domain.ErrTokenRevoked) {
			// Reuse detected — audit log it.
			s.auditSvc.Log(ctx, domain.AuditActionRefreshReuseDetected, &userID, ip, userAgent, nil)
			return nil, domain.ErrTokenRevoked
		}
		return nil, err
	}

	// If RotateRefreshToken returned a valid pair, we need to get the user for role.
	// The role was already embedded in the access token by IssueTokenPair using the
	// session's stored userID. We need to re-fetch for the proper role.
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Re-issue access token with the correct role.
	accessToken, err := s.tokenSvc.GenerateAccessToken(userID, user.Role)
	if err != nil {
		return nil, err
	}
	pair.AccessToken = accessToken

	s.auditSvc.Log(ctx, domain.AuditActionRefreshToken, &userID, ip, userAgent, nil)
	return pair, nil
}

// Logout revokes the current refresh session.
func (s *AuthService) Logout(ctx context.Context, rawToken string, userID uuid.UUID, ip, userAgent string) error {
	if err := s.tokenSvc.RevokeSession(ctx, rawToken); err != nil {
		return err
	}
	s.auditSvc.Log(ctx, domain.AuditActionLogout, &userID, ip, userAgent, nil)
	return nil
}

// LogoutAll revokes all refresh sessions for the authenticated user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, ip, userAgent string) error {
	if err := s.tokenSvc.RevokeAllSessions(ctx, userID); err != nil {
		return err
	}
	s.auditSvc.Log(ctx, domain.AuditActionLogoutAll, &userID, ip, userAgent, nil)
	return nil
}

// ForgotPassword sends a password reset OTP if the user exists. Always returns nil
// to prevent user enumeration — the caller always responds with 202 Accepted.
func (s *AuthService) ForgotPassword(ctx context.Context, email, ip, userAgent string) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		// User doesn't exist — do nothing, but don't reveal this.
		return
	}

	code, err := s.otpSvc.Generate(ctx, user.ID, domain.OTPPurposeResetPassword)
	if err != nil {
		return
	}

	_ = s.mailer.SendPasswordResetEmail(email, code)
	s.auditSvc.Log(ctx, domain.AuditActionForgotPassword, &user.ID, ip, userAgent, nil)
}

// ResetPassword validates the OTP, updates the password, and revokes all sessions.
func (s *AuthService) ResetPassword(ctx context.Context, email, code, newPassword, ip, userAgent string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return domain.ErrOTPInvalid
	}

	if err := s.otpSvc.Validate(ctx, user.ID, domain.OTPPurposeResetPassword, code); err != nil {
		return err
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, user.ID, hash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Revoke all sessions — password change invalidates all tokens.
	_ = s.tokenSvc.RevokeAllSessions(ctx, user.ID)

	s.auditSvc.Log(ctx, domain.AuditActionResetPassword, &user.ID, ip, userAgent, nil)
	return nil
}

// GetUserByID returns the user for the authenticated /me endpoint.
func (s *AuthService) GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

// dummyHash is a pre-computed Argon2id hash used to prevent timing-based user enumeration.
// When a login attempt is made for a non-existent user, we still run the Argon2id comparison
// against this hash so the response time is indistinguishable from a valid user lookup.
var dummyHash = func() string {
	h, _ := HashPassword("dummy-password-for-timing-safety")
	return h
}()
