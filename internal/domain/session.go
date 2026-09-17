package domain

import (
	"time"

	"github.com/google/uuid"
)

// RefreshSession represents a refresh token session in the database.
// The raw token is never stored — only a SHA-256 hash (token_hash).
type RefreshSession struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	UserAgent  string
	IP         string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *uuid.UUID
	CreatedAt  time.Time
}

// IsRevoked returns true if the session has been explicitly revoked.
func (s *RefreshSession) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsExpired returns true if the session has passed its expiration time.
func (s *RefreshSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// OTPCode represents a one-time password code for email verification or password reset.
// The plain code is never stored — only a hash (code_hash).
type OTPCode struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Purpose      string
	CodeHash     string
	AttemptCount int
	ExpiresAt    time.Time
	ConsumedAt   *time.Time
	CreatedAt    time.Time
}

// OTP purpose constants.
const (
	OTPPurposeVerifyEmail   = "verify_email"
	OTPPurposeResetPassword = "reset_password"
)

// OTP validation limits.
const (
	OTPMaxAttempts = 5
	OTPExpiryMins  = 10
)

// IsExpired returns true if the OTP has passed its expiration time.
func (o *OTPCode) IsExpired() bool {
	return time.Now().After(o.ExpiresAt)
}

// IsConsumed returns true if the OTP has already been used.
func (o *OTPCode) IsConsumed() bool {
	return o.ConsumedAt != nil
}

// IsMaxAttemptsReached returns true if the OTP has exceeded the maximum verification attempts.
func (o *OTPCode) IsMaxAttemptsReached() bool {
	return o.AttemptCount >= OTPMaxAttempts
}

// AuditLog represents an immutable audit log entry.
// This table is append-only: no UPDATE or DELETE operations are permitted.
type AuditLog struct {
	ID        uuid.UUID
	UserID    *uuid.UUID
	Action    string
	IP        string
	UserAgent string
	Metadata  map[string]interface{}
	CreatedAt time.Time
}

// Audit action constants.
const (
	AuditActionRegister             = "register"
	AuditActionLogin                = "login"
	AuditActionLoginFailed          = "login_failed"
	AuditActionLogout               = "logout"
	AuditActionLogoutAll            = "logout_all"
	AuditActionRefreshToken         = "refresh_token"
	AuditActionRefreshReuseDetected = "refresh_reuse_detected"
	AuditActionVerifyEmail          = "verify_email"
	AuditActionForgotPassword       = "forgot_password"
	AuditActionResetPassword        = "reset_password"
	AuditActionAccountLocked        = "account_locked"
)
