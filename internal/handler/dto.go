package handler

import (
	"time"

	"github.com/google/uuid"
)

// --- Request DTOs ---

// RegisterRequest is the request body for POST /auth/register.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the request body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// VerifyEmailRequest is the request body for POST /auth/verify-email.
type VerifyEmailRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// ForgotPasswordRequest is the request body for POST /auth/forgot-password.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ResetPasswordRequest is the request body for POST /auth/reset-password.
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

// --- Response DTOs ---
// IMPORTANT: These DTOs must NEVER contain password_hash, otp_hash, or token_hash fields.

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TokenResponse is returned on successful login or token refresh.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"` // seconds
}

// MessageResponse is a generic success response.
type MessageResponse struct {
	Message string `json:"message"`
}

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"db"`
}

// AuditLogResponse is the public representation of an audit log entry.
type AuditLogResponse struct {
	ID        uuid.UUID              `json:"id"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	Action    string                 `json:"action"`
	IP        string                 `json:"ip"`
	UserAgent string                 `json:"user_agent"`
	Metadata  map[string]interface{} `json:"metadata"`
	CreatedAt time.Time              `json:"created_at"`
}

// PaginatedResponse wraps a paginated result set.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}
