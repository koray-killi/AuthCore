package domain

import (
	"fmt"
	"net/http"
)

// AppError is the application's typed error. All domain errors carry a machine-readable
// code, a human-readable message, and the corresponding HTTP status code.
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

// Error implements the error interface.
func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Predefined domain errors. Handlers never construct error responses directly;
// the httperr package maps these to JSON responses.
var (
	ErrInvalidCredentials = &AppError{
		Code:       "INVALID_CREDENTIALS",
		Message:    "Invalid email or password.",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrAccountLocked = &AppError{
		Code:       "ACCOUNT_LOCKED",
		Message:    "Account is temporarily locked due to too many failed login attempts.",
		HTTPStatus: http.StatusForbidden,
	}
	ErrEmailNotVerified = &AppError{
		Code:       "EMAIL_NOT_VERIFIED",
		Message:    "Please verify your email address before logging in.",
		HTTPStatus: http.StatusForbidden,
	}
	ErrEmailAlreadyExists = &AppError{
		Code:       "EMAIL_ALREADY_EXISTS",
		Message:    "An account with this email already exists.",
		HTTPStatus: http.StatusConflict,
	}
	ErrUserNotFound = &AppError{
		Code:       "USER_NOT_FOUND",
		Message:    "User not found.",
		HTTPStatus: http.StatusNotFound,
	}
	ErrWeakPassword = &AppError{
		Code:       "WEAK_PASSWORD",
		Message:    "Password must be at least 10 characters long.",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrTokenExpired = &AppError{
		Code:       "TOKEN_EXPIRED",
		Message:    "Token has expired.",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenInvalid = &AppError{
		Code:       "TOKEN_INVALID",
		Message:    "Token is invalid.",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrTokenRevoked = &AppError{
		Code:       "TOKEN_REVOKED",
		Message:    "Token has been revoked.",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrOTPExpired = &AppError{
		Code:       "OTP_EXPIRED",
		Message:    "Verification code has expired.",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrOTPInvalid = &AppError{
		Code:       "OTP_INVALID",
		Message:    "Invalid verification code.",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrOTPMaxAttempts = &AppError{
		Code:       "OTP_MAX_ATTEMPTS",
		Message:    "Maximum verification attempts exceeded. Please request a new code.",
		HTTPStatus: http.StatusTooManyRequests,
	}
	ErrRateLimited = &AppError{
		Code:       "RATE_LIMITED",
		Message:    "Too many requests. Please try again later.",
		HTTPStatus: http.StatusTooManyRequests,
	}
	ErrUnauthorized = &AppError{
		Code:       "UNAUTHORIZED",
		Message:    "Authentication required.",
		HTTPStatus: http.StatusUnauthorized,
	}
	ErrForbidden = &AppError{
		Code:       "FORBIDDEN",
		Message:    "You do not have permission to access this resource.",
		HTTPStatus: http.StatusForbidden,
	}
	ErrBadRequest = &AppError{
		Code:       "BAD_REQUEST",
		Message:    "Invalid request body.",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrInvalidEmail = &AppError{
		Code:       "INVALID_EMAIL",
		Message:    "Invalid email address format.",
		HTTPStatus: http.StatusBadRequest,
	}
	ErrInternal = &AppError{
		Code:       "INTERNAL_ERROR",
		Message:    "An internal error occurred.",
		HTTPStatus: http.StatusInternalServerError,
	}
)
