package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/middleware"
	"github.com/koray-killi/AuthCore/internal/service"
)

const (
	refreshCookieName = "refresh_token"
	refreshCookiePath = "/api/v1/auth"
)

// AuthHandler handles all /auth/* endpoints.
type AuthHandler struct {
	authSvc  *service.AuthService
	auditSvc *service.AuditService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authSvc *service.AuthService, auditSvc *service.AuditService) *AuthHandler {
	return &AuthHandler{
		authSvc:  authSvc,
		auditSvc: auditSvc,
	}
}

// Register handles POST /auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Password == "" {
		middleware.HandleError(w, domain.ErrBadRequest)
		return
	}
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	if err := h.authSvc.Register(r.Context(), req.Email, req.Password, ip, ua); err != nil {
		middleware.HandleError(w, err)
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, MessageResponse{
		Message: "Registration successful. Please check your email for the verification code.",
	})
}

// VerifyEmail handles POST /auth/verify-email.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Code == "" {
		middleware.HandleError(w, domain.ErrBadRequest)
		return
	}
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	if err := h.authSvc.VerifyEmail(r.Context(), req.Email, req.Code, ip, ua); err != nil {
		middleware.HandleError(w, err)
		return
	}

	middleware.WriteJSON(w, http.StatusOK, MessageResponse{
		Message: "Email verified successfully.",
	})
}

// ResendVerification handles POST /auth/resend-verification.
// Always returns 202 Accepted to prevent user enumeration.
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req ResendVerificationRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	// Fire-and-forget — always return 202 regardless of outcome.
	h.authSvc.ResendVerification(r.Context(), req.Email, ip, ua)

	middleware.WriteJSON(w, http.StatusAccepted, MessageResponse{
		Message: "If your account is pending verification, a new code has been sent.",
	})
}

// Login handles POST /auth/login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Password == "" {
		middleware.HandleError(w, domain.ErrBadRequest)
		return
	}
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	pair, err := h.authSvc.Login(r.Context(), req.Email, req.Password, ip, ua)
	if err != nil {
		middleware.HandleError(w, err)
		return
	}

	// Set refresh token as httpOnly, Secure, SameSite=Strict cookie.
	setRefreshCookie(w, pair.RefreshToken, pair.ExpiresAt)

	middleware.WriteJSON(w, http.StatusOK, TokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   900, // 15 minutes in seconds
	})
}

// Refresh handles POST /auth/refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		middleware.HandleError(w, domain.ErrTokenInvalid)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	pair, err := h.authSvc.RefreshToken(r.Context(), cookie.Value, ua, ip)
	if err != nil {
		// Clear the invalid cookie.
		clearRefreshCookie(w)
		middleware.HandleError(w, err)
		return
	}

	setRefreshCookie(w, pair.RefreshToken, pair.ExpiresAt)

	middleware.WriteJSON(w, http.StatusOK, TokenResponse{
		AccessToken: pair.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   900,
	})
}

// Logout handles POST /auth/logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(uuid.UUID)
	if !ok {
		middleware.HandleError(w, domain.ErrUnauthorized)
		return
	}

	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		// Even without a refresh cookie, clear it and return success.
		clearRefreshCookie(w)
		middleware.WriteJSON(w, http.StatusOK, MessageResponse{Message: "Logged out."})
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	_ = h.authSvc.Logout(r.Context(), cookie.Value, userID, ip, ua)
	clearRefreshCookie(w)

	middleware.WriteJSON(w, http.StatusOK, MessageResponse{Message: "Logged out."})
}

// LogoutAll handles POST /auth/logout-all.
func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(uuid.UUID)
	if !ok {
		middleware.HandleError(w, domain.ErrUnauthorized)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	if err := h.authSvc.LogoutAll(r.Context(), userID, ip, ua); err != nil {
		middleware.HandleError(w, err)
		return
	}

	clearRefreshCookie(w)
	middleware.WriteJSON(w, http.StatusOK, MessageResponse{Message: "All sessions revoked."})
}

// ForgotPassword handles POST /auth/forgot-password.
// Always returns 202 Accepted to prevent user enumeration.
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	// Fire-and-forget — always return 202 regardless of whether user exists.
	h.authSvc.ForgotPassword(r.Context(), req.Email, ip, ua)

	middleware.WriteJSON(w, http.StatusAccepted, MessageResponse{
		Message: "If an account with that email exists, a password reset code has been sent.",
	})
}

// ResetPassword handles POST /auth/reset-password.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest
	if err := middleware.DecodeJSON(r, &req); err != nil {
		middleware.HandleError(w, err)
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Code == "" || req.NewPassword == "" {
		middleware.HandleError(w, domain.ErrBadRequest)
		return
	}
	if err := middleware.ValidateEmail(req.Email); err != nil {
		middleware.HandleError(w, err)
		return
	}

	ip := middleware.ExtractIP(r)
	ua := r.UserAgent()

	if err := h.authSvc.ResetPassword(r.Context(), req.Email, req.Code, req.NewPassword, ip, ua); err != nil {
		middleware.HandleError(w, err)
		return
	}

	middleware.WriteJSON(w, http.StatusOK, MessageResponse{
		Message: "Password has been reset successfully. Please log in with your new password.",
	})
}

// Me handles GET /auth/me.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.UserIDKey).(uuid.UUID)
	if !ok {
		middleware.HandleError(w, domain.ErrUnauthorized)
		return
	}

	user, err := h.authSvc.GetUserByID(r.Context(), userID)
	if err != nil {
		middleware.HandleError(w, err)
		return
	}

	// Map domain model to response DTO — never expose password_hash.
	middleware.WriteJSON(w, http.StatusOK, UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Role:      user.Role,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// AuditLogs handles GET /admin/audit-logs.
func (h *AuthHandler) AuditLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))

	result, err := h.auditSvc.ListAll(r.Context(), page, pageSize)
	if err != nil {
		middleware.HandleError(w, err)
		return
	}

	// Map domain audit logs to response DTOs.
	dtos := make([]AuditLogResponse, len(result.Logs))
	for i, log := range result.Logs {
		dtos[i] = AuditLogResponse{
			ID:        log.ID,
			UserID:    log.UserID,
			Action:    log.Action,
			IP:        log.IP,
			UserAgent: log.UserAgent,
			Metadata:  log.Metadata,
			CreatedAt: log.CreatedAt,
		}
	}

	middleware.WriteJSON(w, http.StatusOK, PaginatedResponse{
		Data:       dtos,
		Total:      result.Total,
		Page:       result.Page,
		PageSize:   result.PageSize,
		TotalPages: result.TotalPages,
	})
}

// setRefreshCookie sets the refresh token as an httpOnly, Secure, SameSite=Strict cookie.
func setRefreshCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearRefreshCookie removes the refresh token cookie.
func clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
