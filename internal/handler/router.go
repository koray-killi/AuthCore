package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/config"
	"github.com/koray-killi/AuthCore/internal/middleware"
	"github.com/koray-killi/AuthCore/internal/service"
	"go.uber.org/zap"
)

// NewRouter creates and configures the main HTTP router with all routes and middleware.
func NewRouter(
	authSvc *service.AuthService,
	tokenSvc *service.TokenService,
	auditSvc *service.AuditService,
	pool *pgxpool.Pool,
	cfg *config.Config,
	logger *zap.Logger,
	rateLimiter middleware.RateLimiter,
) http.Handler {
	r := chi.NewRouter()

	// Global middleware stack.
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(middleware.RequestLog(logger))
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.BodyLimit)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Initialize handlers.
	healthH := NewHealthHandler(pool)
	authH := NewAuthHandler(authSvc, auditSvc)

	// Health check — outside rate limiting.
	r.Get("/healthz", healthH.Healthz)

	// API v1 routes.
	r.Route("/api/v1", func(r chi.Router) {
		// Apply rate limiting to all API routes.
		r.Use(middleware.RateLimit(rateLimiter))

		// Public auth routes.
		r.Route("/auth", func(r chi.Router) {
			// Email-sending endpoints: strict per-email rate limit to prevent email bombing.
			r.Group(func(r chi.Router) {
				r.Use(middleware.EmailRateLimit(rateLimiter))
				r.Post("/register", authH.Register)
				r.Post("/resend-verification", authH.ResendVerification)
				r.Post("/forgot-password", authH.ForgotPassword)
			})

			r.Post("/verify-email", authH.VerifyEmail)
			// Login: per-account rate limit prevents credential-stuffing across shared IPs.
			r.With(middleware.AccountRateLimit(rateLimiter)).Post("/login", authH.Login)
			r.Post("/refresh", authH.Refresh)
			r.Post("/reset-password", authH.ResetPassword)

			// Protected auth routes (require valid JWT).
			r.Group(func(r chi.Router) {
				r.Use(middleware.Auth(tokenSvc))
				r.Post("/logout", authH.Logout)
				r.Post("/logout-all", authH.LogoutAll)
				r.Get("/me", authH.Me)
			})
		})

		// Admin routes (require JWT + admin role).
		r.Route("/admin", func(r chi.Router) {
			r.Use(middleware.Auth(tokenSvc))
			r.Use(middleware.RequireAdmin)
			r.Get("/audit-logs", authH.AuditLogs)
		})
	})

	return r
}
