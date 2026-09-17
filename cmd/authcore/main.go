package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

func main() {
	// Initialize structured logger.
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Load configuration from environment.
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("failed to load config", zap.Error(err))
	}

	// Connect to PostgreSQL and run migrations.
	pool, err := database.Connect(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to connect to database", zap.Error(err))
	}
	defer pool.Close()

	if err := database.RunMigrations(cfg.DatabaseURL); err != nil {
		logger.Fatal("failed to run migrations", zap.Error(err))
	}
	logger.Info("database migrations applied successfully")

	// Initialize mailer.
	ml := mailer.NewSMTPMailer(cfg.SMTP)

	// Initialize repositories.
	userRepo := repository.NewUserRepo(pool)
	sessionRepo := repository.NewSessionRepo(pool)
	otpRepo := repository.NewOTPRepo(pool)
	auditRepo := repository.NewAuditRepo(pool)

	// Initialize services.
	auditSvc := service.NewAuditService(auditRepo)
	tokenSvc := service.NewTokenService(cfg.JWT, sessionRepo)
	otpSvc := service.NewOTPService(otpRepo)
	authSvc := service.NewAuthService(userRepo, tokenSvc, otpSvc, auditSvc, ml, cfg.JWT)

	// Initialize rate limiter.
	rateLimiter := middleware.NewInMemoryRateLimiter(
		cfg.RateLimit.IPRequests,
		cfg.RateLimit.IPWindow,
		cfg.RateLimit.AccountRequests,
		cfg.RateLimit.AccountWindow,
	)

	// Build router.
	router := handler.NewRouter(
		authSvc,
		tokenSvc,
		auditSvc,
		pool,
		cfg,
		logger,
		rateLimiter,
	)

	// Create HTTP server.
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      router,
		ReadTimeout:  cfg.ServerReadTimeout,
		WriteTimeout: cfg.ServerWriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine.
	go func() {
		logger.Info("server starting", zap.Int("port", cfg.ServerPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", zap.Error(err))
		}
	}()

	// Wait for interrupt signal for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ServerShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("server forced to shutdown", zap.Error(err))
	}

	logger.Info("server stopped gracefully")
}
