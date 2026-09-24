// Package config provides application configuration loaded from environment variables.
// Configuration is passed as a value, never stored as global mutable state.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all application configuration parameters.
type Config struct {
	ServerPort            int
	ServerReadTimeout     time.Duration
	ServerWriteTimeout    time.Duration
	ServerShutdownTimeout time.Duration

	DatabaseURL string

	JWT JWTConfig

	SMTP SMTPConfig

	CORSAllowedOrigins []string

	RateLimit RateLimitConfig
}

// JWTConfig holds JWT-related configuration.
type JWTConfig struct {
	Secret        string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

// SMTPConfig holds SMTP mail configuration.
type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Username string
	Password string
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	IPRequests      int
	IPWindow        time.Duration
	AccountRequests int
	AccountWindow   time.Duration
	// EmailRequests limits how many email-sending actions (register, resend) are allowed
	// per email address in EmailWindow. Prevents email bombing.
	EmailRequests int
	EmailWindow   time.Duration
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		// SERVER_PORT is the primary var; fall back to PORT so Railway/Fly.io work
		// without extra configuration (they inject PORT automatically).
		ServerPort:            getEnvIntFallback("SERVER_PORT", "PORT", 8080),
		ServerReadTimeout:     getEnvDuration("SERVER_READ_TIMEOUT", 10*time.Second),
		ServerWriteTimeout:    getEnvDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
		ServerShutdownTimeout: getEnvDuration("SERVER_SHUTDOWN_TIMEOUT", 15*time.Second),

		DatabaseURL: getEnv("DATABASE_URL", ""),

		JWT: JWTConfig{
			Secret:        getEnv("JWT_SECRET", ""),
			AccessExpiry:  getEnvDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshExpiry: getEnvDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
		},

		SMTP: SMTPConfig{
			Host:     getEnv("SMTP_HOST", "localhost"),
			Port:     getEnvInt("SMTP_PORT", 1025),
			From:     getEnv("SMTP_FROM", "noreply@authcore.local"),
			Username: getEnv("SMTP_USERNAME", ""),
			Password: getEnv("SMTP_PASSWORD", ""),
		},

		CORSAllowedOrigins: getEnvSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),

		RateLimit: RateLimitConfig{
			IPRequests:      getEnvInt("RATE_LIMIT_IP_REQUESTS", 60),
			IPWindow:        getEnvDuration("RATE_LIMIT_IP_WINDOW", 1*time.Minute),
			AccountRequests: getEnvInt("RATE_LIMIT_ACCOUNT_REQUESTS", 10),
			AccountWindow:   getEnvDuration("RATE_LIMIT_ACCOUNT_WINDOW", 1*time.Minute),
			EmailRequests:   getEnvInt("RATE_LIMIT_EMAIL_REQUESTS", 3),
			EmailWindow:     getEnvDuration("RATE_LIMIT_EMAIL_WINDOW", 10*time.Minute),
		},
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return n
}

// getEnvIntFallback tries primary, then secondary, then the int fallback.
// Used for port resolution: SERVER_PORT > PORT > 8080.
func getEnvIntFallback(primary, secondary string, fallback int) int {
	if v, ok := os.LookupEnv(primary); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return getEnvInt(secondary, fallback)
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fallback
	}
	return d
}

func getEnvSlice(key string, fallback []string) []string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
