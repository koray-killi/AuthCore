// Package middleware provides HTTP middleware for authentication, rate limiting,
// request logging, and validation.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/httperr"
	"github.com/koray-killi/AuthCore/internal/service"
)

type contextKey string

const (
	// UserIDKey is the context key for the authenticated user's ID.
	UserIDKey contextKey = "userID"
	// UserRoleKey is the context key for the authenticated user's role.
	UserRoleKey contextKey = "userRole"
)

// Auth is a middleware that extracts and validates the JWT from the Authorization header.
// On success, it sets the user ID and role in the request context.
func Auth(tokenSvc *service.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httperr.Write(w, domain.ErrUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				httperr.Write(w, domain.ErrUnauthorized)
				return
			}

			userID, role, err := tokenSvc.ValidateAccessToken(parts[1])
			if err != nil {
				httperr.Write(w, err)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, UserRoleKey, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdmin is a middleware that checks if the authenticated user has the "admin" role.
// It must be used after the Auth middleware.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role, ok := r.Context().Value(UserRoleKey).(string)
		if !ok || role != "admin" {
			httperr.Write(w, domain.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
