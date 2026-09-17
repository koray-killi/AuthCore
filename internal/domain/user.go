// Package domain defines the core business entities for the AuthCore service.
// These structs represent the internal data model and are never serialized directly to JSON.
// Response DTOs in the handler package provide the external representation.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents an application user. The PasswordHash field must never
// appear in any API response — mapping to DTOs happens in the handler layer.
type User struct {
	ID               uuid.UUID
	Email            string
	PasswordHash     string
	Role             string
	IsActive         bool
	FailedLoginCount int
	LockedUntil      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// IsLocked returns true if the account is currently locked due to failed login attempts.
func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}
