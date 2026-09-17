package service

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// --- Fake Repositories for Unit Testing ---

// FakeUserRepo is an in-memory UserRepository for testing.
type FakeUserRepo struct {
	mu    sync.RWMutex
	users map[uuid.UUID]*domain.User
}

func NewFakeUserRepo() *FakeUserRepo {
	return &FakeUserRepo{users: make(map[uuid.UUID]*domain.User)}
}

func (r *FakeUserRepo) Create(_ context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, u := range r.users {
		if u.Email == user.Email {
			return domain.ErrEmailAlreadyExists
		}
	}
	// Deep copy to prevent test mutation issues.
	clone := *user
	r.users[user.ID] = &clone
	return nil
}

func (r *FakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	clone := *u
	return &clone, nil
}

func (r *FakeUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Email == email {
			clone := *u
			return &clone, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *FakeUserRepo) UpdatePassword(_ context.Context, id uuid.UUID, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.PasswordHash = passwordHash
	u.UpdatedAt = time.Now()
	return nil
}

func (r *FakeUserRepo) IncrementFailedLogin(_ context.Context, id uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return 0, domain.ErrUserNotFound
	}
	u.FailedLoginCount++
	return u.FailedLoginCount, nil
}

func (r *FakeUserRepo) ResetFailedLogin(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.FailedLoginCount = 0
	u.LockedUntil = nil
	return nil
}

func (r *FakeUserRepo) LockUntil(_ context.Context, id uuid.UUID, until time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.LockedUntil = &until
	return nil
}

func (r *FakeUserRepo) ActivateUser(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	u, ok := r.users[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.IsActive = true
	return nil
}

// FakeSessionRepo is an in-memory SessionRepository for testing.
type FakeSessionRepo struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*domain.RefreshSession
}

func NewFakeSessionRepo() *FakeSessionRepo {
	return &FakeSessionRepo{sessions: make(map[uuid.UUID]*domain.RefreshSession)}
}

func (r *FakeSessionRepo) Create(_ context.Context, session *domain.RefreshSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	clone := *session
	r.sessions[session.ID] = &clone
	return nil
}

func (r *FakeSessionRepo) GetByTokenHash(_ context.Context, tokenHash string) (*domain.RefreshSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, s := range r.sessions {
		if s.TokenHash == tokenHash {
			clone := *s
			return &clone, nil
		}
	}
	return nil, domain.ErrTokenInvalid
}

func (r *FakeSessionRepo) RevokeByID(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[id]
	if !ok {
		return nil
	}
	now := time.Now()
	s.RevokedAt = &now
	return nil
}

func (r *FakeSessionRepo) RevokeAllByUserID(_ context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for _, s := range r.sessions {
		if s.UserID == userID && s.RevokedAt == nil {
			s.RevokedAt = &now
		}
	}
	return nil
}

func (r *FakeSessionRepo) MarkReplacedBy(_ context.Context, oldID, newID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sessions[oldID]
	if !ok {
		return nil
	}
	s.ReplacedBy = &newID
	return nil
}

// FakeOTPRepo is an in-memory OTPRepository for testing.
type FakeOTPRepo struct {
	mu   sync.RWMutex
	otps []*domain.OTPCode
}

func NewFakeOTPRepo() *FakeOTPRepo {
	return &FakeOTPRepo{}
}

func (r *FakeOTPRepo) Create(_ context.Context, otp *domain.OTPCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	clone := *otp
	r.otps = append(r.otps, &clone)
	return nil
}

func (r *FakeOTPRepo) GetLatestValid(_ context.Context, userID uuid.UUID, purpose string) (*domain.OTPCode, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := len(r.otps) - 1; i >= 0; i-- {
		o := r.otps[i]
		if o.UserID == userID && o.Purpose == purpose && o.ConsumedAt == nil {
			clone := *o
			return &clone, nil
		}
	}
	return nil, domain.ErrOTPInvalid
}

func (r *FakeOTPRepo) IncrementAttempt(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, o := range r.otps {
		if o.ID == id {
			o.AttemptCount++
			return nil
		}
	}
	return nil
}

func (r *FakeOTPRepo) Consume(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, o := range r.otps {
		if o.ID == id {
			now := time.Now()
			o.ConsumedAt = &now
			return nil
		}
	}
	return nil
}

// FakeAuditRepo is an in-memory AuditRepository for testing.
type FakeAuditRepo struct {
	mu   sync.RWMutex
	logs []*domain.AuditLog
}

func NewFakeAuditRepo() *FakeAuditRepo {
	return &FakeAuditRepo{}
}

func (r *FakeAuditRepo) Insert(_ context.Context, log *domain.AuditLog) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	clone := *log
	r.logs = append(r.logs, &clone)
	return nil
}

func (r *FakeAuditRepo) ListByUserID(_ context.Context, userID uuid.UUID, page, pageSize int) ([]domain.AuditLog, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var filtered []domain.AuditLog
	for _, l := range r.logs {
		if l.UserID != nil && *l.UserID == userID {
			filtered = append(filtered, *l)
		}
	}

	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		return nil, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return filtered[start:end], total, nil
}

func (r *FakeAuditRepo) ListAll(_ context.Context, page, pageSize int) ([]domain.AuditLog, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := len(r.logs)
	start := (page - 1) * pageSize
	if start >= total {
		return nil, total, nil
	}
	end := start + pageSize
	if end > total {
		end = total
	}

	result := make([]domain.AuditLog, end-start)
	for i := start; i < end; i++ {
		result[i-start] = *r.logs[i]
	}
	return result, total, nil
}

// GetLogs returns all stored audit logs for test assertions.
func (r *FakeAuditRepo) GetLogs() []domain.AuditLog {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]domain.AuditLog, len(r.logs))
	for i, l := range r.logs {
		result[i] = *l
	}
	return result
}

// FakeMailer is a test mailer that records sent emails.
type FakeMailer struct {
	mu     sync.Mutex
	Emails []FakeEmail
}

type FakeEmail struct {
	To      string
	Code    string
	Purpose string
}

func NewFakeMailer() *FakeMailer {
	return &FakeMailer{}
}

func (m *FakeMailer) SendVerificationEmail(to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Emails = append(m.Emails, FakeEmail{To: to, Code: code, Purpose: "verify_email"})
	return nil
}

func (m *FakeMailer) SendPasswordResetEmail(to, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Emails = append(m.Emails, FakeEmail{To: to, Code: code, Purpose: "reset_password"})
	return nil
}

// GetLastCode returns the last OTP code sent.
func (m *FakeMailer) GetLastCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Emails) == 0 {
		return ""
	}
	return m.Emails[len(m.Emails)-1].Code
}
