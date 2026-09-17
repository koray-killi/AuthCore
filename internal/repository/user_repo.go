// Package repository provides data access interfaces and their PostgreSQL implementations.
// Repositories contain no business logic — they only translate between domain structs and SQL.
package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// UserRepository defines data access operations for users.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	IncrementFailedLogin(ctx context.Context, id uuid.UUID) (int, error)
	ResetFailedLogin(ctx context.Context, id uuid.UUID) error
	LockUntil(ctx context.Context, id uuid.UUID, until time.Time) error
	ActivateUser(ctx context.Context, id uuid.UUID) error
}

type pgxUserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo creates a new PostgreSQL-backed UserRepository.
func NewUserRepo(pool *pgxpool.Pool) UserRepository {
	return &pgxUserRepo{pool: pool}
}

func (r *pgxUserRepo) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, role, is_active, failed_login_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.Role, user.IsActive,
		user.FailedLoginCount, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_email_lower") {
			return domain.ErrEmailAlreadyExists
		}
		return err
	}
	return nil
}

func (r *pgxUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, role, is_active, failed_login_count, locked_until, created_at, updated_at
		FROM users WHERE id = $1`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.IsActive,
		&user.FailedLoginCount, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *pgxUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, role, is_active, failed_login_count, locked_until, created_at, updated_at
		FROM users WHERE lower(email) = lower($1)`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.IsActive,
		&user.FailedLoginCount, &user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (r *pgxUserRepo) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}

func (r *pgxUserRepo) IncrementFailedLogin(ctx context.Context, id uuid.UUID) (int, error) {
	query := `
		UPDATE users SET failed_login_count = failed_login_count + 1, updated_at = NOW()
		WHERE id = $1
		RETURNING failed_login_count`

	var count int
	err := r.pool.QueryRow(ctx, query, id).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (r *pgxUserRepo) ResetFailedLogin(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *pgxUserRepo) LockUntil(ctx context.Context, id uuid.UUID, until time.Time) error {
	query := `UPDATE users SET locked_until = $2, updated_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id, until)
	return err
}

func (r *pgxUserRepo) ActivateUser(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET is_active = TRUE, updated_at = NOW() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
