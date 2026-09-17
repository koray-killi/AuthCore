package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// SessionRepository defines data access operations for refresh sessions.
type SessionRepository interface {
	Create(ctx context.Context, session *domain.RefreshSession) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshSession, error)
	RevokeByID(ctx context.Context, id uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	MarkReplacedBy(ctx context.Context, oldID, newID uuid.UUID) error
}

type pgxSessionRepo struct {
	pool *pgxpool.Pool
}

// NewSessionRepo creates a new PostgreSQL-backed SessionRepository.
func NewSessionRepo(pool *pgxpool.Pool) SessionRepository {
	return &pgxSessionRepo{pool: pool}
}

func (r *pgxSessionRepo) Create(ctx context.Context, session *domain.RefreshSession) error {
	query := `
		INSERT INTO refresh_sessions (id, user_id, token_hash, user_agent, ip, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5::inet, $6, $7)`

	_, err := r.pool.Exec(ctx, query,
		session.ID, session.UserID, session.TokenHash, session.UserAgent,
		session.IP, session.ExpiresAt, session.CreatedAt,
	)
	return err
}

func (r *pgxSessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshSession, error) {
	query := `
		SELECT id, user_id, token_hash, user_agent, ip::text, expires_at, revoked_at, replaced_by, created_at
		FROM refresh_sessions WHERE token_hash = $1`

	s := &domain.RefreshSession{}
	var ip string
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.UserAgent, &ip,
		&s.ExpiresAt, &s.RevokedAt, &s.ReplacedBy, &s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenInvalid
		}
		return nil, err
	}
	s.IP = ip
	return s, nil
}

func (r *pgxSessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *pgxSessionRepo) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE refresh_sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *pgxSessionRepo) MarkReplacedBy(ctx context.Context, oldID, newID uuid.UUID) error {
	query := `UPDATE refresh_sessions SET replaced_by = $2 WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, oldID, newID)
	return err
}
