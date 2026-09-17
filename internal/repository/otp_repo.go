package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// OTPRepository defines data access operations for one-time password codes.
type OTPRepository interface {
	Create(ctx context.Context, otp *domain.OTPCode) error
	GetLatestValid(ctx context.Context, userID uuid.UUID, purpose string) (*domain.OTPCode, error)
	IncrementAttempt(ctx context.Context, id uuid.UUID) error
	Consume(ctx context.Context, id uuid.UUID) error
}

type pgxOTPRepo struct {
	pool *pgxpool.Pool
}

// NewOTPRepo creates a new PostgreSQL-backed OTPRepository.
func NewOTPRepo(pool *pgxpool.Pool) OTPRepository {
	return &pgxOTPRepo{pool: pool}
}

func (r *pgxOTPRepo) Create(ctx context.Context, otp *domain.OTPCode) error {
	query := `
		INSERT INTO otp_codes (id, user_id, purpose, code_hash, attempt_count, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.pool.Exec(ctx, query,
		otp.ID, otp.UserID, otp.Purpose, otp.CodeHash,
		otp.AttemptCount, otp.ExpiresAt, otp.CreatedAt,
	)
	return err
}

func (r *pgxOTPRepo) GetLatestValid(ctx context.Context, userID uuid.UUID, purpose string) (*domain.OTPCode, error) {
	query := `
		SELECT id, user_id, purpose, code_hash, attempt_count, expires_at, consumed_at, created_at
		FROM otp_codes
		WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`

	otp := &domain.OTPCode{}
	err := r.pool.QueryRow(ctx, query, userID, purpose).Scan(
		&otp.ID, &otp.UserID, &otp.Purpose, &otp.CodeHash,
		&otp.AttemptCount, &otp.ExpiresAt, &otp.ConsumedAt, &otp.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrOTPInvalid
		}
		return nil, err
	}
	return otp, nil
}

func (r *pgxOTPRepo) IncrementAttempt(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE otp_codes SET attempt_count = attempt_count + 1 WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}

func (r *pgxOTPRepo) Consume(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE otp_codes SET consumed_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, id)
	return err
}
