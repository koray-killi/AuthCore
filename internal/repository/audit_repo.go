package repository

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/domain"
)

// AuditRepository defines data access operations for audit logs.
// This repository is append-only: no Update or Delete methods exist.
type AuditRepository interface {
	Insert(ctx context.Context, log *domain.AuditLog) error
	ListByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]domain.AuditLog, int, error)
	ListAll(ctx context.Context, page, pageSize int) ([]domain.AuditLog, int, error)
}

type pgxAuditRepo struct {
	pool *pgxpool.Pool
}

// NewAuditRepo creates a new PostgreSQL-backed AuditRepository.
func NewAuditRepo(pool *pgxpool.Pool) AuditRepository {
	return &pgxAuditRepo{pool: pool}
}

func (r *pgxAuditRepo) Insert(ctx context.Context, log *domain.AuditLog) error {
	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		metadataJSON = []byte("{}")
	}

	query := `
		INSERT INTO audit_logs (id, user_id, action, ip::text, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4::inet, $5, $6::jsonb, $7)`

	_, err = r.pool.Exec(ctx, query,
		log.ID, log.UserID, log.Action, log.IP, log.UserAgent, metadataJSON, log.CreatedAt,
	)
	return err
}

func (r *pgxAuditRepo) ListByUserID(ctx context.Context, userID uuid.UUID, page, pageSize int) ([]domain.AuditLog, int, error) {
	offset := (page - 1) * pageSize

	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE user_id = $1`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, userID).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, user_id, action, ip::text, user_agent, metadata, created_at
		FROM audit_logs
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	return r.scanLogs(ctx, query, total, userID, pageSize, offset)
}

func (r *pgxAuditRepo) ListAll(ctx context.Context, page, pageSize int) ([]domain.AuditLog, int, error) {
	offset := (page - 1) * pageSize

	countQuery := `SELECT COUNT(*) FROM audit_logs`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, err
	}

	query := `
		SELECT id, user_id, action, ip::text, user_agent, metadata, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	return r.scanLogs(ctx, query, total, pageSize, offset)
}

func (r *pgxAuditRepo) scanLogs(ctx context.Context, query string, total int, args ...interface{}) ([]domain.AuditLog, int, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []domain.AuditLog
	for rows.Next() {
		var log domain.AuditLog
		var ip string
		var metadataJSON []byte
		if err := rows.Scan(&log.ID, &log.UserID, &log.Action, &ip, &log.UserAgent, &metadataJSON, &log.CreatedAt); err != nil {
			return nil, 0, err
		}
		log.IP = ip
		if err := json.Unmarshal(metadataJSON, &log.Metadata); err != nil {
			log.Metadata = map[string]interface{}{}
		}
		logs = append(logs, log)
	}

	return logs, total, rows.Err()
}
