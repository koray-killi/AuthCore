package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/koray-killi/AuthCore/internal/domain"
	"github.com/koray-killi/AuthCore/internal/repository"
)

// AuditService handles audit log operations.
type AuditService struct {
	repo repository.AuditRepository
}

// NewAuditService creates a new AuditService.
func NewAuditService(repo repository.AuditRepository) *AuditService {
	return &AuditService{repo: repo}
}

// Log creates an audit log entry. This is a fire-and-forget operation:
// audit log failures must not block the main request flow.
func (s *AuditService) Log(ctx context.Context, action string, userID *uuid.UUID, ip, userAgent string, metadata map[string]interface{}) {
	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	entry := &domain.AuditLog{
		ID:        uuid.New(),
		UserID:    userID,
		Action:    action,
		IP:        ip,
		UserAgent: userAgent,
		Metadata:  metadata,
		CreatedAt: time.Now(),
	}

	// Fire-and-forget: audit failures should not affect the user's request.
	_ = s.repo.Insert(ctx, entry)
}

// PaginatedAuditLogs holds a page of audit logs with total count for pagination.
type PaginatedAuditLogs struct {
	Logs       []domain.AuditLog
	Total      int
	Page       int
	PageSize   int
	TotalPages int
}

// ListAll returns a paginated list of all audit logs (admin use).
func (s *AuditService) ListAll(ctx context.Context, page, pageSize int) (*PaginatedAuditLogs, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	logs, total, err := s.repo.ListAll(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	totalPages := total / pageSize
	if total%pageSize > 0 {
		totalPages++
	}

	return &PaginatedAuditLogs{
		Logs:       logs,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
