package handler

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koray-killi/AuthCore/internal/database"
	"github.com/koray-killi/AuthCore/internal/middleware"
)

// HealthHandler handles the /healthz endpoint.
type HealthHandler struct {
	pool *pgxpool.Pool
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

// Healthz returns the application health status including database connectivity.
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := database.Ping(r.Context(), h.pool, 1*time.Second); err != nil {
		dbStatus = "unavailable"
	}

	status := "ok"
	statusCode := http.StatusOK
	if dbStatus != "ok" {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	middleware.WriteJSON(w, statusCode, HealthResponse{
		Status:   status,
		Database: dbStatus,
	})
}
