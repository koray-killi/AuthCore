// Package httperr provides centralized HTTP error response formatting.
// All error-to-JSON mapping happens here. Handlers call httperr.Write instead
// of constructing error responses directly, ensuring a consistent error envelope.
package httperr

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/koray-killi/AuthCore/internal/domain"
)

// ErrorResponse is the JSON envelope for all error responses.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody contains the machine-readable code and human-readable message.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Write inspects the given error, maps it to the appropriate HTTP status and
// JSON body, and writes the response. Unknown errors are mapped to 500.
func Write(w http.ResponseWriter, err error) {
	var appErr *domain.AppError
	if errors.As(err, &appErr) {
		writeJSON(w, appErr.HTTPStatus, ErrorResponse{
			Error: ErrorBody{
				Code:    appErr.Code,
				Message: appErr.Message,
			},
		})
		return
	}

	// Unknown errors → 500 with no internal detail leak.
	writeJSON(w, http.StatusInternalServerError, ErrorResponse{
		Error: ErrorBody{
			Code:    domain.ErrInternal.Code,
			Message: domain.ErrInternal.Message,
		},
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
