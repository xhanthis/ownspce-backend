package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/store"
)

// apiError is the single error shape every endpoint returns.
type apiError struct {
	status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e apiError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func badRequest(format string, args ...any) apiError {
	return apiError{status: http.StatusBadRequest, Code: "invalid_request", Message: fmt.Sprintf(format, args...)}
}

func errUnauthorized(msg string) apiError {
	return apiError{status: http.StatusUnauthorized, Code: "unauthorized", Message: msg}
}

func errForbidden(code, msg string) apiError {
	return apiError{status: http.StatusForbidden, Code: code, Message: msg}
}

func errNotFound(msg string) apiError {
	return apiError{status: http.StatusNotFound, Code: "not_found", Message: msg}
}

func errConflict(code, msg string) apiError {
	return apiError{status: http.StatusConflict, Code: code, Message: msg}
}

func errTooLarge(code, msg string) apiError {
	return apiError{status: http.StatusRequestEntityTooLarge, Code: code, Message: msg}
}

func errUnavailable(msg string) apiError {
	return apiError{status: http.StatusServiceUnavailable, Code: "unavailable", Message: msg}
}

var errInternal = apiError{status: http.StatusInternalServerError, Code: "internal", Message: "internal server error"}

// writeJSON writes a success payload.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

// writeError maps an error to its wire form, logging only unexpected failures so
// request logs never carry user data.
func writeError(w http.ResponseWriter, err error) {
	var apiErr apiError
	if !errors.As(err, &apiErr) {
		log.Printf("unhandled error: %v", err)
		apiErr = errInternal
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiErr.status)
	_ = json.NewEncoder(w).Encode(map[string]apiError{"error": apiErr})
}

// storeError translates store sentinels into HTTP errors, with per-endpoint codes.
func storeError(err error, notFoundMsg, conflictCode, conflictMsg, forbiddenCode, forbiddenMsg string) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errNotFound(notFoundMsg)
	case errors.Is(err, store.ErrConflict):
		return errConflict(conflictCode, conflictMsg)
	case errors.Is(err, store.ErrForbidden):
		return errForbidden(forbiddenCode, forbiddenMsg)
	default:
		return err
	}
}

// decodeJSON reads a JSON body under a size cap.
func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errTooLarge("payload_too_large", fmt.Sprintf("request body exceeds %d bytes", maxBytes))
		}
		return badRequest("malformed json body: %v", err)
	}
	return nil
}

// parseUUIDParam reads a uuid path parameter.
func parseUUIDParam(raw, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, badRequest("%s must be a uuid", name)
	}
	return id, nil
}

// parseSince reads the sync cursor, defaulting to 0 (full catch-up).
func parseSince(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, badRequest("since must be a non-negative integer")
	}
	return v, nil
}
