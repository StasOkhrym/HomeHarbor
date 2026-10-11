// Package httpresponse owns strict JSON request and error response contracts
// shared by the control API and browser authentication adapter.
package httpresponse

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

const MaxBodyBytes int64 = 1 << 20

func DecodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		writeDecodeError(w, err)
		return false
	}

	var trailing any

	if err := decoder.Decode(&trailing); err != io.EOF {
		writeDecodeError(w, err)
		return false
	}

	return true
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		WriteError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}

	WriteError(w, http.StatusBadRequest, "invalid JSON body")
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteErrorCode(w, status, errorCode(status), message)
}

func WriteErrorCode(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, map[string]string{"code": code, "error": message})
}

func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return "internal_error"
	}
}
