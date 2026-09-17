package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	headers := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":        "DENY",
		"X-XSS-Protection":       "0",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"Cache-Control":          "no-store",
		"Pragma":                 "no-cache",
	}

	for name, expected := range headers {
		got := rec.Header().Get(name)
		if got != expected {
			t.Errorf("header %q: got %q, want %q", name, got, expected)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	handler := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2<<20) // Try to read 2MB
		_, err := r.Body.Read(buf)
		if err != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Create a body larger than 1MB.
	largeBody := strings.NewReader(strings.Repeat("x", 2<<20))
	req := httptest.NewRequest("POST", "/", largeBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 for oversized body, got %d", rec.Code)
	}
}

func TestDecodeJSON_Valid(t *testing.T) {
	type testBody struct {
		Name string `json:"name"`
	}

	body := strings.NewReader(`{"name": "test"}`)
	req := httptest.NewRequest("POST", "/", body)

	var dst testBody
	err := DecodeJSON(req, &dst)
	if err != nil {
		t.Fatalf("DecodeJSON failed: %v", err)
	}
	if dst.Name != "test" {
		t.Errorf("expected name 'test', got %q", dst.Name)
	}
}

func TestDecodeJSON_Invalid(t *testing.T) {
	body := strings.NewReader(`{invalid json}`)
	req := httptest.NewRequest("POST", "/", body)

	var dst struct{ Name string }
	err := DecodeJSON(req, &dst)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestDecodeJSON_NilBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Body = nil

	var dst struct{ Name string }
	err := DecodeJSON(req, &dst)
	if err == nil {
		t.Error("expected error for nil body")
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]string{"key": "value"})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
}
