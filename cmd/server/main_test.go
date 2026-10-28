package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
	"github.com/d4m0n1/threat-service/internal/middleware"
	"github.com/d4m0n1/threat-service/internal/model"
)

const (
	testMD5   = "d41d8cd98f00b204e9800998ecf8427e"
	readerKey = "reader-key-0123456789"
	writerKey = "writer-key-0123456789"
)

// slowService имитирует зависшую БД на чтении: Get ждёт отмены контекста.
// Защитный таймаут не даёт тесту зависнуть, если middleware Timeout не сработал.
type slowService struct{}

func (slowService) Create(_ context.Context, t model.Threat) (model.Threat, error) { return t, nil }
func (slowService) Update(_ context.Context, t model.Threat) (model.Threat, error) { return t, nil }
func (slowService) Get(ctx context.Context, _ string) (model.Threat, error) {
	select {
	case <-ctx.Done():
		return model.Threat{}, ctx.Err()
	case <-time.After(3 * time.Second):
		return model.Threat{}, nil
	}
}

// newTestHandler собирает ту же цепочку, что и main, с коротким таймаутом.
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	router, err := handler.NewRouter(slowService{}, log)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	keys, err := middleware.ParseAPIKeys(readerKey + ":reader," + writerKey + ":writer")
	if err != nil {
		t.Fatalf("ParseAPIKeys: %v", err)
	}
	return newHandler(router, keys, middleware.NewRateLimiter(1000, 1000), 50*time.Millisecond, log)
}

func TestHandlerChain(t *testing.T) {
	oversized := `{"md5":"` + testMD5 + `","name":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	valid := `{"md5":"` + testMD5 + `","name":"X"}`

	tests := []struct {
		name       string
		method     string
		path       string
		key        string
		body       string
		wantStatus int
		wantCode   api.ErrorResponseCode
	}{
		{name: "valid create", method: http.MethodPost, path: "/info", key: writerKey, body: valid,
			wantStatus: http.StatusCreated},
		{name: "auth runs before body is read", method: http.MethodPost, path: "/info", body: oversized,
			wantStatus: http.StatusUnauthorized, wantCode: api.UNAUTHORIZED},
		{name: "auth runs before validation", method: http.MethodGet, path: "/info/xyz",
			wantStatus: http.StatusUnauthorized, wantCode: api.UNAUTHORIZED},
		{name: "reader cannot create", method: http.MethodPost, path: "/info", key: readerKey, body: valid,
			wantStatus: http.StatusForbidden, wantCode: api.FORBIDDEN},
		{name: "oversized body", method: http.MethodPost, path: "/info", key: writerKey, body: oversized,
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: api.PAYLOADTOOLARGE},
		{name: "hanging storage times out", method: http.MethodGet, path: "/info/" + testMD5, key: readerKey,
			wantStatus: http.StatusInternalServerError, wantCode: api.INTERNALERROR},
	}

	h := newTestHandler(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if tt.key != "" {
				req.Header.Set("X-API-Key", tt.key)
			}
			rec := httptest.NewRecorder()

			start := time.Now()
			h.ServeHTTP(rec, req)
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("request took %v, timeout must cut it short", elapsed)
			}

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantCode == "" {
				return
			}
			var resp api.ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", resp.Code, tt.wantCode)
			}
		})
	}
}
