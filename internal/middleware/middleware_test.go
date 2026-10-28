package middleware_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/middleware"
)

const (
	readerKey = "reader-key-0123456789"
	writerKey = "writer-key-0123456789"
)

// okHandler — «конечный» обработчик: если запрос дошёл до него, отвечает 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestParseAPIKeys(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "two keys", input: readerKey + ":reader," + writerKey + ":writer"},
		{name: "spaces and trailing comma", input: " " + readerKey + ":reader , "},
		{name: "empty", input: "", wantErr: true},
		{name: "missing role", input: readerKey, wantErr: true},
		{name: "short key", input: "short:reader", wantErr: true},
		{name: "unknown role", input: readerKey + ":admin", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := middleware.ParseAPIKeys(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), readerKey) {
				t.Errorf("error message leaks the key: %v", err)
			}
		})
	}
}

func TestAuth(t *testing.T) {
	keys, err := middleware.ParseAPIKeys(readerKey + ":reader," + writerKey + ":writer")
	if err != nil {
		t.Fatalf("ParseAPIKeys: %v", err)
	}
	h := middleware.Auth(keys)(okHandler)

	tests := []struct {
		name       string
		method     string
		key        string
		wantStatus int
	}{
		{name: "no key", method: http.MethodGet, wantStatus: http.StatusUnauthorized},
		{name: "unknown key", method: http.MethodGet, key: "unknown-key-0123456789", wantStatus: http.StatusUnauthorized},
		{name: "reader reads", method: http.MethodGet, key: readerKey, wantStatus: http.StatusOK},
		{name: "reader creates", method: http.MethodPost, key: readerKey, wantStatus: http.StatusForbidden},
		{name: "reader updates", method: http.MethodPut, key: readerKey, wantStatus: http.StatusForbidden},
		{name: "writer reads", method: http.MethodGet, key: writerKey, wantStatus: http.StatusOK},
		{name: "writer creates", method: http.MethodPost, key: writerKey, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/info", nil)
			if tt.key != "" {
				req.Header.Set("X-API-Key", tt.key)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestRateLimiter(t *testing.T) {
	const burst = 3
	h := middleware.NewRateLimiter(1, burst).Middleware(okHandler)

	send := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		req.RemoteAddr = ip + ":12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := range burst {
		if rec := send("192.0.2.1"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i+1, rec.Code)
		}
	}

	rec := send("192.0.2.1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response must have Retry-After header")
	}

	if rec := send("192.0.2.2"); rec.Code != http.StatusOK {
		t.Errorf("another IP: status = %d, want 200 (limits must be per IP)", rec.Code)
	}
}

// TestRateLimiterConcurrent имеет смысл с флагом -race: проверяет,
// что доступ к общему map клиентов синхронизирован.
func TestRateLimiterConcurrent(t *testing.T) {
	h := middleware.NewRateLimiter(100, 100).Middleware(okHandler)

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodGet, "/info", nil)
			req.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", i%5)
			h.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
	wg.Wait()
}

func TestRecover(t *testing.T) {
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := middleware.Recover(slog.New(slog.NewTextHandler(io.Discard, nil)))(panicking)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/info", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var resp api.ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != api.INTERNALERROR {
		t.Errorf("code = %q, want %q", resp.Code, api.INTERNALERROR)
	}
}
