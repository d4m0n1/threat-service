package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
	"github.com/d4m0n1/threat-service/internal/model"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

var errUnexpectedCall = errors.New("unexpected call")

// fakeService — подставной сервис: тест задаёт только нужные ему методы.
// Незаданный метод возвращает ошибку, и тест получит 500 вместо ожидаемого кода.
type fakeService struct {
	create func(model.Threat) (model.Threat, error)
	get    func(string) (model.Threat, error)
	update func(model.Threat) (model.Threat, error)
}

func (f fakeService) Create(_ context.Context, t model.Threat) (model.Threat, error) {
	if f.create == nil {
		return model.Threat{}, errUnexpectedCall
	}
	return f.create(t)
}

func (f fakeService) Get(_ context.Context, md5 string) (model.Threat, error) {
	if f.get == nil {
		return model.Threat{}, errUnexpectedCall
	}
	return f.get(md5)
}

func (f fakeService) Update(_ context.Context, t model.Threat) (model.Threat, error) {
	if f.update == nil {
		return model.Threat{}, errUnexpectedCall
	}
	return f.update(t)
}

// stored имитирует успешное сохранение: временные метки выставляет «БД».
func stored(t model.Threat) (model.Threat, error) {
	t.CreatedAt = time.Now()
	t.UpdatedAt = t.CreatedAt
	return t, nil
}

// fails возвращает функцию, которая всегда завершается ошибкой err.
func fails(err error) func(model.Threat) (model.Threat, error) {
	return func(model.Threat) (model.Threat, error) { return model.Threat{}, err }
}

// serve прогоняет запрос через роутер и возвращает записанный ответ.
func serve(t *testing.T, svc handler.ThreatService, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	router, err := handler.NewRouter(svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestRouter(t *testing.T) {
	validBody := `{"md5":"` + testMD5 + `","name":"Trojan.Win32.Generic","severity":"high"}`

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		svc        fakeService
		wantStatus int
		wantCode   api.ErrorResponseCode // пусто — ответ без ошибки
	}{
		// POST /info
		{name: "create", method: http.MethodPost, path: "/info", body: validBody,
			svc: fakeService{create: stored}, wantStatus: http.StatusCreated},
		{name: "create without name", method: http.MethodPost, path: "/info", body: `{"md5":"` + testMD5 + `"}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with unknown field", method: http.MethodPost, path: "/info", body: `{"md5":"` + testMD5 + `","name":"X","foo":1}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with invalid severity", method: http.MethodPost, path: "/info", body: `{"md5":"` + testMD5 + `","name":"X","severity":"extreme"}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with null field", method: http.MethodPost, path: "/info", body: `{"md5":"` + testMD5 + `","name":"X","severity":null}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with invalid md5", method: http.MethodPost, path: "/info", body: `{"md5":"xyz","name":"X"}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with wrong type", method: http.MethodPost, path: "/info", body: `{"md5":"` + testMD5 + `","name":"X","file_size":"big"}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create with malformed json", method: http.MethodPost, path: "/info", body: `{"md5":`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},
		{name: "create duplicate", method: http.MethodPost, path: "/info", body: validBody,
			svc: fakeService{create: fails(model.ErrAlreadyExists)}, wantStatus: http.StatusConflict, wantCode: api.ALREADYEXISTS},
		{name: "create rejected by service", method: http.MethodPost, path: "/info", body: validBody,
			svc:        fakeService{create: fails(fmt.Errorf("%w: first_seen must not be after last_seen", model.ErrInvalidInput))},
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},

		// GET /info/{md5}
		{name: "get", method: http.MethodGet, path: "/info/" + testMD5,
			svc: fakeService{get: func(md5 string) (model.Threat, error) {
				return stored(model.Threat{MD5: md5, Name: "X"})
			}},
			wantStatus: http.StatusOK},
		{name: "get not found", method: http.MethodGet, path: "/info/" + testMD5,
			svc: fakeService{get: func(string) (model.Threat, error) {
				return model.Threat{}, model.ErrNotFound
			}},
			wantStatus: http.StatusNotFound, wantCode: api.NOTFOUND},
		{name: "get with invalid md5", method: http.MethodGet, path: "/info/xyz",
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},

		// PUT /info/{md5}
		{name: "update", method: http.MethodPut, path: "/info/" + testMD5, body: `{"name":"X"}`,
			svc: fakeService{update: stored}, wantStatus: http.StatusOK},
		{name: "update not found", method: http.MethodPut, path: "/info/" + testMD5, body: `{"name":"X"}`,
			svc: fakeService{update: fails(model.ErrNotFound)}, wantStatus: http.StatusNotFound, wantCode: api.NOTFOUND},
		{name: "update with md5 in body", method: http.MethodPut, path: "/info/" + testMD5, body: `{"name":"X","md5":"` + testMD5 + `"}`,
			wantStatus: http.StatusBadRequest, wantCode: api.VALIDATIONERROR},

		// Прочее
		{name: "unknown route", method: http.MethodGet, path: "/threats",
			wantStatus: http.StatusNotFound, wantCode: api.NOTFOUND},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(t, tt.svc, tt.method, tt.path, tt.body)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantCode == "" {
				return
			}
			var resp api.ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if resp.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", resp.Code, tt.wantCode)
			}
		})
	}
}

func TestCreateSetsLocation(t *testing.T) {
	body := `{"md5":"` + testMD5 + `","name":"X"}`
	rec := serve(t, fakeService{create: stored}, http.MethodPost, "/info", body)

	if got, want := rec.Header().Get("Location"), "/info/"+testMD5; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestInternalErrorHidesDetails(t *testing.T) {
	svc := fakeService{get: func(string) (model.Threat, error) {
		return model.Threat{}, errors.New("dial tcp 10.0.0.5:5432: connection refused")
	}}
	rec := serve(t, svc, http.MethodGet, "/info/"+testMD5, "")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "5432") {
		t.Errorf("response leaks internal error: %s", rec.Body)
	}
}
