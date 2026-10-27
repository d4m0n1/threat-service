// Package middleware содержит HTTP-middleware общего назначения.
package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
)

// statusRecorder запоминает код ответа, который записал обработчик.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Logging пишет в лог одну строку на запрос. Уровень зависит от статуса ответа:
// 5xx — ERROR, 401/403/429 — WARN, остальное — INFO.
func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			level := slog.LevelInfo
			switch {
			case rec.status >= 500:
				level = slog.LevelError
			case rec.status == http.StatusUnauthorized,
				rec.status == http.StatusForbidden,
				rec.status == http.StatusTooManyRequests:
				level = slog.LevelWarn
			}
			log.Log(r.Context(), level, "request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start),
				"remote", r.RemoteAddr,
			)
		})
	}
}

// Recover перехватывает панику в обработчике: пишет стектрейс в лог
// и отвечает клиенту 500 без внутренних деталей.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error("panic", "value", v, "stack", string(debug.Stack()))
					handler.WriteError(w, http.StatusInternalServerError,
						handler.ErrorBody(api.INTERNALERROR, "Internal server error", ""))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
