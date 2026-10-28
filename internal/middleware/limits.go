package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
)

// BodyLimit читает тело запроса целиком, но не больше limit байт, и подменяет
// r.Body прочитанной копией. Если тело больше лимита, отвечает 413.
func BodyLimit(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				writeTooLarge(w)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					writeTooLarge(w)
					return
				}
				handler.WriteError(w, http.StatusBadRequest,
					handler.ErrorBody(api.VALIDATIONERROR, "Invalid request", "Failed to read request body"))
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}
}

func writeTooLarge(w http.ResponseWriter) {
	handler.WriteError(w, http.StatusRequestEntityTooLarge,
		handler.ErrorBody(api.PAYLOADTOOLARGE, "Payload too large", "Request body must not exceed 1 MB"))
}

// Timeout ограничивает время обработки запроса: через d контекст запроса отменяется,
// и операции, которые его учитывают (запросы к БД), прерываются с ошибкой.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
