package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/d4m0n1/threat-service/internal/api"
)

// WriteError пишет ErrorResponse в формате JSON с указанным статусом.
func WriteError(w http.ResponseWriter, status int, body api.ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// RequestErrorHandler вызывается, если сгенерированный код не смог разобрать запрос.
// Текст ошибки декодера клиенту не отдаём: в нём видны внутренние имена типов.
func RequestErrorHandler(w http.ResponseWriter, _ *http.Request, _ error) {
	WriteError(w, http.StatusBadRequest, ErrorBody(api.VALIDATIONERROR, "Invalid request", "Malformed request body"))
}

// NewResponseErrorHandler возвращает обработчик непредвиденных ошибок:
// подробности уходят в лог, клиент получает 500 без внутренних деталей.
func NewResponseErrorHandler(log *slog.Logger) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		WriteError(w, http.StatusInternalServerError, ErrorBody(api.INTERNALERROR, "Internal server error", ""))
	}
}

// ErrorBody собирает ErrorResponse; пустой details в ответ не попадает.
func ErrorBody(code api.ErrorResponseCode, message, details string) api.ErrorResponse {
	resp := api.ErrorResponse{Code: code, Message: message}
	if details != "" {
		resp.Details = &details
	}
	return resp
}

func invalidInput(err error) api.ErrorResponse {
	return ErrorBody(api.VALIDATIONERROR, "Invalid request", err.Error())
}

func notFound(md5 string) api.ErrorResponse {
	return ErrorBody(api.NOTFOUND, "Threat not found",
		fmt.Sprintf("No threat with MD5 %s found", strings.ToLower(md5)))
}

func alreadyExists(md5 string) api.ErrorResponse {
	return ErrorBody(api.ALREADYEXISTS, "Threat already exists",
		fmt.Sprintf("Threat with MD5 %s already exists", strings.ToLower(md5)))
}
