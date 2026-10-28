package handler

import (
	"log/slog"
	"net/http"

	"github.com/d4m0n1/threat-service/internal/api"
)

// NewRouter собирает HTTP-обработчик API: валидация запросов по спецификации,
// маршрутизация и обработчики поверх сервиса.
func NewRouter(svc ThreatService, log *slog.Logger) (http.Handler, error) {
	validator, err := NewValidator()
	if err != nil {
		return nil, err
	}

	strict := api.NewStrictHandlerWithOptions(New(svc), nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  RequestErrorHandler,
		ResponseErrorHandlerFunc: NewResponseErrorHandler(log),
	})

	mux := http.NewServeMux()
	api.HandlerFromMux(strict, mux)
	return validator(mux), nil
}
