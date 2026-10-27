package handler

import (
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/d4m0n1/threat-service/internal/api"
)

// NewValidator возвращает middleware, проверяющий каждый запрос по встроенной
// OpenAPI-спецификации (типы, форматы, pattern, enum, обязательные и лишние поля).
func NewValidator() (func(http.Handler) http.Handler, error) {
	spec, err := api.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("load openapi spec: %w", err)
	}

	return nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		// В спеке указан servers: https://localhost:8443 — без этой опции валидатор
		// отклонял бы запросы, пришедшие на другой хост или порт.
		DoNotValidateServers: true,
		Options: openapi3filter.Options{
			// API-ключ проверяется отдельным middleware, здесь секцию security пропускаем.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			// Не выводить в ответах JSON-схему поля, только суть ошибки.
			SchemaValidationOptions: []openapi3.SchemaValidationOption{
				openapi3.DisableSchemaErrorDetails(),
			},
		},
		ErrorHandler: validationErrorHandler,
	}), nil
}

// validationErrorHandler отдаёт ошибки валидатора в формате ErrorResponse.
func validationErrorHandler(w http.ResponseWriter, message string, status int) {
	switch status {
	case http.StatusNotFound:
		WriteError(w, status, ErrorBody(api.NOTFOUND, "Route not found", ""))
	case http.StatusMethodNotAllowed:
		WriteError(w, status, ErrorBody(api.VALIDATIONERROR, "Method not allowed", ""))
	case http.StatusInternalServerError:
		WriteError(w, status, ErrorBody(api.INTERNALERROR, "Internal server error", ""))
	default:
		WriteError(w, status, ErrorBody(api.VALIDATIONERROR, "Invalid request", message))
	}
}
