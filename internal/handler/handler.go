// Package handler реализует HTTP-слой: обработчики, сгенерированные по OpenAPI-спецификации,
// валидацию запросов и формат ошибок.
package handler

import (
	"context"
	"errors"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/model"
)

// ThreatService — операции над угрозами, которые нужны HTTP-слою.
type ThreatService interface {
	Create(ctx context.Context, t model.Threat) (model.Threat, error)
	Get(ctx context.Context, md5 string) (model.Threat, error)
	Update(ctx context.Context, t model.Threat) (model.Threat, error)
}

// Handler реализует api.StrictServerInterface и переводит ошибки сервиса в HTTP-ответы.
type Handler struct {
	svc ThreatService
}

// Проверка на этапе компиляции, что Handler реализует интерфейс.
var _ api.StrictServerInterface = (*Handler)(nil)

// New создаёт обработчик поверх сервиса.
func New(svc ThreatService) *Handler {
	return &Handler{svc: svc}
}

// CreateThreat обрабатывает POST /info.
func (h *Handler) CreateThreat(ctx context.Context, req api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	b := req.Body
	t, err := h.svc.Create(ctx, model.Threat{
		MD5:         b.Md5,
		Name:        b.Name,
		Severity:    severityToModel(b.Severity),
		SHA256:      b.Sha256,
		FileSize:    b.FileSize,
		FirstSeen:   b.FirstSeen,
		LastSeen:    b.LastSeen,
		Description: b.Description,
	})
	switch {
	case errors.Is(err, model.ErrInvalidInput):
		return api.CreateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(invalidInput(err))}, nil
	case errors.Is(err, model.ErrAlreadyExists):
		return api.CreateThreat409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(alreadyExists(b.Md5))}, nil
	case err != nil:
		// Непредвиденная ошибка: её обработает ResponseErrorHandler (лог + 500).
		return nil, err
	}

	location := "/info/" + t.MD5
	return api.CreateThreat201JSONResponse{
		Body:    toResponse(t),
		Headers: api.CreateThreat201ResponseHeaders{Location: &location},
	}, nil
}

// GetInfoByMd5 обрабатывает GET /info/{md5}.
func (h *Handler) GetInfoByMd5(ctx context.Context, req api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	t, err := h.svc.Get(ctx, req.Md5)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return api.GetInfoByMd5404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(notFound(req.Md5))}, nil
	case err != nil:
		return nil, err
	}
	return api.GetInfoByMd5200JSONResponse(toResponse(t)), nil
}

// UpdateThreat обрабатывает PUT /info/{md5}.
func (h *Handler) UpdateThreat(ctx context.Context, req api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	b := req.Body
	t, err := h.svc.Update(ctx, model.Threat{
		MD5:         req.Md5,
		Name:        b.Name,
		Severity:    severityToModel(b.Severity),
		SHA256:      b.Sha256,
		FileSize:    b.FileSize,
		FirstSeen:   b.FirstSeen,
		LastSeen:    b.LastSeen,
		Description: b.Description,
	})
	switch {
	case errors.Is(err, model.ErrInvalidInput):
		return api.UpdateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(invalidInput(err))}, nil
	case errors.Is(err, model.ErrNotFound):
		return api.UpdateThreat404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(notFound(req.Md5))}, nil
	case err != nil:
		return nil, err
	}
	return api.UpdateThreat200JSONResponse(toResponse(t)), nil
}

// toResponse переводит доменную модель в тело ответа API.
func toResponse(t model.Threat) api.ThreatResponse {
	resp := api.ThreatResponse{
		Md5:         t.MD5,
		Name:        t.Name,
		Sha256:      t.SHA256,
		FileSize:    t.FileSize,
		FirstSeen:   t.FirstSeen,
		LastSeen:    t.LastSeen,
		Description: t.Description,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
	if t.Severity != nil {
		s := api.Severity(*t.Severity)
		resp.Severity = &s
	}
	return resp
}

func severityToModel(s *api.Severity) *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}
