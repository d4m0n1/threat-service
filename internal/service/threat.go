// Package service содержит бизнес-логику работы с угрозами.
package service

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/d4m0n1/threat-service/internal/model"
)

// Repository — хранилище угроз, которое нужно сервису.
// Реализуется storage.Postgres; в тестах можно подставить реализацию в памяти.
type Repository interface {
	Create(ctx context.Context, t model.Threat) (model.Threat, error)
	Get(ctx context.Context, md5 string) (model.Threat, error)
	Update(ctx context.Context, t model.Threat) (model.Threat, error)
}

// ThreatService нормализует и проверяет данные перед обращением к хранилищу.
type ThreatService struct {
	repo Repository
}

// New создаёт сервис поверх переданного хранилища.
func New(repo Repository) *ThreatService {
	return &ThreatService{repo: repo}
}

// Create создаёт угрозу.
// Ошибки: model.ErrInvalidInput, model.ErrAlreadyExists.
func (s *ThreatService) Create(ctx context.Context, t model.Threat) (model.Threat, error) {
	normalize(&t)
	if err := validate(t); err != nil {
		return model.Threat{}, err
	}
	return s.repo.Create(ctx, t)
}

// Get возвращает угрозу по MD5 (регистр не важен).
// Ошибки: model.ErrNotFound.
func (s *ThreatService) Get(ctx context.Context, md5 string) (model.Threat, error) {
	return s.repo.Get(ctx, strings.ToLower(md5))
}

// Update полностью заменяет данные угрозы: не переданные необязательные поля сбрасываются.
// Ошибки: model.ErrInvalidInput, model.ErrNotFound.
func (s *ThreatService) Update(ctx context.Context, t model.Threat) (model.Threat, error) {
	normalize(&t)
	if err := validate(t); err != nil {
		return model.Threat{}, err
	}
	return s.repo.Update(ctx, t)
}

// normalize приводит хеши к нижнему регистру, как обещает спецификация.
func normalize(t *model.Threat) {
	t.MD5 = strings.ToLower(t.MD5)
	if t.SHA256 != nil {
		lower := strings.ToLower(*t.SHA256)
		t.SHA256 = &lower
	}
}

// validate проверяет правила, которые нельзя выразить в OpenAPI-схеме.
// Формат отдельных полей проверяется раньше — валидатором по спецификации.
func validate(t model.Threat) error {
	if t.FirstSeen != nil && t.LastSeen != nil && t.FirstSeen.After(*t.LastSeen) {
		return fmt.Errorf("%w: first_seen must not be after last_seen", model.ErrInvalidInput)
	}
	// Postgres не хранит NUL в текстовых полях; в названии запрещаем все управляющие символы,
	// описание может быть многострочным, поэтому для него — только NUL.
	if strings.ContainsFunc(t.Name, unicode.IsControl) {
		return fmt.Errorf("%w: name must not contain control characters", model.ErrInvalidInput)
	}
	if t.Description != nil && strings.ContainsRune(*t.Description, 0) {
		return fmt.Errorf("%w: description must not contain NUL characters", model.ErrInvalidInput)
	}
	return nil
}
