// Package model содержит доменную модель сервиса и общие ошибки.
package model

import (
	"errors"
	"time"
)

// Threat — запись об угрозе.
// Необязательные поля — указатели: nil означает «значение не задано» (NULL в БД).
type Threat struct {
	MD5         string // всегда в нижнем регистре
	Name        string
	Severity    *string
	SHA256      *string // всегда в нижнем регистре
	FileSize    *int64
	FirstSeen   *time.Time
	LastSeen    *time.Time
	Description *string
	CreatedAt   time.Time // выставляет БД
	UpdatedAt   time.Time // выставляет БД
}

// Ошибки, которые слои сервиса возвращают наружу; проверяются через errors.Is.
var (
	// ErrNotFound — угрозы с таким MD5 нет.
	ErrNotFound = errors.New("threat not found")
	// ErrAlreadyExists — угроза с таким MD5 уже существует.
	ErrAlreadyExists = errors.New("threat already exists")
	// ErrInvalidInput — данные не прошли бизнес-валидацию.
	ErrInvalidInput = errors.New("invalid input")
)
