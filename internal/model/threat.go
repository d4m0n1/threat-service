package model

import (
	"errors"
	"time"
)

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

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)
