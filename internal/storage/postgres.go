package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/d4m0n1/threat-service/internal/model"
)

const pgUniqueViolation = "23505"

const columns = `md5, name, severity, sha256, file_size, first_seen, last_seen, description, created_at, updated_at`

type Postgres struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Postgres {
	return &Postgres{pool: pool}
}

func (s *Postgres) Create(ctx context.Context, t model.Threat) (model.Threat, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO threats (md5, name, severity, sha256, file_size, first_seen, last_seen, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+columns,
		t.MD5, t.Name, t.Severity, t.SHA256, t.FileSize, t.FirstSeen, t.LastSeen, t.Description)

	res, err := scanThreat(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return model.Threat{}, model.ErrAlreadyExists
		}
		return model.Threat{}, fmt.Errorf("insert threat: %w", err)
	}
	return res, nil
}

func (s *Postgres) Get(ctx context.Context, md5 string) (model.Threat, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+columns+` FROM threats WHERE md5 = $1`, md5)

	res, err := scanThreat(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Threat{}, model.ErrNotFound
	}
	if err != nil {
		return model.Threat{}, fmt.Errorf("select threat: %w", err)
	}
	return res, nil
}

func (s *Postgres) Update(ctx context.Context, t model.Threat) (model.Threat, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE threats
		SET name = $2, severity = $3, sha256 = $4, file_size = $5,
		    first_seen = $6, last_seen = $7, description = $8, updated_at = now()
		WHERE md5 = $1
		RETURNING `+columns,
		t.MD5, t.Name, t.Severity, t.SHA256, t.FileSize, t.FirstSeen, t.LastSeen, t.Description)

	res, err := scanThreat(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.Threat{}, model.ErrNotFound
	}
	if err != nil {
		return model.Threat{}, fmt.Errorf("update threat: %w", err)
	}
	return res, nil
}

func scanThreat(row pgx.Row) (model.Threat, error) {
	var t model.Threat
	err := row.Scan(&t.MD5, &t.Name, &t.Severity, &t.SHA256, &t.FileSize,
		&t.FirstSeen, &t.LastSeen, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}
