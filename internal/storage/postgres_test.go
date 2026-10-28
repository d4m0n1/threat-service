package storage_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/d4m0n1/threat-service/internal/model"
	"github.com/d4m0n1/threat-service/internal/storage"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func ptr[T any](v T) *T { return &v }

// newTestStorage подключается к TEST_DATABASE_URL, создаёт для теста отдельную схему,
// применяет к ней миграцию и удаляет схему после теста.
// Если переменная не задана, тест пропускается.
func newTestStorage(t *testing.T) (*storage.Postgres, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set, skipping integration test")
	}
	ctx := context.Background()
	schema := pgx.Identifier{fmt.Sprintf("test_%d", time.Now().UnixNano())}.Sanitize()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(ctx)
	})

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema // все запросы пула идут в тестовую схему
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)

	migration, err := os.ReadFile("../../migrations/001_create_threats.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	return storage.New(pool), pool
}

func TestCreateAndGet(t *testing.T) {
	s, _ := newTestStorage(t)
	ctx := context.Background()
	firstSeen := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 10, 20, 8, 30, 0, 0, time.UTC)

	in := model.Threat{
		MD5:         testMD5,
		Name:        "Trojan.Win32.Generic",
		Severity:    ptr("high"),
		SHA256:      ptr(strings.Repeat("a", 64)),
		FileSize:    ptr(int64(482304)),
		FirstSeen:   &firstSeen,
		LastSeen:    &lastSeen,
		Description: ptr("Downloads additional modules"),
	}
	created, err := s.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.CreatedAt.IsZero() || !created.UpdatedAt.Equal(created.CreatedAt) {
		t.Errorf("timestamps: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}

	got, err := s.Get(ctx, testMD5)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != in.Name || *got.Severity != *in.Severity || *got.SHA256 != *in.SHA256 ||
		*got.FileSize != *in.FileSize || *got.Description != *in.Description ||
		!got.FirstSeen.Equal(firstSeen) || !got.LastSeen.Equal(lastSeen) {
		t.Errorf("Get returned different data than was stored")
	}
}

func TestCreateDuplicate(t *testing.T) {
	s, _ := newTestStorage(t)
	ctx := context.Background()
	if _, err := s.Create(ctx, model.Threat{MD5: testMD5, Name: "X"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := s.Create(ctx, model.Threat{MD5: testMD5, Name: "Y"})
	if !errors.Is(err, model.ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestGetNotFound(t *testing.T) {
	s, _ := newTestStorage(t)
	_, err := s.Get(context.Background(), testMD5)
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdate(t *testing.T) {
	s, _ := newTestStorage(t)
	ctx := context.Background()
	created, err := s.Create(ctx, model.Threat{MD5: testMD5, Name: "Old", Severity: ptr("low")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := s.Update(ctx, model.Threat{MD5: testMD5, Name: "New"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "New" {
		t.Errorf("Name = %q, want %q", updated.Name, "New")
	}
	if updated.Severity != nil {
		t.Error("Update must reset omitted optional fields")
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Error("Update must not change created_at")
	}
	if updated.UpdatedAt.Before(created.UpdatedAt) {
		t.Error("Update must move updated_at forward")
	}
}

func TestUpdateNotFound(t *testing.T) {
	s, _ := newTestStorage(t)
	_, err := s.Update(context.Background(), model.Threat{MD5: testMD5, Name: "X"})
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// TestSchemaConstraints проверяет, что БД сама отклоняет некорректные данные —
// вторая линия защиты на случай ошибки в коде.
func TestSchemaConstraints(t *testing.T) {
	_, pool := newTestStorage(t)
	tests := []struct {
		name string
		sql  string
	}{
		{"upper-case md5", `INSERT INTO threats (md5, name) VALUES ('D41D8CD98F00B204E9800998ECF8427E', 'X')`},
		{"unknown severity", `INSERT INTO threats (md5, name, severity) VALUES ('` + testMD5 + `', 'X', 'extreme')`},
		{"negative file size", `INSERT INTO threats (md5, name, file_size) VALUES ('` + testMD5 + `', 'X', -1)`},
		{"first_seen after last_seen", `INSERT INTO threats (md5, name, first_seen, last_seen)
			VALUES ('` + testMD5 + `', 'X', '2026-10-01', '2026-09-01')`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pool.Exec(context.Background(), tt.sql); err == nil {
				t.Error("expected constraint violation, got nil")
			}
		})
	}
}
