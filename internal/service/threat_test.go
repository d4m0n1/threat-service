package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/d4m0n1/threat-service/internal/model"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"

// memRepo — хранилище в памяти для юнит-тестов сервиса.
type memRepo struct {
	threats map[string]model.Threat
}

func newMemRepo() *memRepo {
	return &memRepo{threats: map[string]model.Threat{}}
}

func (r *memRepo) Create(_ context.Context, t model.Threat) (model.Threat, error) {
	if _, ok := r.threats[t.MD5]; ok {
		return model.Threat{}, model.ErrAlreadyExists
	}
	r.threats[t.MD5] = t
	return t, nil
}

func (r *memRepo) Get(_ context.Context, md5 string) (model.Threat, error) {
	t, ok := r.threats[md5]
	if !ok {
		return model.Threat{}, model.ErrNotFound
	}
	return t, nil
}

func (r *memRepo) Update(_ context.Context, t model.Threat) (model.Threat, error) {
	if _, ok := r.threats[t.MD5]; !ok {
		return model.Threat{}, model.ErrNotFound
	}
	r.threats[t.MD5] = t
	return t, nil
}

func ptr[T any](v T) *T { return &v }

func TestCreateNormalizesHashes(t *testing.T) {
	const shaUpper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	sha := shaUpper
	svc := New(newMemRepo())

	got, err := svc.Create(context.Background(), model.Threat{
		MD5:    strings.ToUpper(testMD5),
		Name:   "Trojan.Win32.Generic",
		SHA256: &sha,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.MD5 != testMD5 {
		t.Errorf("MD5 = %q, want %q", got.MD5, testMD5)
	}
	if *got.SHA256 != strings.ToLower(shaUpper) {
		t.Errorf("SHA256 = %q, want lower case", *got.SHA256)
	}
	if sha != shaUpper {
		t.Error("Create must not modify the caller's data")
	}
}

func TestGetIsCaseInsensitive(t *testing.T) {
	svc := New(newMemRepo())
	ctx := context.Background()
	if _, err := svc.Create(ctx, model.Threat{MD5: testMD5, Name: "X"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Get(ctx, strings.ToUpper(testMD5)); err != nil {
		t.Errorf("Get with upper-case MD5: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	early := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(24 * time.Hour)

	tests := []struct {
		name    string
		threat  model.Threat
		wantErr bool
	}{
		{name: "minimal", threat: model.Threat{Name: "Trojan.Win32.Generic"}},
		{name: "first_seen before last_seen", threat: model.Threat{Name: "X", FirstSeen: &early, LastSeen: &late}},
		{name: "first_seen equals last_seen", threat: model.Threat{Name: "X", FirstSeen: &early, LastSeen: &early}},
		{name: "only first_seen", threat: model.Threat{Name: "X", FirstSeen: &late}},
		{name: "first_seen after last_seen", threat: model.Threat{Name: "X", FirstSeen: &late, LastSeen: &early}, wantErr: true},
		{name: "name with newline", threat: model.Threat{Name: "Trojan\nX"}, wantErr: true},
		{name: "name with NUL", threat: model.Threat{Name: "A\x00B"}, wantErr: true},
		{name: "multiline description", threat: model.Threat{Name: "X", Description: ptr("line 1\nline 2")}},
		{name: "description with NUL", threat: model.Threat{Name: "X", Description: ptr("a\x00b")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMemRepo()
			threat := tt.threat
			threat.MD5 = testMD5

			_, err := New(repo).Create(context.Background(), threat)
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, model.ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
			if len(repo.threats) != 0 {
				t.Error("invalid threat must not reach the repository")
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	ctx := context.Background()
	svc := New(newMemRepo())
	if _, err := svc.Create(ctx, model.Threat{MD5: testMD5, Name: "Old"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("upper-case md5", func(t *testing.T) {
		got, err := svc.Update(ctx, model.Threat{MD5: strings.ToUpper(testMD5), Name: "New"})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got.Name != "New" {
			t.Errorf("Name = %q, want %q", got.Name, "New")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := svc.Update(ctx, model.Threat{MD5: strings.Repeat("0", 32), Name: "X"})
		if !errors.Is(err, model.ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		_, err := svc.Update(ctx, model.Threat{MD5: testMD5, Name: "A\x00B"})
		if !errors.Is(err, model.ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
}
