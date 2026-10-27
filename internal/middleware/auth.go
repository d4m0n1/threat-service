package middleware

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
)

// minKeyLength — минимальная длина API-ключа.
const minKeyLength = 16

// Role — уровень доступа API-ключа.
type Role string

// Роли API-ключей.
const (
	RoleReader Role = "reader" // только чтение (GET)
	RoleWriter Role = "writer" // все операции
)

// APIKeys сопоставляет SHA-256 ключа и его роль. Сами ключи в памяти не хранятся.
type APIKeys map[[sha256.Size]byte]Role

// ParseAPIKeys разбирает строку вида "key1:writer,key2:reader".
// Ошибки не содержат самих ключей, чтобы они не попали в лог.
func ParseAPIKeys(s string) (APIKeys, error) {
	keys := APIKeys{}
	for i, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, role, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("entry #%d: expected format key:role", i+1)
		}
		if len(key) < minKeyLength {
			return nil, fmt.Errorf("entry #%d: key must be at least %d characters", i+1, minKeyLength)
		}
		r := Role(role)
		if r != RoleReader && r != RoleWriter {
			return nil, fmt.Errorf("entry #%d: unknown role %q (want reader or writer)", i+1, role)
		}
		keys[sha256.Sum256([]byte(key))] = r
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no API keys configured")
	}
	return keys, nil
}

// Auth проверяет заголовок X-API-Key.
// 401 — ключ не передан или неизвестен, 403 — роль reader пытается изменить данные.
func Auth(keys APIKeys) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			role, ok := keys[sha256.Sum256([]byte(key))]
			if key == "" || !ok {
				handler.WriteError(w, http.StatusUnauthorized,
					handler.ErrorBody(api.UNAUTHORIZED, "Unauthorized", "Missing or invalid API key"))
				return
			}
			if role != RoleWriter && !isReadOnly(r.Method) {
				handler.WriteError(w, http.StatusForbidden,
					handler.ErrorBody(api.FORBIDDEN, "Forbidden", "API key role does not allow this operation"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isReadOnly сообщает, только ли читает данные запрос с таким методом.
func isReadOnly(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}
