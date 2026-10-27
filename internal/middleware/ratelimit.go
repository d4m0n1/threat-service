package middleware

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
)

// RateLimiter ограничивает частоту запросов с одного IP (token bucket).
type RateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*client
	rps        rate.Limit
	burst      int
	retryAfter int // секунды, значение заголовка Retry-After
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter создаёт ограничитель: rps запросов в секунду в среднем,
// burst — сколько запросов подряд можно сделать без ожидания.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		clients:    make(map[string]*client),
		rps:        rate.Limit(rps),
		burst:      burst,
		retryAfter: max(1, int(math.Ceil(1/rps))),
	}
}

// Middleware отвечает 429 с заголовком Retry-After, если клиент превысил лимит.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.limiterFor(clientIP(r)).Allow() {
			w.Header().Set("Retry-After", strconv.Itoa(rl.retryAfter))
			handler.WriteError(w, http.StatusTooManyRequests,
				handler.ErrorBody(api.RATELIMITED, "Too many requests", ""))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Cleanup раз в interval удаляет клиентов, не обращавшихся дольше ttl,
// чтобы map не рос бесконечно. Работает, пока не отменён ctx.
func (rl *RateLimiter) Cleanup(ctx context.Context, interval, ttl time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			for ip, c := range rl.clients {
				if time.Since(c.lastSeen) > ttl {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// limiterFor возвращает ограничитель клиента, создавая его при первом обращении.
func (rl *RateLimiter) limiterFor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	c, ok := rl.clients[ip]
	if !ok {
		c = &client{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.clients[ip] = c
	}
	c.lastSeen = time.Now()
	return c.limiter
}

// clientIP берёт IP из адреса соединения. X-Forwarded-For намеренно не используется:
// клиент может подделать его, если перед сервисом нет доверенного прокси.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
