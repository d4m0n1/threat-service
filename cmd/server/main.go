// Command server запускает HTTP-сервис обмена информацией об угрозах.
//
// Переменные окружения:
//
//	HTTP_ADDR      адрес сервера (по умолчанию ":8443" с TLS, ":8080" без него)
//	DATABASE_URL   строка подключения к PostgreSQL
//	API_KEYS       API-ключи с ролями: "key1:writer,key2:reader" (ключ — не короче 16 символов)
//	TLS_CERT_FILE  путь к TLS-сертификату (PEM)
//	TLS_KEY_FILE   путь к приватному ключу (PEM); без обеих TLS-переменных сервер работает по HTTP
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/d4m0n1/threat-service/internal/handler"
	"github.com/d4m0n1/threat-service/internal/middleware"
	"github.com/d4m0n1/threat-service/internal/service"
	"github.com/d4m0n1/threat-service/internal/storage"
)

const (
	maxBodyBytes   = 1 << 20         // 1 МБ
	requestTimeout = 5 * time.Second // меньше WriteTimeout, чтобы ответ об ошибке успел уйти
	pingTimeout    = 5 * time.Second
	rateLimitRPS   = 10 // запросов в секунду с одного IP в среднем
	rateLimitBurst = 20 // допустимый всплеск
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("server stopped with error", "err", err)
		os.Exit(1)
	}
}

// run собирает зависимости, запускает сервер и корректно останавливает его по сигналу.
func run(log *slog.Logger) error {
	tlsConfig, err := loadTLSConfig(os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE"))
	if err != nil {
		return err
	}
	defaultAddr := ":8443"
	if tlsConfig == nil {
		defaultAddr = ":8080"
		log.Warn("TLS is disabled: TLS_CERT_FILE and TLS_KEY_FILE are not set, serving plain HTTP")
	}
	addr := getenv("HTTP_ADDR", defaultAddr)
	dbURL := getenv("DATABASE_URL", "postgres://threat:threat@localhost:5434/threats?sslmode=disable")

	apiKeys, err := middleware.ParseAPIKeys(os.Getenv("API_KEYS"))
	if err != nil {
		return fmt.Errorf("parse API_KEYS: %w", err)
	}

	// ctx отменяется по Ctrl+C или SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	limiter := middleware.NewRateLimiter(rateLimitRPS, rateLimitBurst)
	go limiter.Cleanup(ctx, time.Minute, 5*time.Minute)

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("create db pool: %w", err)
	}
	defer pool.Close()
	pingCtx, pingCancel := context.WithTimeout(ctx, pingTimeout)
	defer pingCancel()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("connect to db: %w", err)
	}

	svc := service.New(storage.New(pool))
	router, err := handler.NewRouter(svc, log)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           newHandler(router, apiKeys, limiter, requestTimeout, log),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server started", "addr", addr, "tls", tlsConfig != nil)
		var err error
		if tlsConfig != nil {
			// Сертификат уже загружен в srv.TLSConfig, поэтому пути пустые.
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// newHandler оборачивает роутер API в цепочку middleware.
// Порядок выполнения: логирование -> recover -> rate-limit -> авторизация ->
// лимит тела -> таймаут -> валидация и обработчики (router).
// Авторизация стоит до лимита тела, чтобы не читать тело от клиента без ключа.
func newHandler(router http.Handler, keys middleware.APIKeys, limiter *middleware.RateLimiter,
	timeout time.Duration, log *slog.Logger) http.Handler {
	h := middleware.Timeout(timeout)(router)
	h = middleware.BodyLimit(maxBodyBytes)(h)
	h = middleware.Auth(keys)(h)
	h = limiter.Middleware(h)
	h = middleware.Recover(log)(h)
	return middleware.Logging(log)(h)
}

// getenv возвращает значение переменной окружения или def, если она не задана.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadTLSConfig загружает сертификат и ключ. Если оба пути пусты, возвращает nil — TLS выключен.
func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("both TLS_CERT_FILE and TLS_KEY_FILE must be set")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
