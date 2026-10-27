// Command server запускает HTTP-сервис обмена информацией об угрозах.
//
// Переменные окружения:
//
//	HTTP_ADDR     адрес, на котором слушает сервер (по умолчанию ":8080")
//	DATABASE_URL  строка подключения к PostgreSQL
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/d4m0n1/threat-service/internal/api"
	"github.com/d4m0n1/threat-service/internal/handler"
	"github.com/d4m0n1/threat-service/internal/middleware"
	"github.com/d4m0n1/threat-service/internal/service"
	"github.com/d4m0n1/threat-service/internal/storage"
)

const maxBodyBytes = 1 << 20 // 1 МБ

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("server stopped with error", "err", err)
		os.Exit(1)
	}
}

// run собирает зависимости, запускает сервер и корректно останавливает его по сигналу.
func run(log *slog.Logger) error {
	addr := getenv("HTTP_ADDR", ":8080")
	dbURL := getenv("DATABASE_URL", "postgres://threat:threat@localhost:5434/threats?sslmode=disable")

	// ctx отменяется по Ctrl+C или SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("create db pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect to db: %w", err)
	}

	svc := service.New(storage.New(pool))
	strict := api.NewStrictHandlerWithOptions(handler.New(svc), nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  handler.RequestErrorHandler,
		ResponseErrorHandlerFunc: handler.NewResponseErrorHandler(log),
	})

	validator, err := handler.NewValidator()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	api.HandlerFromMux(strict, mux)

	// Порядок выполнения: логирование -> recover -> лимит тела -> валидация -> маршрутизация -> handler.
	var root http.Handler = mux
	root = validator(root)
	root = http.MaxBytesHandler(root, maxBodyBytes)
	root = middleware.Recover(log)(root)
	root = middleware.Logging(log)(root)

	srv := &http.Server{
		Addr:              addr,
		Handler:           root,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server started", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// getenv возвращает значение переменной окружения или def, если она не задана.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
