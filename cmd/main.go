package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-stash/sentinel/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	container, err := app.NewContainer(ctx)
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	srv := app.NewServer(container)
	slog.Info("sentinel starting", "addr", srv.Addr(), "env", container.Config.Server.Env)

	go func() {
		if err := srv.Run(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("http shutdown", "error", err)
	}

	if err := container.Shutdown(shutdownCtx); err != nil {
		slog.Error("container shutdown", "error", err)
	}
	slog.Info("sentinel stopped")
}
