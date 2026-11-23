package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.vitalvas.com/repomgr/internal/cli"
)

var version string

func main() {
	p, err := cli.New(version)
	if err != nil {
		slog.Error("build cli", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err = p.Execute(ctx)

	stop()

	if err != nil {
		slog.Error("repomgr failed", "error", err)
		os.Exit(1)
	}
}
