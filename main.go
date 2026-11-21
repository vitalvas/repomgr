package main

import (
	"context"
	"log/slog"
	"os"

	"go.vitalvas.com/repomgr/internal/cli"
)

var version string

func main() {
	p, err := cli.New(version)
	if err != nil {
		slog.Error("build cli", "error", err)
		os.Exit(1)
	}

	err = p.Execute(context.Background())
	if err != nil {
		slog.Error("repomgr failed", "error", err)
		os.Exit(1)
	}
}
