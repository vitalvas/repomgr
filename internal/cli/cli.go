package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"time"

	"go.vitalvas.com/gokit/xflags"
	"go.vitalvas.com/repomgr/internal/debrepo"
)

type debConfig struct {
	Workdir string `long:"workdir" required:"true" description:"repository working directory"`
}

type initConfig struct {
	Name  string `long:"name" required:"true" description:"signing key owner name"`
	Email string `long:"email" description:"signing key owner email, optional"`
}

type addConfig struct {
	Suite     string `long:"suite" required:"true" description:"suite name"`
	Component string `long:"component" required:"true" description:"component name"`
}

type buildConfig struct{}

type debHandlers struct {
	cfg *debConfig
}

func (h *debHandlers) add(ctx context.Context, _ *xflags.Command, cfg *addConfig, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("add requires exactly one .deb file, got %d", len(args))
	}

	res, err := debrepo.Add(ctx, h.cfg.Workdir, cfg.Suite, cfg.Component, args[0])
	if err != nil {
		return err
	}

	if res.Added {
		slog.InfoContext(ctx, "added", "path", path.Join("public", res.Path))
	} else {
		slog.InfoContext(ctx, "unchanged", "path", path.Join("public", res.Path))
	}

	return nil
}

func (h *debHandlers) init(ctx context.Context, _ *xflags.Command, cfg *initConfig, args []string) error {
	if len(args) != 0 {
		return errors.New("init takes no positional arguments")
	}

	return debrepo.Init(ctx, h.cfg.Workdir, cfg.Name, cfg.Email)
}

func (h *debHandlers) build(ctx context.Context, _ *xflags.Command, _ *buildConfig, args []string) error {
	if len(args) != 0 {
		return errors.New("build takes no positional arguments")
	}

	summaries, err := debrepo.Build(ctx, h.cfg.Workdir, time.Now())
	if err != nil {
		return err
	}

	for _, s := range summaries {
		slog.InfoContext(ctx, "built", "suite", s.Suite, "packages", s.Packages, "architectures", s.Architectures)
	}

	return nil
}

func nonEmpty(value any) error {
	if value == "" {
		return errors.New("must not be empty")
	}

	return nil
}

func New(version string) (*xflags.Parser, error) {
	p := xflags.New("repomgr")
	p.SetVersion(version)

	debCfg, deb, debErr := xflags.BindCommand[debConfig]("deb", "manage a deb repository", nil)
	h := &debHandlers{cfg: debCfg}
	_, initCmd, initErr := xflags.BindCommand("init", "initialize the workdir", h.init)
	_, addCmd, addErr := xflags.BindCommand("add", "add a package to the pool", h.add)

	_, buildCmd, buildErr := xflags.BindCommand("build", "build package indexes", h.build)

	err := errors.Join(debErr, initErr, addErr, buildErr)
	if err != nil {
		return nil, err
	}

	err = errors.Join(
		deb.Validate("workdir", nonEmpty),
		initCmd.Validate("name", nonEmpty),
		deb.AddCommand(initCmd),
		deb.AddCommand(addCmd),
		deb.AddCommand(buildCmd),
		p.AddCommand(deb),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}
