package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

	res, err := debrepo.Add(h.cfg.Workdir, cfg.Suite, cfg.Component, args[0], false)
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

	// Build returns summaries with ErrUploadRejected after publishing, so the
	// built lines are logged before the error is returned.
	summaries, err := debrepo.Build(ctx, h.cfg.Workdir, time.Now())

	for _, s := range summaries {
		slog.InfoContext(ctx, "built", "suite", s.Suite, "packages", s.Packages, "architectures", s.Architectures)
	}

	return err
}

type mirrorConfig struct {
	Workdir         string `long:"workdir" required:"true" description:"repository working directory"`
	SourceRepo      string `long:"source-repo" required:"true" description:"upstream repository base URL"`
	SourceSuite     string `long:"source-suite" required:"true" description:"upstream suite name"`
	SourceComponent string `long:"source-component" required:"true" description:"upstream component name"`
	TargetSuite     string `long:"target-suite" required:"true" description:"local suite name"`
	TargetComponent string `long:"target-component" required:"true" description:"local component name"`
	SourceKey       string `long:"source-key" description:"upstream public key file, armored or binary, optional"`
	Force           bool   `long:"force" description:"replace local pool files whose checksum differs from upstream"`

	Name                string `long:"filter-name" default:".*" description:"keep packages whose name matches"`
	NameExclude         string `long:"filter-name-exclude" description:"drop packages whose name matches"`
	Version             string `long:"filter-version" default:".*" description:"keep packages whose version matches"`
	VersionExclude      string `long:"filter-version-exclude" description:"drop packages whose version matches"`
	Architecture        string `long:"filter-architecture" description:"keep packages whose architecture matches"`
	ArchitectureExclude string `long:"filter-architecture-exclude" description:"drop packages whose architecture matches"`
}

func mirror(ctx context.Context, _ *xflags.Command, cfg *mirrorConfig, args []string) error {
	if len(args) != 0 {
		return errors.New("deb-mirror takes no positional arguments")
	}

	var sourceKey []byte

	if cfg.SourceKey != "" {
		var err error

		sourceKey, err = os.ReadFile(cfg.SourceKey)
		if err != nil {
			return fmt.Errorf("read source key: %w", err)
		}

		if len(sourceKey) == 0 {
			return fmt.Errorf("source key %s is empty", cfg.SourceKey)
		}
	}

	r, err := debrepo.Mirror(ctx, cfg.Workdir, debrepo.MirrorOptions{
		SourceKey:       sourceKey,
		Force:           cfg.Force,
		SourceRepo:      cfg.SourceRepo,
		SourceSuite:     cfg.SourceSuite,
		SourceComponent: cfg.SourceComponent,
		TargetSuite:     cfg.TargetSuite,
		TargetComponent: cfg.TargetComponent,

		Name:                cfg.Name,
		NameExclude:         cfg.NameExclude,
		Version:             cfg.Version,
		VersionExclude:      cfg.VersionExclude,
		Architecture:        cfg.Architecture,
		ArchitectureExclude: cfg.ArchitectureExclude,
	})
	if err == nil || errors.Is(err, debrepo.ErrMirrorFailed) {
		slog.InfoContext(ctx, "mirrored", "source", cfg.SourceRepo, "suite", cfg.TargetSuite, "component", cfg.TargetComponent,
			"added", r.Added, "replaced", r.Replaced, "unchanged", r.Unchanged, "failed", r.Failed)
	}

	return err
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

	_, mirrorCmd, mirrorErr := xflags.BindCommand("deb-mirror", "mirror an upstream deb repository", mirror)

	err := errors.Join(debErr, initErr, addErr, buildErr, mirrorErr)
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
		mirrorCmd.Validate("workdir", nonEmpty),
		mirrorCmd.Validate("source-repo", nonEmpty),
		mirrorCmd.Validate("source-suite", nonEmpty),
		mirrorCmd.Validate("source-component", nonEmpty),
		mirrorCmd.Validate("target-suite", nonEmpty),
		mirrorCmd.Validate("target-component", nonEmpty),
		p.AddCommand(mirrorCmd),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}
