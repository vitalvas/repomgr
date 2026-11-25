package debrepo

import (
	"context"
	"errors"
	"path/filepath"

	"go.vitalvas.com/repomgr/internal/pgpsign"
	"go.vitalvas.com/repomgr/internal/repofs"
)

var (
	ErrAlreadyInitialized = repofs.ErrAlreadyInitialized
	ErrRPMWorkdir         = errors.New("workdir holds an rpm repository")

	rpmMarkers = []string{"x86_64", "aarch64"}
)

func Init(ctx context.Context, workdir, name, email string) error {
	err := repofs.RefuseMarkers(workdir, "init", rpmMarkers, ErrRPMWorkdir)
	if err != nil {
		return err
	}

	return repofs.InitKey(ctx, repofs.KeyInit{
		Workdir: workdir,
		Name:    name,
		Email:   email,
		Publish: func(ctx context.Context, public []byte) error {
			files, err := publicKeyFiles(workdir, public)
			if err != nil {
				return err
			}

			return publishFiles(ctx, workdir, files, "created")
		},
	})
}

// publicKeyFiles returns public/key.gpg for keyring files and public/key.asc
// for keys embedded in Signed-By.
func publicKeyFiles(workdir string, public []byte) ([]outputFile, error) {
	armored, err := pgpsign.ArmorPublicKey(public)
	if err != nil {
		return nil, err
	}

	return []outputFile{
		{path: filepath.Join(workdir, "public", "key.gpg"), data: public},
		{path: filepath.Join(workdir, "public", "key.asc"), data: armored},
	}, nil
}
