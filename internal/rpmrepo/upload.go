package rpmrepo

import (
	"context"
	"fmt"

	"go.vitalvas.com/repomgr/internal/repofs"
)

// processUploads moves upload/<release>/<component>/*.rpm into the pool and
// returns the number of rejected files.
func processUploads(ctx context.Context, workdir string) (int, error) {
	return repofs.ProcessUploads(ctx, workdir, repofs.Upload{
		Ext:    ".rpm",
		Layout: "upload/<release>/<component>/<file>.rpm",
		Add: func(release, component, file string) (repofs.UploadResult, error) {
			res, err := Add(workdir, release, component, file)
			if err != nil {
				return repofs.UploadResult{}, err
			}

			return repofs.UploadResult{Path: res.Path, Added: res.Added}, nil
		},
	})
}

// rejectedError is nil when no upload was rejected.
func rejectedError(rejected int) error {
	switch rejected {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("1 upload rejected: %w", repofs.ErrUploadRejected)
	default:
		return fmt.Errorf("%d uploads rejected: %w", rejected, repofs.ErrUploadRejected)
	}
}
