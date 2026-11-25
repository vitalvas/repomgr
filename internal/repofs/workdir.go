package repofs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// RefuseMarkers fails with kind when any marker exists under workdir/public.
func RefuseMarkers(workdir, op string, markers []string, kind error) error {
	for _, marker := range markers {
		markerPath := filepath.Join(workdir, "public", marker)

		_, err := os.Lstat(markerPath)
		if err == nil {
			return fmt.Errorf("%s %s: %w", op, workdir, kind)
		}

		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat %s: %w", markerPath, err)
		}
	}

	return nil
}
