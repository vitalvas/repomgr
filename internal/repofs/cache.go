package repofs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCache reads <workdir>/cache/index.json. A missing, invalid, or null file gives an empty map.
func LoadCache[T any](workdir string) (map[string]T, error) {
	file := filepath.Join(workdir, "cache", "index.json")

	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]T{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}

	var entries map[string]T

	err = json.Unmarshal(data, &entries)
	if err != nil || entries == nil {
		return map[string]T{}, nil
	}

	return entries, nil
}

// SaveCache writes entries to <workdir>/cache/index.json atomically.
func SaveCache[T any](workdir string, entries map[string]T) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encode cache: %w", err)
	}

	// ponytail: concurrent add/build on one workdir are not coordinated and can lose cache entries, a lock file is the upgrade path.
	return WriteAtomic(filepath.Join(workdir, "cache", "index.json"), bytes.NewReader(data), 0o644, nil)
}
