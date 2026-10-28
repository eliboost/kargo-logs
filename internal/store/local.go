// Package store provides a local disk storage implementation for storing and retrieving log files.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/logger"
)

// LocalDisk implements the Store interface, storing log files on the local filesystem.
type LocalDisk struct {
	baseDir   string
	retention time.Duration
}

// NewLocalDisk creates a new LocalDisk instance with the specified base directory.
func NewLocalDisk(baseDir string) (*LocalDisk, error) {
	l := logger.Get(context.Background())
	l.Info("creating local disk", "baseDir", baseDir)

	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating storage dir: %w", err)
	}

	return &LocalDisk{baseDir: baseDir, retention: 72 * time.Hour}, nil
}

func (l *LocalDisk) path(key Key) (string, error) {
	segments := []struct {
		name  string
		value string
	}{
		{name: "namespace", value: key.Namespace},
		{name: "analysis run", value: key.AnalysisRun},
		{name: "job name", value: key.JobName},
		{name: "container", value: key.Container},
	}

	clean := make([]string, 0, len(segments))
	for _, segment := range segments {
		part, err := sanitizePathPart(segment.name, segment.value)
		if err != nil {
			return "", err
		}

		clean = append(clean, part)
	}

	p := filepath.Join(l.baseDir, clean[0], clean[1], clean[2], clean[3], "container.log")

	rel, err := filepath.Rel(l.baseDir, p)
	if err != nil {
		return "", fmt.Errorf("compute relative path: %w", err)
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes base directory")
	}

	return p, nil
}

func sanitizePathPart(field, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("%s is required", field)
	}

	if strings.Contains(value, "/") || strings.Contains(value, "\\") {
		return "", fmt.Errorf("%s must not contain path separators", field)
	}

	if value == "." || value == ".." {
		return "", fmt.Errorf("%s must not be relative path segment", field)
	}

	return value, nil
}

// Writer returns a WriteCloser for the specified key, creating necessary directories if they don't exist.
func (l *LocalDisk) Writer(_ context.Context, key Key) (io.WriteCloser, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return nil, err
	}

	//nolint:gosec // path is constrained to l.baseDir by path() validation
	return os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
}

// Reader returns a ReadCloser for the specified key.
func (l *LocalDisk) Reader(_ context.Context, key Key) (io.ReadCloser, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}

	//nolint:gosec // path is constrained to l.baseDir by path() validation
	return os.Open(p)
}

// Exists checks if a log file exists for the specified key.
func (l *LocalDisk) Exists(_ context.Context, key Key) (bool, error) {
	p, err := l.path(key)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(p)
	if os.IsNotExist(err) {
		return false, nil
	}

	return err == nil, err
}

// Purge removes log files older than the retention period.
func (l *LocalDisk) Purge(_ context.Context) error {
	cutoff := time.Now().Add(-l.retention)

	root, err := os.OpenRoot(l.baseDir)
	if err != nil {
		return err
	}

	defer func() {
		_ = root.Close()
	}()

	return filepath.Walk(l.baseDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return err
		}

		if info.ModTime().Before(cutoff) {
			relPath, err := filepath.Rel(l.baseDir, p)
			if err != nil {
				return err
			}

			if err := root.Remove(relPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		}

		return nil
	})
}
