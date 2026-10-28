package store

import (
	"context"
	"io"
)

// Key identifies a single container's log stream for one AnalysisRun job
// in one cluster.
type Key struct {
	Namespace   string
	AnalysisRun string
	JobName     string
	Container   string
}

// Store is an interface for storing and retrieving log streams.
type Store interface {
	Writer(ctx context.Context, key Key) (io.WriteCloser, error)
	Reader(ctx context.Context, key Key) (io.ReadCloser, error)
	Exists(ctx context.Context, key Key) (bool, error)
	Purge(ctx context.Context) error
}
