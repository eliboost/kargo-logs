// Package logger contains logger functions
//
//nolint:revive // no need to document every function here
package logger

import (
	"context"
	"log/slog"
	"os"

	"gitlab.pnet.ch/linux/go/slogcfg"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/constant"
)

func Get(ctx context.Context) *slog.Logger {
	l := ctx.Value(constant.ContextKeyLogger)
	if l == nil {
		return slog.New(slogcfg.MustNewHandler(os.Stderr, slogcfg.WithFormat(slogcfg.FormatTypeJson)))
	}

	if logger, ok := l.(*slog.Logger); ok {
		return logger
	}

	return slog.New(slogcfg.MustNewHandler(os.Stderr, slogcfg.WithFormat(slogcfg.FormatTypeJson)))
}

func Set(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, constant.ContextKeyLogger, logger)
}

func Error(err error) slog.Attr { return slog.Any(constant.LogKeyError, err) }
