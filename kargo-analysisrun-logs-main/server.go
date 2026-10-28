// Package main is the entry point for the application
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"gitlab.pnet.ch/linux/go/slogcfg"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/collector"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/logger"
	route "gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/router"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/store"
)

func main() {
	level := slog.LevelInfo

	// possible values are debug,info,warn,error
	logLevel := os.Getenv("LOG_LEVEL")

	if logLevel != "" {
		err := level.UnmarshalText([]byte(logLevel))
		if err != nil {
			fmt.Printf("parse log level failed: %v", err)
		}
	}

	rootCtx := context.Background()
	h := slogcfg.MustNewHandler(os.Stderr, slogcfg.WithFormat(slogcfg.FormatTypeJson), slogcfg.WithLevel(level))
	l := slog.New(h)
	rootCtx = logger.Set(rootCtx, l)

	st, err := store.NewLocalDisk("/tmp/logs")
	if err != nil {
		log.Fatalf("failed to init store: %v", err)
	}

	kargoNamespace := os.Getenv("KARGO_NAMESPACE")
	if kargoNamespace == "" {
		kargoNamespace = "kube-kargo"
	}

	c, err := collector.New(kargoNamespace, st)
	if err != nil {
		log.Fatalf("failed to initialize collector: %v", err)
	}

	go func() {
		if err := c.Start(rootCtx); err != nil {
			log.Fatalf("collector exited: %v", err)
		}
	}()

	router := route.Init(rootCtx)

	err = router.Start(":8080")
	if err != nil {
		l.Error("Failed to start HTTP server", logger.Error(err))
	}
}
