// Package handler provides HTTP handlers for the echo server.
package handler

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/labstack/echo/v5"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/logger"
)

// GetLogs handles the GET /logs endpoint
func GetLogs(ctx context.Context) echo.HandlerFunc {
	l := logger.Get(ctx)

	return func(c *echo.Context) error {
		project := c.Param("project")
		analysisRun := c.Param("analysisRun")
		jobName := c.Param("jobName")
		container := c.Param("container")

		if project == "" || analysisRun == "" || jobName == "" || container == "" {
			return c.String(http.StatusBadRequest, "missing required path parameters")
		}

		namespace := c.QueryParam("namespace")

		if namespace == "" {
			namespace = project
		}

		l.Info("Fetching logs for project: %s, analysisRun: %s, jobName: %s, container: %s", project, analysisRun, jobName, container)

		segments := []string{namespace, analysisRun, jobName, container}
		if slices.ContainsFunc(segments, containsInvalidChars) {
			return c.String(http.StatusBadRequest, "invalid path parameters")
		}

		const baseDir = "/tmp/logs"

		logPath := filepath.Join(baseDir, namespace, analysisRun, jobName, container, "container.log")

		if !strings.HasPrefix(logPath, baseDir+string(filepath.Separator)) {
			return c.String(http.StatusBadRequest, "invalid path parameters")
		}

		data, err := os.ReadFile(logPath) // #nosec G304 -- path is validated above
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return c.String(http.StatusNotFound, "log file not found")
			}

			l.Info("Failed to read log file %s: %v", logPath, err)

			return c.String(http.StatusInternalServerError, "failed to read log file")
		}

		return c.Blob(http.StatusOK, "text/plain; charset=utf-8", data)
	}
}

func containsInvalidChars(s string) bool {
	if len(s) == 0 {
		return false
	}

	if strings.Contains(s, "..") {
		return true
	}

	for _, c := range s {
		switch c {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return true
		}
	}

	return false
}
