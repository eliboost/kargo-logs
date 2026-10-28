// Package route is responsible for defining the API routes
package route

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/handler"
)

// Init initializes the API routes
func Init(ctx context.Context) *echo.Echo {
	e := echo.New()

	v1 := e.Group("/api/v1")
	{
		v1.GET("/logs/:project/:analysisRun/:jobName/:container", handler.GetLogs(ctx))
	}

	e.GET("/health", func(c *echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	return e
}
