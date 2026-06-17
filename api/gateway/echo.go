package main

import (
	"fmt"

	"github.com/thinkonmay/global-proxy/api/gateway/handler"
	"github.com/thinkonmay/global-proxy/api/gateway/repo"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/validator"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// NewEcho creates a new Echo instance with base middleware.
func NewEcho() *echo.Echo {
	e := echo.New()
	e.Use(middleware.CORS())
	return e
}

// SetupEcho wires the validator and registers application routes.
func SetupEcho(e *echo.Echo, repo *repo.Repo, eventBus bus.Client) error {
	customVal, err := validator.New()
	if err != nil {
		return fmt.Errorf("create validator: %w", err)
	}
	e.Validator = customVal

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})

	echoHandler := handler.NewHandler(e, repo, eventBus)
	echoHandler.Route()

	return nil
}
