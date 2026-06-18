package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/repo"
)

type Handler struct {
	e    *echo.Echo
	repo *repo.Repo
	bus  bus.Client
}

func NewHandler(e *echo.Echo, repo *repo.Repo, bus bus.Client) *Handler {
	return &Handler{
		e:    e,
		repo: repo,
		bus:  bus,
	}
}

func (h *Handler) Init() {
	h.e.POST("/jobs", h.create)
	h.e.GET("/jobs/:id", h.get)
}
