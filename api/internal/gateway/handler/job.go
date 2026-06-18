package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
	"github.com/thinkonmay/global-proxy/api/shared/repo"

	"github.com/labstack/echo/v4"
)

type createJobRequest struct {
	Command   string          `json:"command" validate:"required"`
	Arguments json.RawMessage `json:"arguments"`
	Cluster   *int64          `json:"cluster"`
}

func (h *Handler) create(c echo.Context) error {
	var req createJobRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid body")
	}
	if err := c.Validate(&req); err != nil {
		return err
	}

	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}") // arguments column is NOT NULL
	}

	ctx := c.Request().Context()
	id, err := h.repo.Enqueue(ctx, req.Command, args, req.Cluster)
	if err != nil {
		return err
	}

	if err := bus.Publish(ctx, h.bus, model.TopicJob, model.JobMsg{ID: id, Command: req.Command, Arguments: args}); err != nil {
		return err
	}

	return c.JSON(http.StatusAccepted, map[string]int64{"id": id})
}

func (h *Handler) get(c echo.Context) error {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid id")
	}

	j, err := h.repo.Get(c.Request().Context(), id)
	if errors.Is(err, repo.ErrNotFound) {
		return echo.NewHTTPError(http.StatusNotFound, "job not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, j)
}
