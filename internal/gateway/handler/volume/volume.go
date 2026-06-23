// Package volume serves POST /volume: it validates the request, resolves the
// target cluster, then publishes the volume-lifecycle job to the bus. There is
// no outbox and no DB write here — the gateway is a thin publisher. A failed
// publish fast-fails the caller (nothing was persisted, so nothing to clean
// up). The worker is the sole DB writer: it inserts the job row and dedups on
// the request id, so at-least-once redelivery never duplicates.
package volume

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/validator"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const publishTimeout = 10 * time.Second

// supportedCommands mirrors the worker's dispatch switch and the command filter
// the retired infra.enqueue_job_outbox trigger used.
var supportedCommands = map[string]bool{
	"create volume v7": true,
	"create volume v6": true,
	"update volume v7": true,
	"delete volume v5": true,
	"grant app_access": true,
	"grant buckets":    true,
	"grant llm":        true,
	"unmap app_access": true,
	"unmap buckets":    true,
	"unmap llm":        true,
	"reset app_access": true,
	"reset llm":        true,
}

type Handler struct {
	pr  *postgrest.Client
	bus bus.Client
}

func New(pr *postgrest.Client, b bus.Client) *Handler {
	return &Handler{pr: pr, bus: b}
}

// Register mounts POST /volume. With no bus (dev), volume jobs are disabled.
func (h *Handler) Register(mux *http.ServeMux) {
	if h.bus == nil {
		return
	}
	mux.HandleFunc("POST /volume", h.CreateVolume)
}

type createVolumeRequest struct {
	Command   string          `json:"command" validate:"required"`
	Cluster   int64           `json:"cluster" validate:"required"`
	Arguments json.RawMessage `json:"arguments"`
}

// CreateVolume validates, resolves the cluster, then publishes the job. It
// writes nothing to the DB — the worker owns the insert.
func (h *Handler) CreateVolume(w http.ResponseWriter, r *http.Request) {
	var req createVolumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := validator.Validate(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !supportedCommands[req.Command] {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported command: "+req.Command)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), publishTimeout)
	defer cancel()

	// Resolve cluster routing up-front so a bad cluster fails at request time.
	info, err := cluster.Lookup(ctx, h.pr, req.Cluster)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}

	requestID := uuid.NewString()
	msg := model.VolumeJobMsg{
		RequestID:    requestID,
		Command:      req.Command,
		ClusterID:    info.ID,
		Arguments:    args,
		TargetDomain: info.Domain,
	}

	// Must publish. A JetStream ack = persisted = worker gets it at least once.
	if err := bus.Publish(ctx, h.bus, model.TopicVolumeJob, msg); err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]bool{"global_unavailable": true})
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"id": requestID})
}
