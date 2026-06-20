package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/validator"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

var topicDevJob = bus.NewTopic[model.JobMsg]("jobs.dev")

type createJobRequest struct {
	Command   string          `json:"command" validate:"required"`
	Arguments json.RawMessage `json:"arguments"`
}

// CreateJob publishes a job to the bus and fast-returns its id — the idempotency
// key the worker dedups on. No DB write.
func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	var req createJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := validator.Validate(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	id := uuid.NewString()

	// Publish ack from JetStream = persisted; that is the only outcome checked (P11).
	if err := bus.Publish(
		r.Context(),
		h.bus,
		topicDevJob,
		model.JobMsg{ID: id, Command: req.Command, Arguments: args},
	); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]bool{"global_unavailable": true})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}
