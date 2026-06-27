// Package volume consumes volume-lifecycle jobs off the bus and applies them
// to global Postgres + virtdaemon gRPC, patching the originating job row with
// the result. Delivery is at-least-once; an idempotency guard dedups redeliveries.
package volume

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem     *idempotency.Guard
	pr       *postgrest.Client
	dc       *daemonclient.Client
	storj    *storj.Client
	eventBus bus.Client
}

func New(idem *idempotency.Guard, pr *postgrest.Client, dc *daemonclient.Client, st *storj.Client, eventBus bus.Client) *Handler {
	return &Handler{
		idem:     idem,
		pr:       pr,
		dc:       dc,
		storj:    st,
		eventBus: eventBus,
	}
}

// Init subscribes the handler to the volume-job topic.
func (h *Handler) Init(eventBus bus.Client) {
	bus.Subscribe(
		eventBus,
		model.TopicVolumeJob,
		"worker-volume",
		h.handle,
		bus.WithConcurrency(16),
		bus.WithMaxDeliver(5),
	)
}

func (h *Handler) handle(ctx context.Context, p model.VolumeJobMsg) error {
	return h.idem.Run(ctx, "volume-"+p.RequestID, func(ctx context.Context) error {
		jobID, err := h.ensureJob(ctx, p)
		if err != nil {
			return err
		}
		p.JobID = jobID
		deriveFields(&p)
		err = h.dispatch(ctx, p)
		if err == nil {
			return nil
		}
		return err
	})
}

func (h *Handler) dispatch(ctx context.Context, p model.VolumeJobMsg) error {
	var err error
	switch p.Command {
	case "create volume v7", "create volume v6":
		err = h.createVolume(ctx, p)
	case "update volume v7":
		err = h.updateVolume(ctx, p)
	case "delete volume v5":
		err = h.deleteVolume(ctx, p)
	case "snapshot all v1":
		err = h.snapshotAll(ctx, p)
	case "grant app_access", "grant buckets", "grant llm",
		"unmap app_access", "unmap buckets", "unmap llm",
		"reset app_access", "reset llm":
		err = h.handleGrantJob(ctx, p)
	default:
		if patchErr := h.patchJob(ctx, p.JobID, false, jobErrorResult("unsupported command: "+p.Command)); patchErr != nil {
			return patchErr
		}
		return nil
	}
	return err
}

// ensureJob inserts the job row for this request and returns its id. It is
// idempotent: request_id is unique, so a redelivery's insert 409s and we
// recover the existing id instead of creating a duplicate.
func (h *Handler) ensureJob(ctx context.Context, p model.VolumeJobMsg) (int64, error) {
	args := p.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	body := map[string]any{
		"command":    p.Command,
		"cluster":    p.ClusterID,
		"arguments":  args,
		"request_id": p.RequestID,
	}
	var created []struct {
		ID int64 `json:"id"`
	}
	err := h.pr.Insert(ctx, "job", body, &created)
	if err == nil {
		if len(created) == 0 {
			return 0, fmt.Errorf("insert job returned no id (request %s)", p.RequestID)
		}
		return created[0].ID, nil
	}
	if postgrest.IsConflict(err) {
		return h.jobIDByRequest(ctx, p.RequestID)
	}
	return 0, err
}

func (h *Handler) jobIDByRequest(ctx context.Context, requestID string) (int64, error) {
	q := url.Values{}
	q.Set("select", "id")
	q.Set("request_id", "eq."+requestID)
	q.Set("limit", "1")
	var rows []struct {
		ID int64 `json:"id"`
	}
	if err := h.pr.SelectService(ctx, "job", q, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("job for request %s not found", requestID)
	}
	return rows[0].ID, nil
}

// deriveFields fills Email/VolumeID/Configuration from the raw Arguments,
// matching the mapping the retired infra.enqueue_job_outbox trigger applied:
// configuration = arguments minus "email" and "id".
func deriveFields(p *model.VolumeJobMsg) {
	m := map[string]json.RawMessage{}
	_ = json.Unmarshal(p.Arguments, &m)

	p.Email = jsonString(m["email"])
	p.VolumeID = jsonString(m["id"])
	if p.VolumeID == "" {
		p.VolumeID = jsonString(m["volume_id"])
	}
	delete(m, "email")
	delete(m, "id")
	p.Configuration, _ = json.Marshal(m)
}

func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func (h *Handler) patchJob(ctx context.Context, jobID int64, success bool, content []byte) error {
	var result any
	if len(content) > 0 {
		_ = json.Unmarshal(content, &result)
	}
	patch := map[string]any{
		"success":     success,
		"result":      result,
		"finished_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	q := url.Values{}
	q.Set("id", fmt.Sprintf("eq.%d", jobID))
	if err := h.pr.Update(ctx, "job", q, patch, nil); err != nil {
		slog.Error("patch job failed", "job_id", jobID, "err", err)
		return err
	}
	h.notifyJobFinished(ctx, jobID, success, content)
	return nil
}

func (h *Handler) notifyJobFinished(ctx context.Context, jobID int64, success bool, content []byte) {
	if h.eventBus == nil {
		return
	}
	email := h.jobOwnerEmail(ctx, jobID)
	if email == "" {
		return
	}
	var result any
	if len(content) > 0 {
		_ = json.Unmarshal(content, &result)
	}
	_ = model.PublishSSE(ctx, h.eventBus, model.SSEMsg[map[string]any]{
		Type:      "job",
		Recipient: email,
		Data: map[string]any{
			"job_id":   jobID,
			"success":  success,
			"finished": true,
			"result":   result,
		},
	})
}

func (h *Handler) jobOwnerEmail(ctx context.Context, jobID int64) string {
	q := url.Values{}
	q.Set("select", "arguments")
	q.Set("id", fmt.Sprintf("eq.%d", jobID))
	q.Set("limit", "1")
	var rows []struct {
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := h.pr.SelectService(ctx, "job", q, &rows); err != nil || len(rows) == 0 {
		return ""
	}
	m := map[string]json.RawMessage{}
	if json.Unmarshal(rows[0].Arguments, &m) != nil {
		return ""
	}
	return jsonString(m["email"])
}

func jobErrorResult(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

func jobExistsResult(localID string) []byte {
	b, _ := json.Marshal(map[string]any{"idempotent": true, "local_id": localID})
	return b
}
