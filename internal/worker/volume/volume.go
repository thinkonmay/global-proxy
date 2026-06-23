// Package volume consumes volume-lifecycle jobs off the bus and applies them
// to the target cluster's PocketBase, patching the originating job row with the
// result. Delivery is at-least-once; an idempotency guard dedups redeliveries.
package volume

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem *idempotency.Guard
	pr   *postgrest.Client
	pb   *pocketbase.Client
}

func New(idem *idempotency.Guard, pr *postgrest.Client, pb *pocketbase.Client) *Handler {
	return &Handler{
		idem: idem,
		pr:   pr,
		pb:   pb,
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
		// The worker is the sole DB writer: insert the job row (idempotent on
		// request_id) before applying, so a publish-only gateway leaves no
		// orphan and a redelivery never duplicates.
		jobID, err := h.ensureJob(ctx, p)
		if err != nil {
			return err
		}
		p.JobID = jobID
		deriveFields(&p)

		switch p.Command {
		case "create volume v7", "create volume v6":
			err = h.createVolume(ctx, p)
		case "update volume v7":
			err = h.updateVolume(ctx, p)
		case "delete volume v5":
			err = h.deleteVolume(ctx, p)
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
		if err == nil || isPermanentDispatchError(err) {
			return nil
		}
		return err
	})
}

func isPermanentDispatchError(err error) bool {
	var pe *pocketbase.Error
	if errors.As(err, &pe) {
		return pe.Status >= 400 && pe.Status < 500 && pe.Status != http.StatusTooManyRequests
	}
	return false
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

func (h *Handler) patchJobFromPBError(ctx context.Context, jobID int64, err error) error {
	var pe *pocketbase.Error
	if errors.As(err, &pe) {
		if patchErr := h.patchJob(ctx, jobID, false, pe.Body); patchErr != nil {
			return patchErr
		}
		if isPermanentDispatchError(err) {
			return nil
		}
		return err
	}
	if patchErr := h.patchJob(ctx, jobID, false, jobErrorResult(err.Error())); patchErr != nil {
		return patchErr
	}
	return err
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
	return nil
}

func (h *Handler) clusterURL(ctx context.Context, clusterID int64) (string, error) {
	var rows []struct {
		URL string `json:"url"`
	}
	if err := h.pr.RPC(ctx, "get_cluster_secrets", map[string]any{"cluster_id": clusterID}, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 || rows[0].URL == "" {
		return "", fmt.Errorf("cluster url not found")
	}
	return rows[0].URL, nil
}

func (h *Handler) ensurePBUser(ctx context.Context, pb *pocketbase.Client, email string) (string, error) {
	q := url.Values{}
	q.Set("filter", fmt.Sprintf(`(email="%s")`, email))
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "users", q, &list); err != nil {
		return "", err
	}
	if len(list.Items) > 0 {
		return list.Items[0].ID, nil
	}

	password, err := randomPBPassword()
	if err != nil {
		return "", err
	}
	var created struct {
		ID string `json:"id"`
	}
	err = pb.CreateRecord(ctx, "users", map[string]any{
		"username":        strings.ReplaceAll(email, "@", ""),
		"email":           email,
		"emailVisibility": true,
		"password":        password,
		"passwordConfirm": password,
		"name":            email,
	}, &created)
	if err != nil || created.ID == "" {
		return "", fmt.Errorf("create pb user failed: %w", err)
	}
	return created.ID, nil
}

func randomPBPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func jobErrorResult(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

func jobExistsResult(localID string) []byte {
	b, _ := json.Marshal(map[string]any{"idempotent": true, "local_id": localID})
	return b
}
