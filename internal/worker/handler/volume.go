package handler

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

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type volumeHandler struct {
	idem *idempotency.Guard
	pr   *postgrest.Client
	pb   *pocketbase.Client
}

func newVolumeHandler(idem *idempotency.Guard, pr *postgrest.Client, pb *pocketbase.Client) *volumeHandler {
	return &volumeHandler{
		idem: idem,
		pr:   pr,
		pb:   pb,
	}
}

func (h *volumeHandler) handle(ctx context.Context, env model.VolumeJobEnvelope) error {
	key := fmt.Sprintf("outbox-%d", env.OutboxID)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		p := env.Payload
		var err error
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

func (h *volumeHandler) createVolume(ctx context.Context, p model.VolumeJobPayload) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	body := map[string]any{
		"user":     userID,
		"local_id": p.VolumeID,
	}
	if len(p.Configuration) > 0 {
		var cfg map[string]any
		if json.Unmarshal(p.Configuration, &cfg) == nil {
			for k, v := range cfg {
				body[k] = v
			}
		}
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	var created map[string]any
	err = pb.CreateRecord(ctx, "volumes", body, &created, pocketbase.WithHeaders(headers))
	if err != nil {
		if p.VolumeID != "" && h.volumeExistsByLocalID(ctx, pb, userID, p.VolumeID) {
			return h.patchJob(ctx, p.JobID, true, jobExistsResult(p.VolumeID))
		}
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	respBody, _ := json.Marshal(created)
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func (h *volumeHandler) volumeExistsByLocalID(ctx context.Context, pb *pocketbase.Client, userID, localID string) bool {
	if localID == "" {
		return false
	}
	q := url.Values{}
	q.Set("filter", fmt.Sprintf(`(user~"%s" && local_id="%s")`, userID, localID))
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		return false
	}
	return len(list.Items) > 0
}

func (h *volumeHandler) updateVolume(ctx context.Context, p model.VolumeJobPayload) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID            string          `json:"id"`
			Configuration json.RawMessage `json:"configuration"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}
	if len(list.Items) == 0 {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("Volume not found"))
	}

	item := list.Items[0]
	argCfg := map[string]any{}
	if len(p.Configuration) > 0 {
		_ = json.Unmarshal(p.Configuration, &argCfg)
	}
	var oldCfg map[string]any
	if len(item.Configuration) > 0 {
		_ = json.Unmarshal(item.Configuration, &oldCfg)
	}
	for _, key := range []string{"email", "template", "disk"} {
		if oldCfg != nil {
			if v, ok := oldCfg[key]; ok {
				argCfg[key] = v
			}
		}
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	var updated map[string]any
	err = pb.UpdateRecord(ctx, "volumes", item.ID, map[string]any{"configuration": argCfg}, &updated, pocketbase.WithHeaders(headers))
	if err != nil {
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	respBody, _ := json.Marshal(updated)
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func (h *volumeHandler) deleteVolume(ctx context.Context, p model.VolumeJobPayload) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}
	if len(list.Items) == 0 {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("Volume not found"))
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	if err := pb.DeleteRecord(ctx, "volumes", list.Items[0].ID, pocketbase.WithHeaders(headers)); err != nil {
		if pocketbase.IsNotFound(err) {
			return h.patchJob(ctx, p.JobID, true, []byte(`{"deleted":true}`))
		}
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	return h.patchJob(ctx, p.JobID, true, []byte(`{"deleted":true}`))
}

func (h *volumeHandler) patchJobFromPBError(ctx context.Context, jobID int64, err error) error {
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

func (h *volumeHandler) patchJob(ctx context.Context, jobID int64, success bool, content []byte) error {
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

func (h *volumeHandler) clusterURL(ctx context.Context, clusterID int64) (string, error) {
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

func (h *volumeHandler) ensurePBUser(ctx context.Context, pb *pocketbase.Client, email string) (string, error) {
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
