package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const pbDispatchTimeout = 30 * time.Second

type volumeHandler struct {
	idem *idempotency.Guard
	pr   *postgrest.Client
	http *http.Client
}

func newVolumeHandler(idem *idempotency.Guard, pr *postgrest.Client) *volumeHandler {
	return &volumeHandler{
		idem: idem,
		pr:   pr,
		http: &http.Client{Timeout: pbDispatchTimeout},
	}
}

func (h *volumeHandler) handle(ctx context.Context, env model.VolumeJobEnvelope) error {
	key := fmt.Sprintf("outbox-%d", env.OutboxID)
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		p := env.Payload
		switch p.Command {
		case "create volume v7", "create volume v6":
			return h.createVolume(ctx, p)
		case "update volume v7":
			return h.updateVolume(ctx, p)
		case "delete volume v5":
			return h.deleteVolume(ctx, p)
		default:
			slog.Info("skip unsupported command", "command", p.Command)
			return nil
		}
	})
}

func (h *volumeHandler) createVolume(ctx context.Context, p model.VolumeJobPayload) error {
	token, baseURL, err := h.clusterSecrets(ctx, p.ClusterID)
	if err != nil {
		return err
	}
	userID, err := h.ensurePBUser(ctx, baseURL, token, p.Email)
	if err != nil {
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
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/collections/volumes/records", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))

	resp, err := h.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)

	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	return h.patchJob(ctx, p.JobID, success, respBody)
}

func (h *volumeHandler) updateVolume(ctx context.Context, p model.VolumeJobPayload) error {
	token, baseURL, err := h.clusterSecrets(ctx, p.ClusterID)
	if err != nil {
		return err
	}
	userID, err := h.ensurePBUser(ctx, baseURL, token, p.Email)
	if err != nil {
		return err
	}

	listURL := strings.TrimRight(baseURL, "/") + "/api/collections/volumes/records?" + url.Values{
		"filter": {`(user~"` + userID + `")`},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)

	var list struct {
		Items []struct {
			ID            string          `json:"id"`
			Configuration json.RawMessage `json:"configuration"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
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

	patchBody, _ := json.Marshal(map[string]any{"configuration": argCfg})
	patchURL := strings.TrimRight(baseURL, "/") + "/api/collections/volumes/records/" + item.ID
	patchReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, patchURL, bytes.NewReader(patchBody))
	if err != nil {
		return err
	}
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))

	patchResp, err := h.http.Do(patchReq)
	if err != nil {
		return err
	}
	defer func() { _ = patchResp.Body.Close() }()
	respBody, _ := io.ReadAll(patchResp.Body)
	success := patchResp.StatusCode >= 200 && patchResp.StatusCode < 300
	return h.patchJob(ctx, p.JobID, success, respBody)
}

func (h *volumeHandler) deleteVolume(ctx context.Context, p model.VolumeJobPayload) error {
	return h.pr.RPC(ctx, "unmap_user_email_v2", map[string]any{"job_id": p.JobID}, nil)
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
	return h.pr.Update(ctx, "job", q, patch, nil)
}

func (h *volumeHandler) clusterSecrets(ctx context.Context, clusterID int64) (token, baseURL string, err error) {
	var rows []struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	if err := h.pr.RPC(ctx, "get_cluster_secrets", map[string]any{"cluster_id": clusterID}, &rows); err != nil {
		return "", "", err
	}
	if len(rows) == 0 {
		return "", "", fmt.Errorf("cluster secrets not found")
	}
	return rows[0].Token, rows[0].URL, nil
}

func (h *volumeHandler) ensurePBUser(ctx context.Context, baseURL, adminToken, email string) (string, error) {
	filterURL := strings.TrimRight(baseURL, "/") + "/api/collections/users/records?filter=(email%3D%22" + urlQueryEscape(email) + "%22)"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, filterURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := h.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	_ = json.Unmarshal(data, &list)
	if len(list.Items) > 0 {
		return list.Items[0].ID, nil
	}

	password, err := randomPBPassword()
	if err != nil {
		return "", err
	}
	createBody, _ := json.Marshal(map[string]any{
		"username":        strings.ReplaceAll(email, "@", ""),
		"email":           email,
		"emailVisibility": true,
		"password":        password,
		"passwordConfirm": password,
		"name":            email,
	})
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/api/collections/users/records", bytes.NewReader(createBody))
	if err != nil {
		return "", err
	}
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := h.http.Do(req2)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp2.Body.Close() }()
	data2, _ := io.ReadAll(resp2.Body)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data2, &created); err != nil || created.ID == "" {
		return "", fmt.Errorf("create pb user failed")
	}
	return created.ID, nil
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(s, `"`, `%22`)
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
