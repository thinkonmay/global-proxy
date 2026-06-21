package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const otaQueryTimeout = 10 * time.Second

// OTAHandler serves /v1/ota/* (F15).
type OTAHandler struct {
	pr         *postgrest.Client
	serviceKey string
}

func NewOTAHandler(pr *postgrest.Client, serviceKey string) *OTAHandler {
	return &OTAHandler{pr: pr, serviceKey: strings.TrimSpace(serviceKey)}
}

func (h *OTAHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/ota/manifest", h.Manifest)
	mux.HandleFunc("POST /v1/ota/releases", h.PublishRelease)
	mux.HandleFunc("POST /v1/ota/releases/", h.PublishRelease)
}

func (h *OTAHandler) requireServiceKey(r *http.Request) bool {
	if h.serviceKey == "" {
		return true
	}
	if key := strings.TrimSpace(r.Header.Get("apikey")); key == h.serviceKey {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:]) == h.serviceKey
	}
	return false
}

type otaNodeRow struct {
	ProxyMD5  string `json:"proxymd5"`
	DaemonMD5 string `json:"daemonmd5"`
	PBMD5     string `json:"pbmd5"`
	AppMD5    string `json:"appmd5"`
	ProxyURL  string `json:"proxyurl"`
	DaemonURL string `json:"daemonurl"`
	PBURL     string `json:"pburl"`
	AppURL    string `json:"appurl"`
}

type otaBinaryRow struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	MD5Sum      string `json:"md5sum"`
	CreatedAt   string `json:"created_at"`
	Updated     string `json:"updated"`
}

func (h *OTAHandler) Manifest(w http.ResponseWriter, r *http.Request) {
	if binaryName := strings.TrimSpace(r.URL.Query().Get("binary")); binaryName != "" {
		h.manifestBinary(w, r, binaryName)
		return
	}
	h.manifestNode(w, r)
}

func (h *OTAHandler) manifestNode(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), otaQueryTimeout)
	defer cancel()

	var rows []otaNodeRow
	if err := h.pr.RPC(ctx, "local_version_control_v1", map[string]any{}, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	row := rows[0]
	out := map[string]any{}
	addComponent := func(key, md5, rawURL string) {
		md5 = strings.TrimSpace(md5)
		rawURL = strings.TrimSpace(rawURL)
		if md5 == "" && rawURL == "" {
			return
		}
		out[key] = map[string]string{"md5": md5, "url": rawURL}
	}
	addComponent("proxy", row.ProxyMD5, row.ProxyURL)
	addComponent("daemon", row.DaemonMD5, row.DaemonURL)
	addComponent("pocketbase", row.PBMD5, row.PBURL)
	addComponent("app", row.AppMD5, row.AppURL)
	writeJSON(w, http.StatusOK, out)
}

func (h *OTAHandler) manifestBinary(w http.ResponseWriter, r *http.Request, binaryName string) {
	ctx, cancel := context.WithTimeout(r.Context(), otaQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("name", "eq."+binaryName)
	q.Set("order", "created_at.desc")
	q.Set("limit", "1")
	q.Set("select", "name,download_url,md5sum,created_at,updated")

	var rows []otaBinaryRow
	if err := h.pr.Select(ctx, "binary_release", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "binary not found"})
		return
	}
	row := rows[0]
	writeJSON(w, http.StatusOK, map[string]any{
		"data": map[string]string{
			"name":         row.Name,
			"download_url": row.DownloadURL,
			"md5sum":       row.MD5Sum,
			"updated":      firstNonEmptyOTA(row.Updated, row.CreatedAt),
		},
	})
}

func firstNonEmptyOTA(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (h *OTAHandler) PublishRelease(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid service credentials"})
		return
	}
	var body struct {
		Name        string `json:"name"`
		MD5         string `json:"md5"`
		StoragePath string `json:"storage_path"`
		PublicURL   string `json:"public_url"`
		Channel     string `json:"channel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.Name == "" || body.MD5 == "" || body.StoragePath == "" || body.PublicURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, md5, storage_path, and public_url required"})
		return
	}
	if body.Channel == "" {
		body.Channel = "verified"
	}

	ctx, cancel := context.WithTimeout(r.Context(), otaQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "publish_binary_release", map[string]any{
		"p_name":         body.Name,
		"p_md5":          body.MD5,
		"p_storage_path": body.StoragePath,
		"p_public_url":   body.PublicURL,
		"p_channel":      body.Channel,
	}, &out); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": out})
}
