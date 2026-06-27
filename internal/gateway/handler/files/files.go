package files

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const (
	filesTimeout = 120 * time.Second
	grantTimeout = 2 * time.Second
)

type Handler struct {
	pr        *postgrest.Client
	storj     *storj.Client
	transport http.RoundTripper
}

func New(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	var st *storj.Client
	if grant := strings.TrimSpace(cfg.Storj.AccessGrant); grant != "" {
		if c, err := storj.New(grant, 24*time.Hour); err == nil {
			st = c
		}
	}
	return &Handler{pr: pr, storj: st, transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.GET("/files/list/{path...}", h.listFiles)
	v1.GET("/files/{path...}", h.downloadFile)
	v1.PUT("/files/{path...}", h.uploadFile)

	// Legacy pb-proxy aliases (files only; snapshots stay on node proxy).
	v1.GET("/pb-proxy/files/v1/{path...}", h.listFilesLegacy)
	v1.GET("/pb-proxy/file/v1/{path...}", h.downloadFileLegacy)
	v1.GET("/internal/sync-bucket-size", h.SyncBucketSize)
	v1.POST("/internal/increment-app-access-usage", h.IncrementAppAccessUsage)
	v1.POST("/internal/increment-llm-usage", h.IncrementLLMUsage)
	v1.GET("/internal/lookup-app-access", h.LookupAppAccess)
}

func (h *Handler) listFiles(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/list/")
	h.serveList(w, r, path)
}

func (h *Handler) listFilesLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/files/v1/")
	h.serveList(w, r, path)
}

func (h *Handler) downloadFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/")
	if strings.HasPrefix(path, "list/") {
		http.NotFound(w, r)
		return
	}
	h.serveDownload(w, r, path)
}

func (h *Handler) downloadFileLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/file/v1/")
	h.serveDownload(w, r, path)
}

func (h *Handler) uploadFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/")
	if strings.HasPrefix(path, "list/") {
		http.NotFound(w, r)
		return
	}
	h.serveUpload(w, r, path)
}

func (h *Handler) uploadFileLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/file/v1/")
	h.serveUpload(w, r, path)
}

func (h *Handler) serveList(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	if h.storj == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "storj not configured")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), filesTimeout)
	defer cancel()
	objs, err := h.storj.ListObjects(bucket, path)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to list objects")
		return
	}
	_ = ctx
	httpx.WriteJSON(w, http.StatusOK, objs)
}

func (h *Handler) serveDownload(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	if h.storj == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "storj not configured")
		return
	}
	url, err := h.storj.DownloadableURL(bucket, path, 15*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate download url")
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) serveUpload(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	if h.storj == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "storj not configured")
		return
	}
	url, err := h.storj.UploadableURL(bucket, path, 15*time.Minute)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "failed to generate upload url")
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *Handler) resolveBucket(r *http.Request) (string, int, string) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		return "", http.StatusUnauthorized, "authorization required"
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	email, ok, status, msg := auth.RequireUser(ctx, r, h.transport)
	if !ok {
		return "", status, msg
	}
	volumeID := strings.TrimSpace(r.URL.Query().Get("volume_id"))
	domain, err := cluster.ResolveGrantDomain(ctx, h.pr, email, volumeID)
	if err != nil {
		return "", http.StatusBadRequest, err.Error()
	}
	var lookup map[string]any
	if err := h.pr.RPC(ctx, "lookup_user_bucket_v1", map[string]any{
		"email":  email,
		"domain": domain,
	}, &lookup); err != nil || lookup == nil {
		return "", http.StatusUnauthorized, "no bucket was found"
	}
	name, _ := lookup["bucket_name"].(string)
	if name == "" {
		return "", http.StatusUnauthorized, "no bucket was found"
	}
	return name, 0, ""
}
