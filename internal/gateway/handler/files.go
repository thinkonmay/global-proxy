package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const filesTimeout = 120 * time.Second

type FilesHandler struct {
	pr        *postgrest.Client
	storj     *storj.Client
	transport http.RoundTripper
}

func NewFilesHandler(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper) *FilesHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	var st *storj.Client
	if grant := strings.TrimSpace(cfg.Storj.AccessGrant); grant != "" {
		if c, err := storj.New(grant, 24*time.Hour); err == nil {
			st = c
		}
	}
	return &FilesHandler{pr: pr, storj: st, transport: rt}
}

func (h *FilesHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/files/list/{path...}", h.listFiles)
	mux.HandleFunc("GET /v1/files/{path...}", h.downloadFile)
	mux.HandleFunc("PUT /v1/files/{path...}", h.uploadFile)

	// Legacy pb-proxy aliases (files only; snapshots stay on node proxy).
	mux.HandleFunc("GET /v1/pb-proxy/files/v1/{path...}", h.listFilesLegacy)
	mux.HandleFunc("GET /v1/pb-proxy/file/v1/{path...}", h.downloadFileLegacy)
	mux.HandleFunc("GET /v1/internal/sync-bucket-size", h.SyncBucketSize)
	mux.HandleFunc("POST /v1/internal/increment-app-access-usage", h.IncrementAppAccessUsage)
	mux.HandleFunc("POST /v1/internal/increment-llm-usage", h.IncrementLLMUsage)
	mux.HandleFunc("GET /v1/internal/lookup-app-access", h.LookupAppAccess)
}

func (h *FilesHandler) listFiles(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/list/")
	h.serveList(w, r, path)
}

func (h *FilesHandler) listFilesLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/files/v1/")
	h.serveList(w, r, path)
}

func (h *FilesHandler) downloadFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/")
	if strings.HasPrefix(path, "list/") {
		http.NotFound(w, r)
		return
	}
	h.serveDownload(w, r, path)
}

func (h *FilesHandler) downloadFileLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/file/v1/")
	h.serveDownload(w, r, path)
}

func (h *FilesHandler) uploadFile(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/files/")
	if strings.HasPrefix(path, "list/") {
		http.NotFound(w, r)
		return
	}
	h.serveUpload(w, r, path)
}

func (h *FilesHandler) uploadFileLegacy(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pb-proxy/file/v1/")
	h.serveUpload(w, r, path)
}

func (h *FilesHandler) serveList(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if h.storj == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storj not configured"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), filesTimeout)
	defer cancel()
	objs, err := h.storj.ListObjects(bucket, path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list objects"})
		return
	}
	_ = ctx
	writeJSON(w, http.StatusOK, objs)
}

func (h *FilesHandler) serveDownload(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if h.storj == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storj not configured"})
		return
	}
	url, err := h.storj.DownloadableURL(bucket, path, 15*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate download url"})
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *FilesHandler) serveUpload(w http.ResponseWriter, r *http.Request, path string) {
	bucket, code, msg := h.resolveBucket(r)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if h.storj == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storj not configured"})
		return
	}
	url, err := h.storj.UploadableURL(bucket, path, 15*time.Minute)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate upload url"})
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (h *FilesHandler) resolveBucket(r *http.Request) (string, int, string) {
	cluster := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if cluster == "" {
		return "", http.StatusBadRequest, "cluster query required"
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", http.StatusUnauthorized, "authorization required"
	}
	base := clusterBaseURL(cluster)
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	email, err := pbUserAuth.UserEmail(ctx, base, authHeader, h.transport)
	if err != nil {
		return "", http.StatusUnauthorized, "invalid auth"
	}
	var lookup map[string]any
	if err := h.pr.RPC(ctx, "lookup_user_bucket_v1", map[string]any{
		"email":  email,
		"domain": clusterHost(cluster),
	}, &lookup); err != nil || lookup == nil {
		return "", http.StatusUnauthorized, "no bucket was found"
	}
	name, _ := lookup["bucket_name"].(string)
	if name == "" {
		return "", http.StatusUnauthorized, "no bucket was found"
	}
	return name, 0, ""
}

func clusterHost(cluster string) string {
	cluster = strings.TrimSpace(cluster)
	cluster = strings.TrimPrefix(cluster, "https://")
	cluster = strings.TrimPrefix(cluster, "http://")
	return strings.TrimRight(cluster, "/")
}

// SyncBucketSize updates global bucket size after a node session ends.
func (h *FilesHandler) SyncBucketSize(w http.ResponseWriter, r *http.Request) {
	if h.storj == nil || h.pr == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storj unavailable"})
		return
	}
	email := r.URL.Query().Get("email")
	cluster := clusterHost(r.URL.Query().Get("cluster"))
	bucket := strings.TrimSpace(r.URL.Query().Get("bucket_name"))
	if email == "" || cluster == "" || bucket == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email, cluster, bucket_name required"})
		return
	}
	size, err := h.storj.BucketSize(bucket)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stat bucket failed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "sync_user_bucket_size_v1", map[string]any{
		"email":          email,
		"domain":         cluster,
		"new_size_bytes": size,
	}, nil); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sync failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// IncrementAppAccessUsage bumps global app_access usage after a node session ends.
func (h *FilesHandler) IncrementAppAccessUsage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := clusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "increment_user_app_access_usage_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, nil); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "increment failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// IncrementLLMUsage bumps global LLM addon usage (node calls via gateway, not Postgres HTTP).
func (h *FilesHandler) IncrementLLMUsage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := clusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "increment_user_llm_usage_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, nil); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "increment failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LookupUserAppAccess returns app_id for node /new hydration.
func (h *FilesHandler) LookupAppAccess(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := clusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	var lookup map[string]any
	if err := h.pr.RPC(ctx, "lookup_user_app_access_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, &lookup); err != nil || lookup == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, lookup)
}
