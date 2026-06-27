package runtime

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/daemonclient"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	runtimepkg "github.com/thinkonmay/global-proxy/api/pkg/runtime"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/workerinfor"
)

const (
	infoTimeout    = 20 * time.Second
	runtimeTimeout = 120 * time.Second
)

// Config configures the runtime handler (Track C3).
type Config struct {
	PublicURL string
	Transport http.RoundTripper
	Daemon    *daemonclient.Client
	PostgREST *postgrest.Client
}

// Handler serves node runtime REST at /v1/runtime/* via virtdaemon gRPC only (D25).
type Handler struct {
	cfg      Config
	tickets  *runtimepkg.Tickets
	sessions *runtimepkg.SessionBuilder
}

// New constructs a runtime handler.
func New(cfg Config) *Handler {
	return &Handler{
		cfg:      cfg,
		tickets:  runtimepkg.NewTickets(),
		sessions: runtimepkg.NewSessionBuilder(cfg.PostgREST, cfg.PublicURL),
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.Handle(http.MethodGet, "/runtime/info", h.handleInfo)
	v1.Handle(http.MethodGet, "/runtime/info/sse", h.handleInfoSSE)
	v1.Handle(http.MethodPost, "/runtime/new", h.handleNew)
	v1.Handle(http.MethodGet, "/runtime/new/sse", h.handleNewSSE)
	v1.Handle(http.MethodDelete, "/runtime/close", h.handleClose)
	v1.Handle(http.MethodPost, "/runtime/restart", h.handleRestart)
	v1.Handle(http.MethodPost, "/runtime/reallocate", h.handleReallocate)
	v1.Handle(http.MethodGet, "/runtime/reallocate/sse", h.handleReallocateSSE)
	v1.Handle(http.MethodPost, "/runtime/template", h.handleTemplate)
	v1.Handle(http.MethodGet, "/runtime/template/sse", h.handleTemplateSSE)
	v1.Handle(http.MethodPost, "/runtime/resize", h.notImplemented)
	v1.Handle(http.MethodPost, "/runtime/assistant", h.notImplemented)
	v1.Handle(http.MethodGet, "/runtime/snapshots", h.handleListSnapshots)
	v1.Handle(http.MethodPost, "/runtime/snapshots", h.handleConfigureSnapshots)
	v1.Handle(http.MethodPost, "/runtime/snapshots/restore", h.handleRestoreSnapshot)
	v1.Handle(http.MethodPost, "/runtime/keepalive", h.handleKeepalive)
	v1.Handle(http.MethodDelete, "/runtime/resource", h.handleResource)
	v1.Handle(http.MethodGet, "/runtime/log", h.notImplemented)
	v1.Handle(http.MethodGet, "/runtime/analytics", h.notImplemented)
}

func (h *Handler) requireDaemon(w http.ResponseWriter) bool {
	if h.cfg.Daemon == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "runtime gRPC unavailable")
		return false
	}
	return true
}

func (h *Handler) requireUser(w http.ResponseWriter, r *http.Request) (email string, ok bool) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.cfg.Transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
	}
	return email, ok
}

func (h *Handler) notImplemented(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteError(w, http.StatusNotImplemented, "not implemented on gRPC runtime edge")
}

func (h *Handler) handleInfo(w http.ResponseWriter, r *http.Request) {
	// Cluster destination is resolved from Postgres (user_v2); ?cluster= is ignored.
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), infoTimeout)
	defer cancel()
	info, err := h.cfg.Daemon.InfoForUser(ctx, email)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "daemon info unavailable")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, info)
}

func (h *Handler) handleInfoSSE(w http.ResponseWriter, r *http.Request) {
	// Fans out InfoStream across all clusters in user_v2; ?cluster= is ignored.
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if err := h.cfg.Daemon.RelayInfoStream(ctx, w, email); err != nil && ctx.Err() == nil {
		httpx.WriteError(w, http.StatusBadGateway, "info stream unavailable")
	}
}

func (h *Handler) handleNew(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var session persistent.WorkerSession
	if err := httpx.ReadJSONBody(r, &session); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	clusterID, err := h.sessions.Prepare(ctx, email, &session)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	id := h.tickets.IssueNew(clusterID, &session)
	httpx.WriteJSON(w, http.StatusOK, id)
}

func (h *Handler) handleNewSSE(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	sid := strings.TrimSpace(r.URL.Query().Get("id"))
	if sid == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	ticket, ok := h.tickets.TakeNew(sid)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer h.tickets.FinishNew(sid)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := h.cfg.Daemon.NewStream(ctx, ticket.ClusterID, ticket.Session)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "new stream unavailable")
		return
	}
	_ = daemonclient.RelayNewStream(ctx, w, stream)
}

func (h *Handler) handleClose(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var session persistent.WorkerSession
	if err := httpx.ReadJSONBody(r, &session); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	clusterID, err := h.resolveCluster(r.Context(), email, runtimepkg.VolumeFromCloseRequest(&session))
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	info, err := h.cfg.Daemon.CloseSession(ctx, clusterID, &session)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "failed to close session")
		return
	}
	vols, _ := cluster.UserVolumeGroups(ctx, h.cfg.PostgREST, email)
	filtered := workerinfor.Filter(info, vols[clusterID])
	httpx.WriteJSON(w, http.StatusOK, filtered)
}

func (h *Handler) handleRestart(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var session persistent.WorkerSession
	if err := httpx.ReadJSONBody(r, &session); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	clusterID, err := h.resolveCluster(r.Context(), email, runtimepkg.VolumeFromCloseRequest(&session))
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	if err := h.cfg.Daemon.RestartSession(ctx, clusterID, &session); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "failed to restart session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleReallocate(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	if err := httpx.ReadJSONBody(r, &body); err != nil || body.ID == "" || body.Source == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id and source required")
		return
	}
	clusterID, err := cluster.ClusterForVolume(r.Context(), h.cfg.PostgREST, email, body.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	info, err := h.cfg.Daemon.InfoCluster(ctx, clusterID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster info unavailable")
		return
	}
	req, err := daemonclient.BuildReallocateRequest(info, body.ID, body.Source)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := h.tickets.IssueAlloc(clusterID, req)
	httpx.WriteJSON(w, http.StatusOK, id)
}

func (h *Handler) handleReallocateSSE(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	sid := strings.TrimSpace(r.URL.Query().Get("id"))
	if sid == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	ticket, ok := h.tickets.TakeAlloc(sid)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer h.tickets.FinishAlloc(sid)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stream, err := h.cfg.Daemon.AllocateStream(ctx, ticket.ClusterID, ticket.Request)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "allocate stream unavailable")
		return
	}
	_ = daemonclient.RelayAllocateStream(ctx, w, stream)
}

func (h *Handler) handleTemplate(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		ID           string `json:"id"`
		TemplateName string `json:"template_name"`
	}
	if err := httpx.ReadJSONBody(r, &body); err != nil || body.ID == "" || body.TemplateName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id and template_name required")
		return
	}
	clusterID, err := cluster.ClusterForVolume(r.Context(), h.cfg.PostgREST, email, body.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	info, err := h.cfg.Daemon.InfoCluster(ctx, clusterID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster info unavailable")
		return
	}
	rename, allocate, err := daemonclient.BuildTemplateRequest(info, body.ID, body.TemplateName)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	id := h.tickets.IssueTemplate(clusterID, rename, allocate)
	httpx.WriteJSON(w, http.StatusOK, id)
}

func (h *Handler) handleTemplateSSE(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	sid := strings.TrimSpace(r.URL.Query().Get("id"))
	if sid == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	ticket, ok := h.tickets.TakeTemplate(sid)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	defer h.tickets.FinishTemplate(sid)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	_ = daemonclient.RelayTemplateStream(ctx, w, h.cfg.Daemon, ticket.ClusterID, ticket.Rename, ticket.Allocate)
}

func (h *Handler) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	volID := strings.TrimSpace(r.URL.Query().Get("id"))
	if volID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	clusterID, err := cluster.ClusterForVolume(r.Context(), h.cfg.PostgREST, email, volID)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	res, err := h.cfg.Daemon.ListSnapshots(ctx, clusterID, volID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "list snapshots failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Snapshots)
}

func (h *Handler) handleConfigureSnapshots(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := httpx.ReadJSONBody(r, &body); err != nil {
		_ = r.URL.Query().Get("id")
	}
	volID := strings.TrimSpace(body.ID)
	if volID == "" {
		volID = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if volID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	clusterID, err := cluster.ClusterForVolume(r.Context(), h.cfg.PostgREST, email, volID)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	if err := h.cfg.Daemon.SnapshotVolume(ctx, clusterID, volID); err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "snapshot configure failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	if !h.requireDaemon(w) {
		return
	}
	email, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	var body struct {
		ID           string `json:"id"`
		SnapshotName string `json:"snapshot_name"`
	}
	if err := httpx.ReadJSONBody(r, &body); err != nil || body.ID == "" || body.SnapshotName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id and snapshot_name required")
		return
	}
	clusterID, err := cluster.ClusterForVolume(r.Context(), h.cfg.PostgREST, email, body.ID)
	if err != nil {
		httpx.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), runtimeTimeout)
	defer cancel()
	if err := h.cfg.Daemon.RestoreSnapshot(ctx, clusterID, body.ID, body.SnapshotName); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "restore failed")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleKeepalive(w http.ResponseWriter, r *http.Request) {
	kaid := strings.TrimSpace(r.URL.Query().Get("id"))
	if kaid == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	n, err := strconv.ParseInt(kaid, 10, 32)
	if err != nil || n <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}
	id := int32(n)
	if h.cfg.PostgREST == nil {
		httpx.WriteJSON(w, http.StatusOK, false)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var alive bool
	if err := h.cfg.PostgREST.RPC(ctx, "keepalive_v1", map[string]any{"id": id}, &alive); err != nil {
		httpx.WriteJSON(w, http.StatusOK, true)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, !alive)
}

func (h *Handler) handleResource(w http.ResponseWriter, r *http.Request) {
	// Addon session leases are global (Postgres); clearing is a no-op at the gRPC edge.
	_, ok := h.requireUser(w, r)
	if !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resolveCluster(ctx context.Context, email, volumeID string) (int64, error) {
	if strings.TrimSpace(volumeID) != "" {
		return cluster.ClusterForVolume(ctx, h.cfg.PostgREST, email, volumeID)
	}
	return cluster.PrimaryCluster(ctx, h.cfg.PostgREST, email)
}
