package runtime

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/grants"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const grantTimeout = 2 * time.Second

// SessionBuilder enriches client WorkerSession intent with grants and keepalive (D24/D25).
type SessionBuilder struct {
	pr        *postgrest.Client
	publicURL string
	storj     *storj.Client
}

// NewSessionBuilder creates a session builder.
func NewSessionBuilder(pr *postgrest.Client, publicURL string, st *storj.Client) *SessionBuilder {
	return &SessionBuilder{
		pr:        pr,
		publicURL: strings.TrimRight(strings.TrimSpace(publicURL), "/"),
		storj:     st,
	}
}

// Prepare validates volume ownership and hydrates storage/app sessions for /new.
func (b *SessionBuilder) Prepare(ctx context.Context, email string, session *persistent.WorkerSession) (clusterID int64, err error) {
	if session == nil {
		return 0, errVolumeRequired
	}
	volID := primaryVolumeID(session)
	if volID == "" {
		return 0, errVolumeRequired
	}
	clusterID, err = cluster.ClusterForVolume(ctx, b.pr, email, volID)
	if err != nil {
		return 0, err
	}
	info, err := cluster.Lookup(ctx, b.pr, clusterID)
	if err != nil {
		return 0, err
	}
	domain := httpx.ClusterHost(info.Domain)

	b.attachKeepalive(session)
	b.attachStorageGrant(ctx, session, email, domain)
	b.attachAppGrant(ctx, session, email, domain)
	return clusterID, nil
}

func (b *SessionBuilder) attachStorageGrant(ctx context.Context, session *persistent.WorkerSession, email, domain string) {
	if session.S3Bucket == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, grantTimeout)
	defer cancel()
	cred, err := grants.GrantBucketAccess(ctx, b.pr, b.storj, email, domain)
	if err != nil {
		slog.Warn("storage grant failed (fail-open)", "err", err)
		return
	}
	if name, ok := cred["bucket_name"].(string); ok {
		session.S3Bucket.Bucket = name
	}
	if id, ok := cred["access_id"].(string); ok {
		session.S3Bucket.AccessId = id
	}
	if key, ok := cred["access_key"].(string); ok {
		session.S3Bucket.AccessKey = key
	}
	if endpoint, ok := cred["endpoint"].(string); ok {
		session.S3Bucket.Endpoint = endpoint
	}
	if token, ok := cred["token"].(string); ok {
		session.S3Bucket.Token = token
	}
}

func (b *SessionBuilder) attachAppGrant(ctx context.Context, session *persistent.WorkerSession, email, domain string) {
	if session.App == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, grantTimeout)
	defer cancel()
	claim, err := grants.GrantAndClaimApp(ctx, b.pr, email, domain, session.App.Appid)
	if err != nil {
		slog.Warn("app grant failed (fail-open)", "err", err)
		return
	}
	if claim.AppID != "" {
		session.App.Appid = claim.AppID
	}
	session.App.Username = claim.Username
	session.App.Credential = claim.Password
	session.App.Depotkey = claim.DepotKey
	if session.App.Keepalive != nil && claim.KeepaliveID > 0 {
		session.App.Keepalive.KeepaliveID = claim.KeepaliveID
	}
}

func (b *SessionBuilder) attachKeepalive(session *persistent.WorkerSession) {
	base := b.publicURL
	if base == "" {
		base = "https://thinkmay.net"
	}
	url := base + "/v1/runtime/keepalive"
	if session.S3Bucket != nil {
		session.S3Bucket.Keepalive = &persistent.Keepalive{
			KeepaliveUrl:        url,
			KeepaliveCredential: uuid.NewString(),
			KeepaliveID:         0,
		}
	}
	if session.App != nil {
		session.App.Keepalive = &persistent.Keepalive{
			KeepaliveUrl:        url,
			KeepaliveCredential: uuid.NewString(),
			KeepaliveID:         0,
		}
	}
}

func primaryVolumeID(session *persistent.WorkerSession) string {
	if session.Vm != nil {
		for _, v := range session.Vm.Volumes {
			if v != nil && strings.TrimSpace(v.Name) != "" {
				return strings.TrimSpace(v.Name)
			}
		}
		for _, nd := range session.Vm.Ndisks {
			if nd != nil && nd.Volume != nil && strings.TrimSpace(nd.Volume.Name) != "" {
				return strings.TrimSpace(nd.Volume.Name)
			}
		}
	}
	if session.Ndisk != nil && session.Ndisk.Volume != nil {
		return strings.TrimSpace(session.Ndisk.Volume.Name)
	}
	for _, pf := range session.Portfw {
		if strings.TrimSpace(pf.VolumeID) != "" {
			return strings.TrimSpace(pf.VolumeID)
		}
	}
	return ""
}

var errVolumeRequired = errString("volume required in session")

type errString string

func (e errString) Error() string { return string(e) }

// VolumeFromCloseRequest extracts a volume id from a close/restart session body.
func VolumeFromCloseRequest(session *persistent.WorkerSession) string {
	return primaryVolumeID(session)
}
