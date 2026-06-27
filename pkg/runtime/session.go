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
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
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

// Prepare validates volume ownership, merges configuration, and hydrates addon sessions for /new.
func (b *SessionBuilder) Prepare(ctx context.Context, email string, session *persistent.WorkerSession) (*PrepareResult, error) {
	if session == nil {
		return nil, errVolumeRequired
	}
	volID := PrimaryVolumeID(session)
	if volID == "" {
		return nil, errVolumeRequired
	}
	clusterID, err := cluster.ClusterForVolume(ctx, b.pr, email, volID)
	if err != nil {
		return nil, err
	}
	info, err := cluster.Lookup(ctx, b.pr, clusterID)
	if err != nil {
		return nil, err
	}
	domain := httpx.ClusterHost(info.Domain)

	conf, err := LookupVolumeConfiguration(ctx, b.pr, email, volID)
	if err != nil {
		return nil, err
	}
	volumeconfig.Apply(session, volID, conf, volumeconfig.DefaultVlans)

	b.attachEntitledAddons(ctx, session, email, domain)
	b.attachKeepalive(session)

	volumeIDs, err := b.volumeIDsForCluster(ctx, email, clusterID)
	if err != nil {
		return nil, err
	}

	return &PrepareResult{
		ClusterID: clusterID,
		VolumeIDs: volumeIDs,
		Session:   session,
		Config:    conf,
	}, nil
}

func (b *SessionBuilder) volumeIDsForCluster(ctx context.Context, email string, clusterID int64) ([]string, error) {
	groups, err := cluster.UserVolumeGroups(ctx, b.pr, email)
	if err != nil {
		return nil, err
	}
	return groups[clusterID], nil
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

// PrimaryVolumeID returns the first volume id referenced in a WorkerSession body
// (Vm.Volumes, Ndisks, Ndisk, or Portfw).
func PrimaryVolumeID(session *persistent.WorkerSession) string {
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

