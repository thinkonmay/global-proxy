package runtime

import (
	"context"
	"log/slog"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/grants"
)

// attachEntitledAddons mirrors PB addStorageSession + addAppSession on /new (fail-open).
func (b *SessionBuilder) attachEntitledAddons(ctx context.Context, session *persistent.WorkerSession, email, domain string) {
	b.tryAttachBucketSession(ctx, session, email, domain)
	b.tryAttachAppSession(ctx, session, email, domain)
}

func (b *SessionBuilder) tryAttachBucketSession(ctx context.Context, session *persistent.WorkerSession, email, domain string) {
	ctx, cancel := context.WithTimeout(ctx, grantTimeout)
	defer cancel()
	var lookup map[string]any
	if err := b.pr.RPC(ctx, "lookup_user_bucket_v1", map[string]any{
		"email":  email,
		"domain": domain,
	}, &lookup); err != nil {
		return
	}
	name, _ := lookup["bucket_name"].(string)
	if name == "" {
		return
	}
	if session.S3Bucket == nil {
		session.S3Bucket = &persistent.S3Bucket{}
	}
	b.attachStorageGrant(ctx, session, email, domain)
}

func (b *SessionBuilder) tryAttachAppSession(ctx context.Context, session *persistent.WorkerSession, email, domain string) {
	ctx, cancel := context.WithTimeout(ctx, grantTimeout)
	defer cancel()
	claim, err := grants.GrantAndClaimApp(ctx, b.pr, email, domain, "")
	if err != nil {
		slog.Warn("app session failed (fail-open)", "err", err)
		return
	}
	if claim.AppID == "" || claim.AppID == "unknown" {
		return
	}
	if session.App == nil {
		session.App = &persistent.AppSession{Type: "steam"}
	}
	session.App.Appid = claim.AppID
	session.App.Username = claim.Username
	session.App.Credential = claim.Password
	session.App.Depotkey = claim.DepotKey
	if session.App.Keepalive == nil {
		session.App.Keepalive = &persistent.Keepalive{}
	}
	if claim.KeepaliveID > 0 {
		session.App.Keepalive.KeepaliveID = claim.KeepaliveID
	}
}
