package grants

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

// GrantBucketAccess ensures infra.user_bucket, creates the Storj bucket, and
// mints VM credentials when a Storj client is configured.
func GrantBucketAccess(ctx context.Context, pr *postgrest.Client, st *storj.Client, email, domain string) (map[string]any, error) {
	var cred map[string]any
	if err := pr.RPC(ctx, "grant_bucket_access_v1", map[string]any{
		"email":  email,
		"domain": domain,
	}, &cred); err != nil {
		return nil, err
	}
	name, _ := cred["bucket_name"].(string)
	if name == "" || st == nil {
		return cred, nil
	}
	if err := st.CreateBucket(name); err != nil {
		return cred, err
	}
	minted, err := st.GrantBucketCredential(name)
	if err != nil {
		return cred, err
	}
	cred["access_id"] = minted.AccessID
	cred["access_key"] = minted.AccessKey
	cred["endpoint"] = minted.Endpoint
	cred["token"] = minted.Token
	return cred, nil
}
