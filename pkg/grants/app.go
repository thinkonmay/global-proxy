package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// AppClaim is the Steam/app credential row returned by claim_v1.
type AppClaim struct {
	AppID       string
	Username    string
	Password    string
	KeepaliveID int32
	DepotKey    map[string]string
}

// LookupUserAppAccess reads infra.user_app_access for the user/cluster.
func LookupUserAppAccess(ctx context.Context, pr *postgrest.Client, email, domain string) (string, error) {
	var lookup map[string]any
	if err := pr.RPC(ctx, "lookup_user_app_access_v1", map[string]any{
		"email":  email,
		"domain": domain,
	}, &lookup); err != nil {
		return "", err
	}
	if lookup == nil {
		return "", nil
	}
	appID, _ := lookup["app_id"].(string)
	return strings.TrimSpace(appID), nil
}

// ClaimApp claims a runtime lease via claim_v1 for an existing app entitlement.
func ClaimApp(ctx context.Context, pr *postgrest.Client, email, appID string) (*AppClaim, error) {
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, fmt.Errorf("empty app_id")
	}
	var rows []struct {
		ID       int32             `json:"id"`
		Username string            `json:"username"`
		Password string            `json:"password"`
		DepotKey map[string]string `json:"depotKey"`
	}
	if err := pr.RPC(ctx, "claim_v1", map[string]any{
		"app_id": appID,
		"email":  email,
	}, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty claim for app %s", appID)
	}
	row := rows[0]
	if row.DepotKey == nil {
		row.DepotKey = map[string]string{}
	}
	return &AppClaim{
		AppID:       appID,
		Username:    row.Username,
		Password:    row.Password,
		KeepaliveID: row.ID,
		DepotKey:    row.DepotKey,
	}, nil
}

// GrantAndClaimApp ensures user_app_access then claims a runtime lease via claim_v1.
func GrantAndClaimApp(ctx context.Context, pr *postgrest.Client, email, domain, appID string) (*AppClaim, error) {
	args := map[string]any{"email": email, "domain": domain}
	if strings.TrimSpace(appID) != "" {
		args["app_id"] = appID
	}
	var grant map[string]any
	if err := pr.RPC(ctx, "grant_app_access_v1", args, &grant); err != nil {
		return nil, err
	}
	claimedAppID := strings.TrimSpace(appID)
	if v, ok := grant["app_id"].(string); ok && strings.TrimSpace(v) != "" {
		claimedAppID = strings.TrimSpace(v)
	}
	if claimedAppID == "" {
		claimedAppID = "unknown"
	}
	return ClaimApp(ctx, pr, email, claimedAppID)
}

// AppClaimFromRows parses a raw PostgREST claim_v1 payload.
func AppClaimFromRows(raw json.RawMessage) (*AppClaim, error) {
	var rows []struct {
		ID       int32             `json:"id"`
		Username string            `json:"username"`
		Password string            `json:"password"`
		DepotKey map[string]string `json:"depotKey"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty claim result")
	}
	row := rows[0]
	if row.DepotKey == nil {
		row.DepotKey = map[string]string{}
	}
	return &AppClaim{
		Username:    row.Username,
		Password:    row.Password,
		KeepaliveID: row.ID,
		DepotKey:    row.DepotKey,
	}, nil
}
