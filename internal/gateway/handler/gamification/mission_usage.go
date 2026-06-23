package gamification

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

func userMissionsV2(ctx context.Context, pr *postgrest.Client, usageQ *usage.Querier, email string) (json.RawMessage, error) {
	args := map[string]any{"p_email": email}
	if usageQ == nil {
		var raw json.RawMessage
		if err := pr.RPC(ctx, "get_user_missions_v2", args, &raw); err != nil {
			return nil, err
		}
		return raw, nil
	}
	var raw json.RawMessage
	if err := pr.RPC(ctx, "get_user_missions_v2", args, &raw); err != nil {
		return nil, err
	}
	return usage.MergeMissionUsageProgress(ctx, usageQ, email, raw)
}

func userHeatmap(ctx context.Context, usageQ *usage.Querier, email string) (json.RawMessage, error) {
	if usageQ == nil {
		return nil, errors.New("usage store unavailable")
	}
	rows, err := usageQ.Heatmap(ctx, email, 365)
	if err != nil {
		return nil, err
	}
	return usage.HeatmapJSON(rows)
}

func claimMission(ctx context.Context, pr *postgrest.Client, usageQ *usage.Querier, email, missionCode string) (bool, error) {
	args := map[string]any{
		"p_email":        email,
		"p_mission_code": missionCode,
	}
	if usageQ == nil {
		var out bool
		if err := pr.RPC(ctx, "claim_mission_v2", args, &out); err != nil {
			return false, err
		}
		return out, nil
	}

	type missionTypeRow struct {
		Type string `json:"type"`
	}
	var missions []missionTypeRow
	q := url.Values{}
	q.Set("select", "type")
	q.Set("code", "eq."+missionCode)
	q.Set("limit", "1")
	if err := pr.Select(ctx, "missions", q, &missions); err != nil {
		return false, err
	}
	if len(missions) == 0 {
		var out bool
		if err := pr.RPC(ctx, "claim_mission_v2", args, &out); err != nil {
			return false, err
		}
		return out, nil
	}

	switch missions[0].Type {
	case "DAILY_SESSION", "PLAY_STREAK":
		var progress int
		var err error
		if missions[0].Type == "DAILY_SESSION" {
			progress, err = usageQ.DailySessionCount(ctx, email)
		} else {
			progress, err = usageQ.PlayStreak(ctx, email)
		}
		if err != nil {
			return false, err
		}
		var out bool
		if err := pr.RPC(ctx, "claim_mission_gateway_v2", map[string]any{
			"p_email":        email,
			"p_mission_code": missionCode,
			"p_progress":     progress,
		}, &out); err != nil {
			return false, err
		}
		return out, nil
	default:
		var out bool
		if err := pr.RPC(ctx, "claim_mission_v2", args, &out); err != nil {
			return false, err
		}
		return out, nil
	}
}
