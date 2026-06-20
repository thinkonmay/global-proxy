package usage

import (
	"context"
	"encoding/json"
)

// MissionRow mirrors get_user_missions_v2 output for progress patching.
type MissionRow struct {
	ID              int     `json:"id"`
	Code            string  `json:"code"`
	Category        string  `json:"category"`
	Type            string  `json:"type"`
	TargetValue     int     `json:"target_value"`
	RewardStars     int     `json:"reward_stars"`
	TitleKey        string  `json:"title_key"`
	DescriptionKey  string  `json:"description_key"`
	Icon            string  `json:"icon"`
	IsRepeatable    bool    `json:"is_repeatable"`
	Progress        int     `json:"progress"`
	Status          string  `json:"status"`
}

// MissionProgressReader supplies usage-driven mission counters from ClickHouse.
type MissionProgressReader interface {
	DailySessionCount(ctx context.Context, email string) (int, error)
	PlayStreak(ctx context.Context, email string) (int, error)
}

// MergeMissionUsageProgress patches DAILY_SESSION and PLAY_STREAK from ClickHouse.
func MergeMissionUsageProgress(ctx context.Context, q MissionProgressReader, email string, raw json.RawMessage) (json.RawMessage, error) {
	if q == nil || len(raw) == 0 {
		return raw, nil
	}
	var rows []MissionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return raw, err
	}
	daily, err := q.DailySessionCount(ctx, email)
	if err != nil {
		return nil, err
	}
	streak, err := q.PlayStreak(ctx, email)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		switch rows[i].Type {
		case "DAILY_SESSION":
			rows[i].Progress = daily
		case "PLAY_STREAK":
			rows[i].Progress = streak
		default:
			continue
		}
		if rows[i].Status == "claimed" {
			continue
		}
		if rows[i].Progress >= rows[i].TargetValue {
			rows[i].Status = "completed"
		} else {
			rows[i].Status = "in_progress"
		}
	}
	out, err := json.Marshal(rows)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UsageRPCEmail extracts the user email from common global_rpc arg shapes.
func UsageRPCEmail(args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var a struct {
		Email       *string `json:"email"`
		PEmail      *string `json:"p_email"`
		TargetEmail *string `json:"target_email"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return ""
	}
	if a.TargetEmail != nil && *a.TargetEmail != "" {
		return *a.TargetEmail
	}
	if a.PEmail != nil && *a.PEmail != "" {
		return *a.PEmail
	}
	if a.Email != nil && *a.Email != "" {
		return *a.Email
	}
	return ""
}

// CHBackedRPCs are served from ClickHouse when a querier is configured.
var CHBackedRPCs = map[string]struct{}{
	"get_user_heatmap":    {},
	"get_data_usage":      {},
	"get_user_missions_v2": {},
}

// IsCHBackedRPC reports whether rpcName should be served from ClickHouse.
func IsCHBackedRPC(rpcName string) bool {
	_, ok := CHBackedRPCs[rpcName]
	return ok
}

// HeatmapJSON encodes heatmap rows for encrypted RPC responses.
func HeatmapJSON(rows []HeatmapEntry) (json.RawMessage, error) {
	type outRow struct {
		UsageDate  string  `json:"usage_date"`
		TotalHours float64 `json:"total_hours"`
	}
	out := make([]outRow, len(rows))
	for i, r := range rows {
		out[i] = outRow{
			UsageDate:  r.UsageDate.Format("2006-01-02"),
			TotalHours: r.TotalHours,
		}
	}
	return json.Marshal(out)
}

// DataUsageJSON encodes data usage rows for encrypted RPC responses.
func DataUsageJSON(rows []DataUsageEntry) (json.RawMessage, error) {
	return json.Marshal(rows)
}
