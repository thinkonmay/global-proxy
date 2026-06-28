package persona

import (
	"context"
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

const defaultMaxAppUsageItems = 30

func trimAppUsage(apps []usage.AppUsageEntry, maxItems int) []usage.AppUsageEntry {
	if maxItems <= 0 {
		maxItems = defaultMaxAppUsageItems
	}
	if len(apps) <= maxItems {
		return apps
	}
	return apps[:maxItems]
}

func toAppUsageEntries(apps []usage.AppUsageEntry) []AppUsageEntry {
	out := make([]AppUsageEntry, len(apps))
	for i, a := range apps {
		out[i] = AppUsageEntry{
			AppKey:      a.AppKey,
			DurationSec: a.DurationSec,
			LaunchCount: a.LaunchCount,
		}
	}
	return out
}

func buildCDPSignals(days int, apps []usage.AppUsageEntry, payments []PaymentRecord, subs []SubscriptionRecord, engagement EngagementContext, frontend FrontendContext) CDPSignals {
	if payments == nil {
		payments = []PaymentRecord{}
	}
	if subs == nil {
		subs = []SubscriptionRecord{}
	}
	if engagement.Feedbacks.Recent == nil {
		engagement.Feedbacks.Recent = []FeedbackRecent{}
	}
	if frontend.Rollup == nil {
		frontend.Rollup = json.RawMessage("{}")
	}
	if frontend.RecentWebEvents == nil {
		frontend.RecentWebEvents = json.RawMessage("[]")
	}
	return CDPSignals{
		AppUsageDays:  days,
		AppUsage:      toAppUsageEntries(apps),
		Payments:      payments,
		Subscriptions: subs,
		Engagement:    engagement,
		Frontend:      frontend,
	}
}

func fetchSubscriptionContext(ctx context.Context, pr *postgrest.Client, email string) []SubscriptionRecord {
	var raw json.RawMessage
	if err := pr.RPC(ctx, "get_cdp_subscription_context", map[string]any{"email": email}, &raw); err != nil {
		return nil
	}
	var out []SubscriptionRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func fetchEngagementContext(ctx context.Context, pr *postgrest.Client, email string) EngagementContext {
	empty := EngagementContext{Feedbacks: FeedbackSummary{Recent: []FeedbackRecent{}}}
	var raw json.RawMessage
	if err := pr.RPC(ctx, "get_cdp_engagement_context", map[string]any{"email": email}, &raw); err != nil {
		return empty
	}
	var out EngagementContext
	if err := json.Unmarshal(raw, &out); err != nil {
		return empty
	}
	if out.Feedbacks.Recent == nil {
		out.Feedbacks.Recent = []FeedbackRecent{}
	}
	return out
}

func fetchFrontendContext(ctx context.Context, pr *postgrest.Client, email string) FrontendContext {
	var raw json.RawMessage
	if err := pr.RPC(ctx, "get_cdp_frontend_context", map[string]any{"email": email}, &raw); err != nil {
		return FrontendContext{
			Rollup:          json.RawMessage("{}"),
			RecentWebEvents: json.RawMessage("[]"),
		}
	}
	var out FrontendContext
	if err := json.Unmarshal(raw, &out); err != nil {
		return FrontendContext{
			Rollup:          json.RawMessage("{}"),
			RecentWebEvents: json.RawMessage("[]"),
		}
	}
	if out.Rollup == nil {
		out.Rollup = json.RawMessage("{}")
	}
	if out.RecentWebEvents == nil {
		out.RecentWebEvents = json.RawMessage("[]")
	}
	return out
}
