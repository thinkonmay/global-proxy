package persona

import "encoding/json"

type Candidate struct {
	Email    string `json:"email"`
	PBUserID string `json:"pb_user_id"`
}

type PaymentRecord struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	PlanName  string `json:"plan_name"`
	Amount    int    `json:"amount"`
}

type SubscriptionRecord struct {
	PlanName        string  `json:"plan_name"`
	Status          string  `json:"status"`
	AllocatedAt     *string `json:"allocated_at"`
	EndedAt         *string `json:"ended_at"`
	UsageLimit      *int64  `json:"usage_limit"`
	TotalUsage      *int    `json:"total_usage"`
	TotalDataCredit *int    `json:"total_data_credit"`
	AutoRenew       bool    `json:"auto_renew"`
	CancelledAt     *string `json:"cancelled_at"`
}

type EngagementContext struct {
	StarBalance      int64           `json:"star_balance"`
	MissionClaims30d int64           `json:"mission_claims_30d"`
	ReferralsMade    int64           `json:"referrals_made"`
	FeedbackCount    int64           `json:"feedback_count"`
	Feedbacks        FeedbackSummary `json:"feedbacks"`
}

type FeedbackSummary struct {
	Count30d          int64              `json:"count_30d"`
	AvgOverallAllTime *float64           `json:"avg_overall_all_time,omitempty"`
	AvgOverall30d     *float64           `json:"avg_overall_30d,omitempty"`
	AvgDimensions30d  map[string]float64 `json:"avg_dimensions_30d,omitempty"`
	Recent            []FeedbackRecent   `json:"recent"`
}

type FeedbackRecent struct {
	CreatedAt     string   `json:"created_at"`
	OverallRating *float64 `json:"overall_rating,omitempty"`
	Feedback      string   `json:"feedback,omitempty"`
}

type FrontendContext struct {
	Rollup          json.RawMessage `json:"rollup"`
	RecentWebEvents json.RawMessage `json:"recent_web_events"`
}

// CDPSignals is the merged LLM input snapshot stored in events.cdp_profiles (CDP-3).
type CDPSignals struct {
	AppUsageDays  int                   `json:"app_usage_days"`
	AppUsage      []AppUsageEntry       `json:"app_usage"`
	Payments      []PaymentRecord       `json:"payments"`
	Subscriptions []SubscriptionRecord  `json:"subscriptions"`
	Engagement    EngagementContext     `json:"engagement"`
	Frontend      FrontendContext       `json:"frontend"`
}

// AppUsageEntry mirrors usage.AppUsageEntry without importing usage in types.go.
type AppUsageEntry struct {
	AppKey      string  `json:"app_key"`
	DurationSec float64 `json:"duration_sec"`
	LaunchCount uint64  `json:"launch_count"`
}

type Profile struct {
	Objective string `json:"objective"`
	GamerType string `json:"gamer_type"`
	Persona   string `json:"persona"`
}

type AppScore struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

type Summary struct {
	UserBatch          string     `json:"user_batch"`
	UsageHabbit        string     `json:"usage_habbit"`
	Frequency          string     `json:"frequency"`
	RenewalBehavior    string     `json:"renewal_behavior"`
	RenewalProbability string     `json:"renewal_probability"`
	TopApps            []AppScore `json:"top_apps"`
}

type RecommendedGame struct {
	Name   string     `json:"name"`
	Score  float64    `json:"score"`
	ID     int        `json:"id,omitempty"`
	Reason string     `json:"reason,omitempty"`
	Info   *StoreGame `json:"info,omitempty"`
}

type GamePreference struct {
	PlayedGame      string            `json:"played_game"`
	Score           float64           `json:"score"`
	Recommendations []RecommendedGame `json:"recommendations"`
}

type StoreGame struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	CodeName         string   `json:"code_name"`
	ShortDescription string   `json:"short_description"`
	HeaderImage      string   `json:"header_image"`
	Genres           []string `json:"genres"`
	Type             string   `json:"type"`
	Rank             float64  `json:"rank"`
}

type Result struct {
	UsageSummary       Summary          `json:"usage_summary"`
	UserProfile        Profile          `json:"user_profile"`
	UserRecommendation []GamePreference `json:"game_recommendations"`
}
