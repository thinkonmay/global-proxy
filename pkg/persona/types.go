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

type Profile struct {
	Objective string `json:"objective"`
	GamerType string `json:"gamer_type"`
	Persona   string `json:"persona"`
}

type Summary struct {
	UserBatch          string          `json:"user_batch"`
	UsageHabbit        string          `json:"usage_habbit"`
	Frequency          string          `json:"frequency"`
	RenewalBehavior    string          `json:"renewal_behavior"`
	RenewalProbability string          `json:"renewal_probability"`
	TopApps            json.RawMessage `json:"top_apps"`
}

type GamePreference struct {
	PlayedGame      string          `json:"played_game"`
	Score           float64         `json:"score"`
	Recommendations json.RawMessage `json:"recommendations"`
}

type Result struct {
	UsageSummary       Summary          `json:"usage_summary"`
	UserProfile        Profile          `json:"user_profile"`
	UserRecommendation []GamePreference `json:"game_recommendations"`
}
