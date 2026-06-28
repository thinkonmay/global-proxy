package persona

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
