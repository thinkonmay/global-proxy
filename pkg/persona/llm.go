package persona

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/llmtrace"
)

const analystSystemPrompt = `You are a Senior User Behavior Analyst for Thinkmay CloudPC, a high-performance cloud gaming service.
Analyze VM app usage rollups, payment history, active subscriptions, and product engagement signals.
Return a deep behavioral profile with Steam-oriented game recommendations.

App usage fields (platform ClickHouse rollups):
- app_key: normalized process or game slug (game:* for Steam titles)
- duration_sec: dwell time in the VM over the lookback window
- launch_count: how often the app was started

Subscription fields (Postgres billing snapshot):
- plan_name, status, usage_limit, total_usage, total_data_credit, auto_renew, allocated_at, ended_at

Engagement fields (Postgres gamification + support):
- star_balance, mission_claims_30d, referrals_made, feedback_count
- feedbacks.count_30d, avg_overall_all_time, avg_overall_30d
- feedbacks.avg_dimensions_30d: latency, image_quality, easy_to_control, stability, uiux, overall_rating (1-6 scale)
- feedbacks.recent: up to 3 latest submissions with overall_rating and short feedback text

Frontend fields (web analytics ETL + gateway product events in Postgres):
- rollup.pageviews, rollup.sessions, rollup.top_paths, rollup.top_events
- recent_web_events: high-intent product events (store, checkout) from source=web

Plan policies:
- hour1: trial for new users (~3 hours, no date limit)
- month1: 30 days, 120 hours, RTX 3060 Ti class
- month2: 30 days, 360 hours, RTX 5060 Ti class
- month3: 30 days, unlimited hours

Instructions:
1. Focus on games and high-intent apps; ignore system noise already filtered upstream.
2. Infer usage frequency, peak hours, and renewal likelihood from payments, subscription usage, and web funnel signals.
3. Weight engagement (missions, referrals, feedback) and frontend store/checkout activity when estimating churn vs loyalty.
4. For each played game, recommend up to 6 similar Steam-available titles with scores 0.0–1.0.
5. Recommendations must be real Steam game titles, not generic genres.`

type LLMConfig struct {
	BaseURL string
	APIKey  string
	Model   string
	HTTP    *http.Client
}

type synthesizer struct {
	cfg LLMConfig
}

func newSynthesizer(cfg LLMConfig) *synthesizer {
	if cfg.Model == "" {
		cfg.Model = "deepseek-v4-flash"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 180 * time.Second}
	}
	return &synthesizer{cfg: cfg}
}

func (s *synthesizer) Synthesize(ctx context.Context, signals CDPSignals) (*Result, error) {
	llmtrace.LogFeatureStart(llmtrace.FeaturePersonaCDP,
		"app_usage_items", len(signals.AppUsage),
		"payments", len(signals.Payments),
		"subscriptions", len(signals.Subscriptions),
	)

	signalsRaw, err := json.Marshal(signals)
	if err != nil {
		return nil, err
	}
	schemaJSON, err := json.Marshal(personaResponseSchema())
	if err != nil {
		return nil, err
	}
	userPrompt := fmt.Sprintf(`Current timestamp: %s
CDP signals (JSON — app usage, payments, subscriptions, engagement, frontend web):
%s
Return JSON matching this schema:
%s`,
		time.Now().Format(time.DateTime),
		string(signalsRaw),
		string(schemaJSON),
	)

	body := map[string]any{
		"model": s.cfg.Model,
		"messages": []map[string]any{
			{"role": "system", "content": analystSystemPrompt},
			{"role": "user", "content": userPrompt},
		},
		// deepseek-v4-flash supports json_object but not json_schema.
		"response_format": map[string]any{"type": "json_object"},
	}
	raw, err := s.postChat(ctx, body)
	if err != nil {
		llmtrace.LogFeatureError(llmtrace.FeaturePersonaCDP, err)
		return nil, err
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content          *string `json:"content"`
				ReasoningContent *string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &completion); err != nil {
		llmtrace.LogParseError(llmtrace.FeaturePersonaCDP, 0, err, raw)
		return nil, err
	}
	if len(completion.Choices) == 0 {
		err := fmt.Errorf("empty llm response")
		llmtrace.LogFeatureError(llmtrace.FeaturePersonaCDP, err)
		return nil, err
	}
	text := personaAssistantText(completion.Choices[0].Message.Content, completion.Choices[0].Message.ReasoningContent)
	if text == "" {
		err := fmt.Errorf("empty llm response")
		llmtrace.LogFeatureError(llmtrace.FeaturePersonaCDP, err)
		return nil, err
	}
	var result Result
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		llmtrace.LogDecodeError(llmtrace.FeaturePersonaCDP, err, text)
		return nil, fmt.Errorf("decode persona llm: %w", err)
	}
	if len(result.UserRecommendation) == 0 {
		result.UserRecommendation = []GamePreference{}
	}
	if result.UsageSummary.TopApps == nil {
		result.UsageSummary.TopApps = []AppScore{}
	}
	llmtrace.LogFeatureOK(llmtrace.FeaturePersonaCDP,
		"recommendations", len(result.UserRecommendation),
		"top_apps", len(result.UsageSummary.TopApps),
	)
	return &result, nil
}

func personaAssistantText(content, reasoning *string) string {
	if content != nil {
		if text := strings.TrimSpace(*content); text != "" {
			return text
		}
	}
	if reasoning != nil {
		return strings.TrimSpace(*reasoning)
	}
	return ""
}

func (s *synthesizer) postChat(ctx context.Context, body map[string]any) ([]byte, error) {
	if s.cfg.BaseURL == "" || s.cfg.APIKey == "" {
		return nil, fmt.Errorf("llm not configured")
	}
	model, messages, tools := llmtrace.BodyMeta(body)
	if model == "" {
		model = s.cfg.Model
	}
	llmtrace.LogCallStart(llmtrace.FeaturePersonaCDP, model, 0, messages, tools)

	start := time.Now()
	payload, err := json.Marshal(body)
	if err != nil {
		llmtrace.LogCallTransportError(llmtrace.FeaturePersonaCDP, 0, err)
		return nil, err
	}
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		llmtrace.LogCallTransportError(llmtrace.FeaturePersonaCDP, 0, err)
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		llmtrace.LogCallTransportError(llmtrace.FeaturePersonaCDP, 0, err)
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	elapsed := time.Since(start)
	if err != nil {
		llmtrace.LogCallTransportError(llmtrace.FeaturePersonaCDP, 0, err)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		llmtrace.LogCallHTTPError(llmtrace.FeaturePersonaCDP, 0, elapsed, resp.StatusCode, raw)
		return nil, fmt.Errorf("llm status %d: %s", resp.StatusCode, raw)
	}
	llmtrace.LogCallOK(llmtrace.FeaturePersonaCDP, 0, elapsed, llmtrace.SummarizeCompletion(raw))
	return raw, nil
}

func personaResponseSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"usage_summary": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"user_batch":           map[string]any{"type": "string"},
					"usage_habbit":         map[string]any{"type": "string"},
					"frequency":            map[string]any{"type": "string"},
					"renewal_behavior":     map[string]any{"type": "string"},
					"renewal_probability":  map[string]any{"type": "string"},
					"top_apps": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"name":  map[string]any{"type": "string"},
								"score": map[string]any{"type": "number"},
							},
							"required": []string{"name", "score"},
						},
					},
				},
				"required": []string{"user_batch", "frequency", "top_apps", "usage_habbit", "renewal_behavior", "renewal_probability"},
			},
			"user_profile": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"objective":  map[string]any{"type": "string"},
					"gamer_type": map[string]any{"type": "string"},
					"persona":    map[string]any{"type": "string"},
				},
				"required": []string{"objective", "gamer_type", "persona"},
			},
			"game_recommendations": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"played_game": map[string]any{"type": "string"},
						"score":       map[string]any{"type": "number"},
						"recommendations": map[string]any{
							"type": "array",
							"items": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"name":  map[string]any{"type": "string"},
									"score": map[string]any{"type": "number"},
								},
								"required": []string{"name", "score"},
							},
						},
					},
					"required": []string{"played_game", "score", "recommendations"},
				},
			},
		},
		"required": []string{"usage_summary", "user_profile", "game_recommendations"},
	}
}
