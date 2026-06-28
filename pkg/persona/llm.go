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
)

const analystSystemPrompt = `You are a Senior User Behavior Analyst for Thinkmay CloudPC, a high-performance cloud gaming service.
Analyze VM app usage rollups and payment history and return a deep behavioral profile with Steam-oriented game recommendations.

App usage fields (platform ClickHouse rollups):
- app_key: normalized process or game slug (game:* for Steam titles)
- duration_sec: dwell time in the VM over the lookback window
- launch_count: how often the app was started

Plan policies:
- hour1: trial for new users (~3 hours, no date limit)
- month1: 30 days, 120 hours, RTX 3060 Ti class
- month2: 30 days, 360 hours, RTX 5060 Ti class
- month3: 30 days, unlimited hours

Instructions:
1. Focus on games and high-intent apps; ignore system noise already filtered upstream.
2. Infer usage frequency, peak hours, and renewal likelihood from payments.
3. For each played game, recommend up to 6 similar Steam-available titles with scores 0.0–1.0.
4. Recommendations must be real Steam game titles, not generic genres.`

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

func (s *synthesizer) Synthesize(ctx context.Context, appUsageJSON string, payments []PaymentRecord) (*Result, error) {
	paymentRaw, err := json.Marshal(payments)
	if err != nil {
		return nil, err
	}
	userPrompt := fmt.Sprintf(`Current timestamp: %s
VM app usage rollups (JSON):
%s
Payment history (JSON):
%s
Return JSON matching the persona_result schema.`,
		time.Now().Format(time.DateTime),
		appUsageJSON,
		string(paymentRaw),
	)

	body := map[string]any{
		"model": s.cfg.Model,
		"messages": []map[string]any{
			{"role": "system", "content": analystSystemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"response_format": map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "persona_result",
				"schema": personaResponseSchema(),
				"strict": false,
			},
		},
	}
	raw, err := s.postChat(ctx, body)
	if err != nil {
		return nil, err
	}
	var completion struct {
		Choices []struct {
			Message struct {
				Content *string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &completion); err != nil {
		return nil, err
	}
	if len(completion.Choices) == 0 || completion.Choices[0].Message.Content == nil {
		return nil, fmt.Errorf("empty llm response")
	}
	var result Result
	if err := json.Unmarshal([]byte(strings.TrimSpace(*completion.Choices[0].Message.Content)), &result); err != nil {
		return nil, fmt.Errorf("decode persona llm: %w", err)
	}
	if len(result.UserRecommendation) == 0 {
		result.UserRecommendation = []GamePreference{}
	}
	if result.UsageSummary.TopApps == nil {
		result.UsageSummary.TopApps = []AppScore{}
	}
	return &result, nil
}

func (s *synthesizer) postChat(ctx context.Context, body map[string]any) ([]byte, error) {
	if s.cfg.BaseURL == "" || s.cfg.APIKey == "" {
		return nil, fmt.Errorf("llm not configured")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.APIKey)
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm status %d: %s", resp.StatusCode, raw)
	}
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
