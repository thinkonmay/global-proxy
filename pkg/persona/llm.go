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

const analystSystemPrompt = `You are a Senior User Behavior Analyst for Thinkmay CloudPC.
Analyze session and payment data and return structured JSON with usage_summary, user_profile, and game_recommendations.
Focus on games and high-intent apps; ignore system noise.`

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
		cfg.HTTP = &http.Client{Timeout: 120 * time.Second}
	}
	return &synthesizer{cfg: cfg}
}

func (s *synthesizer) Synthesize(ctx context.Context, sessionsYAML string, payments []PaymentRecord) (*Result, error) {
	paymentRaw, err := json.Marshal(payments)
	if err != nil {
		return nil, err
	}
	userPrompt := fmt.Sprintf(`Current timestamp: %s
Sessions (JSON):
%s
Payment history (JSON):
%s
Return the structured persona analysis.`,
		time.Now().Format(time.DateTime),
		sessionsYAML,
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
			"usage_summary": map[string]any{"type": "object"},
			"user_profile":  map[string]any{"type": "object"},
			"game_recommendations": map[string]any{
				"type":  "array",
				"items": map[string]any{"type": "object"},
			},
		},
		"required": []string{"usage_summary", "user_profile", "game_recommendations"},
	}
}
