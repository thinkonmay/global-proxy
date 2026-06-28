package config

import "testing"

func TestIsDirectLLMProviderURL(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"https://api.openai.com/v1", true},
		{"https://myorg.openai.azure.com/openai/deployments/gpt-4o", true},
		{"https://generativelanguage.googleapis.com/v1beta", true},
		{"http://litellm:4000/v1", false},
		{"http://litellm:4000", false},
		{"", false},
		{"not-a-url", false},
	}
	for _, tc := range tests {
		if got := isDirectLLMProviderURL(tc.raw); got != tc.want {
			t.Errorf("isDirectLLMProviderURL(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestApplyGatewayLLMConfigForcesLiteLLM(t *testing.T) {
	litellmProxyBaseURL = "http://litellm:4000/v1"
	t.Setenv("APP_LLM_GATEWAYAPIKEY", "sk-gateway-virtual")
	t.Setenv("LLM_GATEWAY_API_KEY", "")
	t.Setenv("APP_LLM_BASEURL", "https://api.openai.com/v1")

	cfg := &Config{LLM: LLM{BaseURL: "https://api.openai.com/v1", APIKey: "sk-openai-direct"}}
	ApplyGatewayLLMConfig(cfg)

	if cfg.LLM.BaseURL != "http://litellm:4000/v1" {
		t.Fatalf("BaseURL = %q, want LiteLLM proxy from config.yaml", cfg.LLM.BaseURL)
	}
	if cfg.LLM.APIKey != "sk-gateway-virtual" {
		t.Fatalf("APIKey = %q, want gateway virtual key", cfg.LLM.APIKey)
	}
}

func TestApplyGatewayLLMConfigIgnoresGenericAPIKey(t *testing.T) {
	litellmProxyBaseURL = "http://litellm:4000/v1"
	t.Setenv("APP_LLM_GATEWAYAPIKEY", "")
	t.Setenv("LLM_GATEWAY_API_KEY", "")

	cfg := &Config{LLM: LLM{APIKey: "sk-openai-direct"}}
	ApplyGatewayLLMConfig(cfg)

	if cfg.LLM.APIKey != "" {
		t.Fatalf("APIKey = %q, want empty when gateway virtual key unset", cfg.LLM.APIKey)
	}
}

func TestApplyGatewayLLMConfigDefaultBaseURL(t *testing.T) {
	litellmProxyBaseURL = "http://litellm:4000/v1"
	t.Setenv("APP_LLM_GATEWAYAPIKEY", "")
	t.Setenv("LLM_GATEWAY_API_KEY", "")

	cfg := &Config{}
	ApplyGatewayLLMConfig(cfg)

	if cfg.LLM.BaseURL != litellmProxyBaseURL {
		t.Fatalf("BaseURL = %q, want %q from config.yaml", cfg.LLM.BaseURL, litellmProxyBaseURL)
	}
}

func TestApplyGatewayLLMConfigRespectsConfigYAMLProxyURL(t *testing.T) {
	litellmProxyBaseURL = "http://custom-litellm:4000/v1"
	t.Setenv("APP_LLM_GATEWAYAPIKEY", "sk-gateway-virtual")

	cfg := &Config{LLM: LLM{BaseURL: "https://api.openai.com/v1"}}
	ApplyGatewayLLMConfig(cfg)

	if cfg.LLM.BaseURL != "http://custom-litellm:4000/v1" {
		t.Fatalf("BaseURL = %q, want config.yaml proxy URL", cfg.LLM.BaseURL)
	}
}
