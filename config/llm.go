package config

import (
	"log/slog"
	"net/url"
	"os"
	"strings"
)

// litellmProxyBaseURL is llm.baseURL from config.yaml (captured before APP_LLM_* env overrides).
var litellmProxyBaseURL string

const defaultLLMModel = "deepseek-v4-flash"

// directProviderHosts are upstream LLM endpoints the gateway must never call.
var directProviderHosts = map[string]struct{}{
	"api.openai.com":                    {},
	"api.deepseek.com":                  {},
	"openai.azure.com":                  {},
	"api.anthropic.com":                 {},
	"generativelanguage.googleapis.com": {},
	"aiplatform.googleapis.com":         {},
}

// LLM configures the OpenAI-compatible API used by PWA game search.
// Gateway traffic is pinned to the compose LiteLLM proxy (ApplyGatewayLLMConfig).
type LLM struct {
	BaseURL string `mapstructure:"baseURL"`
	APIKey  string `mapstructure:"apiKey"`
	Model   string `mapstructure:"model"`
}

func captureLiteLLMProxyBaseURL(cfg Config, fallback string) {
	litellmProxyBaseURL = strings.TrimRight(strings.TrimSpace(cfg.LLM.BaseURL), "/")
	if litellmProxyBaseURL == "" {
		litellmProxyBaseURL = strings.TrimRight(strings.TrimSpace(fallback), "/")
	}
}

func mergeLLMDefaults(cfg *Config) {
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = defaultLLMModel
	}
	if cfg.LLM.BaseURL == "" {
		cfg.LLM.BaseURL = litellmProxyBaseURL
	}
	cfg.LLM.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.LLM.BaseURL), "/")
}

// ApplyGatewayLLMConfig routes all gateway LLM calls through LiteLLM using a
// dedicated virtual key (APP_LLM_GATEWAYAPIKEY / LLM_GATEWAY_API_KEY). Upstream
// provider URLs and credentials are never used from the gateway binary.
func ApplyGatewayLLMConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	mergeLLMDefaults(cfg)

	if v := strings.TrimSpace(os.Getenv("APP_LLM_GATEWAYAPIKEY")); v != "" {
		cfg.LLM.APIKey = v
	} else if v := strings.TrimSpace(os.Getenv("LLM_GATEWAY_API_KEY")); v != "" {
		cfg.LLM.APIKey = v
	} else {
		// Never fall back to APP_LLM_APIKEY / upstream provider credentials on gateway.
		cfg.LLM.APIKey = ""
	}

	proxyURL := litellmProxyBaseURL
	baseURL := strings.TrimSpace(cfg.LLM.BaseURL)
	if baseURL == "" {
		baseURL = proxyURL
	} else if isDirectLLMProviderURL(baseURL) {
		slog.Warn("gateway llm baseURL points at an upstream provider; forcing LiteLLM proxy",
			"configured", baseURL,
			"litellm", proxyURL,
		)
		baseURL = proxyURL
	}
	cfg.LLM.BaseURL = strings.TrimRight(baseURL, "/")
}

func isDirectLLMProviderURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if _, ok := directProviderHosts[host]; ok {
		return true
	}
	// Azure OpenAI: *.openai.azure.com
	if strings.HasSuffix(host, ".openai.azure.com") {
		return true
	}
	return false
}
