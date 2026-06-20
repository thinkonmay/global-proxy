package config

// LLM configures the OpenAI-compatible API used by PWA game search.
type LLM struct {
	BaseURL string `mapstructure:"baseURL"`
	APIKey  string `mapstructure:"apiKey"`
	Model   string `mapstructure:"model"`
}

func mergeLLMDefaults(cfg *Config) {
	if cfg.LLM.Model == "" {
		cfg.LLM.Model = "gpt-4o"
	}
}
