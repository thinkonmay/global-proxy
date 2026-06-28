package config

// SerpAPI configures Google web search for AI store search (gateway PWA /v1/search/ai).
type SerpAPI struct {
	APIKey string `mapstructure:"apiKey"`
}
