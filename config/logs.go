package config

// Logs configures worker-node verbose log push ingest into Elasticsearch.
type Logs struct {
	ElasticsearchURL     string `mapstructure:"elasticsearchUrl"`
	BulkMaxBytes         int    `mapstructure:"bulkMaxBytes"`
	RateLimitBytesPerSec int    `mapstructure:"rateLimitBytesPerSec"`
}

func mergeLogsDefaults(cfg *Config) {
	l := &cfg.Logs
	if l.ElasticsearchURL == "" {
		l.ElasticsearchURL = "http://elasticsearch:9200"
	}
	if l.BulkMaxBytes <= 0 {
		l.BulkMaxBytes = 1 << 20
	}
	if l.RateLimitBytesPerSec <= 0 {
		l.RateLimitBytesPerSec = 1 << 20
	}
}
