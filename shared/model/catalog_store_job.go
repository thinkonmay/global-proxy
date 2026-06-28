package model

import "github.com/thinkonmay/global-proxy/api/pkg/bus"

var TopicCatalogStoreJob = bus.NewTopic[CatalogStoreJobMsg]("jobs.catalog.store")

// CatalogStoreJobMsg enqueues Steam catalog enrichment. The worker fetches
// appdetails, writes slim Postgres rows, and indexes Elasticsearch metadata.
type CatalogStoreJobMsg struct {
	RequestID string `json:"request_id"`
	AppID     int64  `json:"app_id"`
	Type      string `json:"type,omitempty"`
}
