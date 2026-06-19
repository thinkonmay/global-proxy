-- Analytics storage (TDD §6 platform ClickHouse).
--
-- Ingest path: NATS JetStream (usage.snapshot) -> a Go sink consumer that
-- batch-INSERTs into usage_events. ClickHouse has NO native NATS engine (unlike
-- Kafka), so unlike the kafka design there is no auto-pump table + MV here — the
-- sink is application code: the worker's usage.snapshot subscription.

CREATE TABLE IF NOT EXISTS usage_events
(
    event_time   DateTime64(3),
    user_email   String,
    session_id   String,
    metric       LowCardinality(String),
    value        Float64,
    cluster      LowCardinality(String),
    _ingested_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(_ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (cluster, metric, session_id, event_time)
TTL toDateTime(event_time) + INTERVAL 18 MONTH;
