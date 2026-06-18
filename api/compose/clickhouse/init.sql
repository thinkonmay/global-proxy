-- Analytics pipeline: Kafka -> ClickHouse, native Kafka table engine (no consumer code).
-- Demonstrates the usage.snapshot stream (TDD §6 platform ClickHouse).

-- 1. Kafka engine table = streaming consumer. Do NOT SELECT directly.
CREATE TABLE IF NOT EXISTS kafka_usage_raw
(
    event_time DateTime64(3),
    user_email String,
    session_id String,
    metric     String,
    value      Float64,
    cluster    String
)
ENGINE = Kafka
SETTINGS
    kafka_broker_list       = 'kafka:9092',
    kafka_topic_list        = 'usage.snapshot',
    kafka_group_name        = 'ch-usage-ingest',
    kafka_format            = 'JSONEachRow',
    kafka_num_consumers     = 1,
    kafka_max_block_size    = 1048576,
    kafka_flush_interval_ms = 5000,
    kafka_handle_error_mode = 'stream';   -- bad rows -> _error, don't stall

-- 2. Real storage.
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

-- 3. Materialized view = the pump (Kafka -> MergeTree on each flushed block).
CREATE MATERIALIZED VIEW IF NOT EXISTS usage_mv TO usage_events AS
SELECT event_time, user_email, session_id, metric, value, cluster
FROM kafka_usage_raw;
