package usage

import (
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/config"
)

// OpenCH connects to platform ClickHouse from gateway/worker config.
func OpenCH(cfg config.ClickHouse) (driver.Conn, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("clickhouse addr is empty")
	}
	db := cfg.Database
	if db == "" {
		db = "platform"
	}
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{cfg.Addr},
		Auth: clickhouse.Auth{
			Database: db,
			Username: cfg.Username,
			Password: cfg.Password,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}
	return conn, nil
}
