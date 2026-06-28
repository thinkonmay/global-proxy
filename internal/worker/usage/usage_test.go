package usage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type fakeBatch struct {
	appendErr error
	sendErr   error
	rows      [][]any
}

func (f *fakeBatch) Append(v ...any) error {
	if f.appendErr != nil {
		return f.appendErr
	}
	f.rows = append(f.rows, v)
	return nil
}
func (f *fakeBatch) AppendStruct(_ any) error        { return nil }
func (f *fakeBatch) Column(_ int) driver.BatchColumn { return nil }
func (f *fakeBatch) Columns() []column.Interface     { return nil }
func (f *fakeBatch) Flush() error                    { return nil }
func (f *fakeBatch) Send() error                     { return f.sendErr }
func (f *fakeBatch) Abort() error                    { return nil }
func (f *fakeBatch) IsSent() bool                    { return false }
func (f *fakeBatch) Rows() int                       { return len(f.rows) }
func (f *fakeBatch) Close() error                    { return nil }

type fakeCH struct {
	batch driver.Batch
	err   error
}

func (f *fakeCH) Contributors() []string                                     { return nil }
func (f *fakeCH) ServerVersion() (*driver.ServerVersion, error)              { return nil, nil }
func (f *fakeCH) Select(context.Context, any, string, ...any) error          { return nil }
func (f *fakeCH) Query(context.Context, string, ...any) (driver.Rows, error) { return nil, nil }
func (f *fakeCH) QueryRow(context.Context, string, ...any) driver.Row        { return nil }
func (f *fakeCH) PrepareBatch(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.batch, nil
}
func (f *fakeCH) Exec(context.Context, string, ...any) error              { return nil }
func (f *fakeCH) AsyncInsert(context.Context, string, bool, ...any) error { return nil }
func (f *fakeCH) Ping(context.Context) error                              { return nil }
func (f *fakeCH) Stats() driver.Stats                                     { return driver.Stats{} }
func (f *fakeCH) Close() error                                            { return nil }

func TestHandleUsageInsert(t *testing.T) {
	batch := &fakeBatch{}
	h := &Handler{ch: &fakeCH{batch: batch}}
	events := []model.UsageMsg{{
		EventTime: time.Now().UTC(),
		UserEmail: "u@example.com",
		SessionID: "s1",
		Metric:    "hours",
		Value:     1.5,
		Cluster:   "c1",
	}}
	errs := h.handleUsage(context.Background(), events)
	if len(errs) != 0 {
		for _, e := range errs {
			if e != nil {
				t.Fatalf("unexpected error: %v", e)
			}
		}
	}
}

func TestHandleUsagePrepareBatchError(t *testing.T) {
	want := errors.New("ch down")
	h := &Handler{ch: &fakeCH{err: want}}
	errs := h.handleUsage(context.Background(), []model.UsageMsg{{Metric: "x"}})
	if len(errs) != 1 || errs[0] != want {
		t.Fatalf("errs: %v", errs)
	}
}

func TestHandleAppUsageSinkCDP1(t *testing.T) {
	batch := &fakeBatch{}
	h := &Handler{ch: &fakeCH{batch: batch}}
	ts := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	events := []model.AppUsageMsg{
		{
			EventTime:        ts,
			UserEmail:        "u@example.com",
			RuntimeSessionID: "sess-1",
			AppKey:           "game:elden-ring",
			DurationSec:      120,
			LaunchCount:      2,
			Cluster:          "c1",
			Node:             "n1",
			FlushReason:      "interval",
			FlushSeq:         3,
		},
		{
			EventTime:        ts,
			UserEmail:        "u@example.com",
			RuntimeSessionID: "sess-1",
			AppKey:           "fivem",
			DurationSec:      30,
			Cluster:          "c1",
		},
	}

	errs := h.handleAppUsage(context.Background(), events)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	if len(batch.rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(batch.rows))
	}
	row := batch.rows[0]
	if len(row) != 11 {
		t.Fatalf("column count = %d, want 11", len(row))
	}
	if row[3] != "game:elden-ring" || row[4] != 120.0 || row[5] != uint32(2) {
		t.Fatalf("first row = %#v", row)
	}
	if row[10] != "process_analytics" {
		t.Fatalf("default source = %v, want process_analytics", row[10])
	}
	if batch.rows[1][5] != uint32(1) {
		t.Fatalf("zero launch_count should default to 1, got %v", batch.rows[1][5])
	}
}
