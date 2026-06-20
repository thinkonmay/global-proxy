package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type fakeBatch struct {
	appendErr error
	sendErr   error
}

func (f *fakeBatch) Append(_ ...any) error { return f.appendErr }
func (f *fakeBatch) AppendStruct(_ any) error { return nil }
func (f *fakeBatch) Column(_ int) driver.BatchColumn { return nil }
func (f *fakeBatch) Columns() []column.Interface     { return nil }
func (f *fakeBatch) Flush() error { return nil }
func (f *fakeBatch) Send() error  { return f.sendErr }
func (f *fakeBatch) Abort() error { return nil }
func (f *fakeBatch) IsSent() bool { return false }
func (f *fakeBatch) Rows() int    { return 0 }
func (f *fakeBatch) Close() error { return nil }

type fakeCH struct {
	batch driver.Batch
	err   error
}

func (f *fakeCH) Contributors() []string { return nil }
func (f *fakeCH) ServerVersion() (*driver.ServerVersion, error) { return nil, nil }
func (f *fakeCH) Select(context.Context, any, string, ...any) error { return nil }
func (f *fakeCH) Query(context.Context, string, ...any) (driver.Rows, error) { return nil, nil }
func (f *fakeCH) QueryRow(context.Context, string, ...any) driver.Row { return nil }
func (f *fakeCH) PrepareBatch(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.batch, nil
}
func (f *fakeCH) Exec(context.Context, string, ...any) error { return nil }
func (f *fakeCH) AsyncInsert(context.Context, string, bool, ...any) error { return nil }
func (f *fakeCH) Ping(context.Context) error { return nil }
func (f *fakeCH) Stats() driver.Stats { return driver.Stats{} }
func (f *fakeCH) Close() error { return nil }

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

func TestInitSubscribesVolumeTopic(t *testing.T) {
	bus := busmemory.New(nil)
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"})
	h := New(idempotency.New(idempotency.NewMemStore()), bus, &fakeCH{}, pr)
	h.Init()

	err := bus.Publish(context.Background(), model.TopicVolumeJob.Name, []byte(`{"outbox_id":1,"payload":{"command":"unknown"}}`))
	if err != nil {
		t.Fatal(err)
	}
	bus.Wait()
}
