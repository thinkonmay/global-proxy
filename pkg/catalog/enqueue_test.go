package catalog_test

import (
	"context"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestEnqueueEnsureSteamStore(t *testing.T) {
	b := busmemory.New(nil)
	got := make(chan model.CatalogStoreJobMsg, 1)
	bus.Subscribe(b, model.TopicCatalogStoreJob, "test-cap", func(_ context.Context, msg model.CatalogStoreJobMsg) error {
		got <- msg
		return nil
	})
	if err := catalog.EnqueueEnsureSteamStore(context.Background(), b, 413150); err != nil {
		t.Fatal(err)
	}
	b.Wait()
	select {
	case msg := <-got:
		if msg.AppID != 413150 {
			t.Fatalf("msg=%#v", msg)
		}
	default:
		t.Fatal("expected published catalog store job")
	}
}
