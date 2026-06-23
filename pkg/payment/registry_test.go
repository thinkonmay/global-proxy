// pkg/payment/registry_test.go
package payment_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
)

func TestRegistryGetCaseInsensitive(t *testing.T) {
	r := registry.NewRegistry(registry.Config{
		Stripe: registry.StripeConfig{SecretKey: "sk_test"},
	})
	c, ok := r.Get("STRIPE")
	if !ok {
		t.Fatal("Get(STRIPE) not found")
	}
	if c.Name() != "stripe" {
		t.Fatalf("Name() = %q, want stripe", c.Name())
	}
	if _, ok := r.Get("unknown"); ok {
		t.Fatal("Get(unknown) should be false")
	}
}

func TestRegistryAllReturnsCopy(t *testing.T) {
	r := registry.NewRegistry(registry.Config{})
	all := r.All()
	if len(all) != 5 {
		t.Fatalf("All() len = %d, want 5", len(all))
	}
	delete(all, "stripe")
	if _, ok := r.Get("stripe"); !ok {
		t.Fatal("mutating All() result corrupted the registry")
	}
}
