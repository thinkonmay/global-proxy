// Package idempotency deduplicates side effects under at-least-once delivery.
// Failed attempts are recorded but may be retried (NATS nak) until status=done.
package idempotency

import "context"

// Store is the ledger backend. Register is the claim (dedup by done/in-flight); Mark*
// record the attempt's outcome for observability.
type Store interface {
	// Register claims id: acquired=true runs fn, false means skip (done or in-flight).
	Register(ctx context.Context, id string) (acquired bool, err error)
	MarkDone(ctx context.Context, id string) error
	MarkError(ctx context.Context, id string) error
}

// Guard runs fn with at-least-once delivery semantics over a Store.
type Guard struct{ store Store }

func New(store Store) *Guard { return &Guard{store: store} }

// Run skips when already done or another worker holds a fresh pending claim.
// Register errors nak (safe retry). fn errors nak for redelivery; success marks done.
func (g *Guard) Run(ctx context.Context, id string, fn func(context.Context) error) error {
	acquired, err := g.store.Register(ctx, id)
	if err != nil {
		return err
	}
	if !acquired {
		return nil
	}
	if err := fn(ctx); err != nil {
		_ = g.store.MarkError(context.WithoutCancel(ctx), id)
		return err
	}
	_ = g.store.MarkDone(context.WithoutCancel(ctx), id)
	return nil
}
