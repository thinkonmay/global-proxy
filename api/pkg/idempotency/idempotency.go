// Package idempotency runs a side-effect at most once per id: Register (atomic
// claim) is the consume commitment, so duplicates and crash redeliveries skip and
// fn is never retried. Store backends: postgres, in-mem.
package idempotency

import "context"

// Store is the ledger backend. Register is the claim (dedup by existence); Mark*
// record the attempt's outcome for observability.
type Store interface {
	// Register claims id: acquired=true runs fn, false means it already exists (skip).
	Register(ctx context.Context, id string) (acquired bool, err error)
	MarkDone(ctx context.Context, id string) error
	MarkError(ctx context.Context, id string) error
}

// Guard runs fn at most once per id over a Store.
type Guard struct{ store Store }

func New(store Store) *Guard { return &Guard{store: store} }

// Run runs fn at most once. Register error naks (claim not committed, safe to
// retry). Once acquired the message is acked: a fn failure is recorded but never
// retried. A crash or unrecorded failure just loses the message (at most once).
func (g *Guard) Run(ctx context.Context, id string, fn func(context.Context) error) error {
	acquired, err := g.store.Register(ctx, id)
	if err != nil {
		return err
	}
	if !acquired {
		return nil // already attempted -> skip
	}
	if err := fn(ctx); err != nil {
		_ = g.store.MarkError(context.WithoutCancel(ctx), id)
		return nil
	}
	_ = g.store.MarkDone(context.WithoutCancel(ctx), id)
	return nil
}
