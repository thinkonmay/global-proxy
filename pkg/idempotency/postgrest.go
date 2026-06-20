package idempotency

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

var _ Store = (*PostgrestStore)(nil)

// PostgrestStore is the durable ledger over PostgREST RPCs.
type PostgrestStore struct{ pr *postgrest.Client }

func NewPostgrestStore(pr *postgrest.Client) *PostgrestStore { return &PostgrestStore{pr: pr} }

func (s *PostgrestStore) Register(ctx context.Context, id string) (bool, error) {
	var status string
	if err := s.pr.RPC(ctx, "register_message", map[string]any{"p_id": id}, &status); err != nil {
		return false, err
	}
	return status == "acquired", nil
}

func (s *PostgrestStore) MarkDone(ctx context.Context, id string) error {
	return s.pr.RPC(ctx, "mark_done", map[string]any{"p_id": id}, nil)
}

func (s *PostgrestStore) MarkError(ctx context.Context, id string) error {
	return s.pr.RPC(ctx, "mark_error", map[string]any{"p_id": id}, nil)
}
