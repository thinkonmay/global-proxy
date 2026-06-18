package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	contract "github.com/thinkonmay/global-proxy/api/shared/model"
)

// Enqueue inserts a pending job and returns its id.
func (r *Repo) Enqueue(ctx context.Context, cmd string, args json.RawMessage, cluster *int64) (int64, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`) // arguments column is NOT NULL
	}
	body := map[string]any{"command": cmd, "arguments": args, "cluster": cluster}

	data, err := r.pr.Insert(ctx, "job", body, true)
	if err != nil {
		return 0, err
	}

	var rows []contract.Job
	if err := json.Unmarshal(data, &rows); err != nil {
		return 0, fmt.Errorf("decode insert response: %w", err)
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("insert returned no rows")
	}
	return rows[0].ID, nil
}

// Get returns a job by id, for status polling. Returns ErrNotFound if absent.
func (r *Repo) Get(ctx context.Context, id int64) (contract.Job, error) {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("eq.%d", id))
	q.Set("limit", "1")

	data, err := r.pr.Select(ctx, "job", q)
	if err != nil {
		return contract.Job{}, err
	}

	var rows []contract.Job
	if err := json.Unmarshal(data, &rows); err != nil {
		return contract.Job{}, fmt.Errorf("decode select response: %w", err)
	}
	if len(rows) == 0 {
		return contract.Job{}, ErrNotFound
	}
	return rows[0], nil
}

func (r *Repo) Complete(ctx context.Context, jobID int64, result []byte, success bool) error {
	_, err := r.pr.Update(
		ctx,
		"job",
		url.Values{"id": {"eq." + fmt.Sprint(jobID)}},
		map[string]any{
			"finished_at": "now()",
			"result":      result,
			"success":     success,
		},
		false,
	)
	return err
}
