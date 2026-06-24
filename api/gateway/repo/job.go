package repo

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thinkonmay/global-proxy/api/contract"
)

type Repo struct{ pool *pgxpool.Pool }

func NewRepo(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// Enqueue inserts a pending job and returns its id. (gateway)
func (r *Repo) Enqueue(ctx context.Context, cmd string, args json.RawMessage, cluster *int64) (int64, error) {
	var id int64
	err := r.pool.QueryRow(ctx,
		`INSERT INTO job (command, arguments, cluster) VALUES ($1, $2, $3) RETURNING id`,
		cmd, args, cluster,
	).Scan(&id)
	return id, err
}

// Complete records a finished job's outcome. (worker)
func (r *Repo) Complete(ctx context.Context, id int64, result json.RawMessage, success bool) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE job SET result = $2, success = $3, finished_at = now() WHERE id = $1`,
		id, result, success,
	)
	return err
}

// Get returns a job by id, for status polling. (gateway)
func (r *Repo) Get(ctx context.Context, id int64) (contract.Job, error) {
	var j contract.Job
	err := r.pool.QueryRow(ctx,
		`SELECT id, command, arguments, cluster, created_at, finished_at, result, success FROM job WHERE id = $1`, id,
	).Scan(&j.ID, &j.Command, &j.Arguments, &j.Cluster, &j.CreatedAt, &j.FinishedAt, &j.Result, &j.Success)
	return j, err
}
