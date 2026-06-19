package repo

import "github.com/thinkonmay/global-proxy/api/pkg/postgrest"

// Repo wraps the PostgREST client with the worker's claim/mark RPCs.
type Repo struct{ pr *postgrest.Client }

func NewRepo(pr *postgrest.Client) *Repo { return &Repo{pr: pr} }
