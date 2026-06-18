package repo

import (
	"errors"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

var ErrNotFound = errors.New("not found")

type Repo struct{ pr *postgrest.Client }

func NewRepo(pr *postgrest.Client) *Repo { return &Repo{pr: pr} }
