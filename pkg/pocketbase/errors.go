package pocketbase

import "errors"

// ErrUnknownIssuer is returned when ?issuer= / cluster= is not in infra.clusters.
var ErrUnknownIssuer = errors.New("unknown cluster issuer")
