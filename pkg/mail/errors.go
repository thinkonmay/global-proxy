package mail

import "errors"

var (
	ErrMissingEmail = errors.New("mail: email required")
)
