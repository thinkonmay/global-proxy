package cluster

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Secret is the PocketBase admin credentials stored in infra.clusters.secret.
type Secret struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func ParseSecret(raw json.RawMessage) (Secret, error) {
	var s Secret
	if len(raw) == 0 {
		return Secret{}, fmt.Errorf("empty cluster secret")
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return Secret{}, err
	}
	s.URL = strings.TrimRight(strings.TrimSpace(s.URL), "/")
	s.Username = strings.TrimSpace(s.Username)
	s.Password = strings.TrimSpace(s.Password)
	if s.URL == "" || s.Username == "" || s.Password == "" {
		return Secret{}, fmt.Errorf("cluster secret missing url/username/password")
	}
	return s, nil
}
