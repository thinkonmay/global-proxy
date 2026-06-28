package persona_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/persona"
)

func TestNewWorkerRequiresClickHouseCDP2(t *testing.T) {
	_, err := persona.NewWorker(nil, nil, persona.Config{}, nil)
	if err == nil {
		t.Fatal("expected error when usage querier is nil")
	}
}
