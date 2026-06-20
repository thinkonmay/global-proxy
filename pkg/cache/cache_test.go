package cache_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/cache"
	cachememory "github.com/thinkonmay/global-proxy/api/pkg/cache/memory"
)

func TestMemoryImplementsClient(t *testing.T) {
	var _ cache.Client = cachememory.New()
}
