package cluster_test

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
)

func TestGrpcTarget(t *testing.T) {
	info := cluster.Info{Domain: "haiphong.thinkmay.net"}
	if got := cluster.GrpcTarget(info, 50000, "", ""); got != "haiphong.thinkmay.net:50000" {
		t.Fatalf("got %q", got)
	}
	if got := cluster.GrpcTarget(info, 0, "haiphong.thinkmay.net", "10.0.0.5:50000"); got != "10.0.0.5:50000" {
		t.Fatalf("home override: got %q", got)
	}
}
