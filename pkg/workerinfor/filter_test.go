package workerinfor_test

import (
	"testing"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/workerinfor"
)

func TestFilterAndMerge(t *testing.T) {
	info := &persistent.WorkerInfor{
		Hostname: "node-a",
		Volumes: []*persistent.Volume{
			{Name: "vol-1", Pool: "unified"},
			{Name: "other-vol", Pool: "unified"},
			{Name: "app.bin", Pool: "app_data"},
		},
		Sessions: []*persistent.WorkerSession{
			{Id: "s1", Vm: &persistent.WorkerInfor{Volumes: []*persistent.Volume{{Name: "vol-1"}}}},
			{Id: "s2", Vm: &persistent.WorkerInfor{Volumes: []*persistent.Volume{{Name: "other-vol"}}}},
		},
		GPUs: []*persistent.GPU{{Id: "gpu0"}},
	}

	filtered := workerinfor.Filter(info, []string{"vol-1"})
	if len(filtered.Sessions) != 1 || filtered.Sessions[0].Id != "s1" {
		t.Fatalf("sessions: %+v", filtered.Sessions)
	}
	if len(filtered.Volumes) != 2 {
		t.Fatalf("volumes: %d", len(filtered.Volumes))
	}
	if len(filtered.GPUs) != 0 {
		t.Fatalf("expected GPUs stripped")
	}

	merged := workerinfor.Merge([]*persistent.WorkerInfor{
		{Hostname: "a", Sessions: filtered.Sessions, Volumes: filtered.Volumes},
		{Hostname: "b", Sessions: []*persistent.WorkerSession{{Id: "s3"}}, Volumes: []*persistent.Volume{{Name: "vol-2"}}},
	})
	if len(merged.Sessions) != 2 {
		t.Fatalf("merged sessions: %d", len(merged.Sessions))
	}
	if merged.Hostname != "a" {
		t.Fatalf("hostname: %q", merged.Hostname)
	}
}
