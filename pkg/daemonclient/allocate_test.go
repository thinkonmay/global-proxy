package daemonclient

import (
	"testing"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

func TestBuildAllocateRequest(t *testing.T) {
	info := &persistent.WorkerInfor{
		Pools: []*persistent.Pool{
			{Name: "user_data", Node: "node-a", Size: 100},
			{Name: "unified_data", Node: "node-a", Size: 50},
		},
		Volumes: []*persistent.Volume{
			{Name: "win11.template", Node: "node-a"},
		},
	}

	req, err := BuildAllocateRequest(info, "vol-new", "win11", false)
	if err != nil {
		t.Fatalf("BuildAllocateRequest: %v", err)
	}
	if req.Source.Name != "win11.template" {
		t.Fatalf("source = %q", req.Source.Name)
	}
	if req.Destination.Name != "vol-new" || req.Destination.Node != "node-a" {
		t.Fatalf("destination = %+v", req.Destination)
	}
	if req.Destination.Transient {
		t.Fatal("expected non-transient destination")
	}
}

func TestBuildAllocateRequestRejectsDuplicate(t *testing.T) {
	info := &persistent.WorkerInfor{
		Volumes: []*persistent.Volume{{Name: "vol-dup", Node: "node-a"}},
	}
	_, err := BuildAllocateRequest(info, "vol-dup", "win11", false)
	if err == nil {
		t.Fatal("expected duplicate volume error")
	}
}
