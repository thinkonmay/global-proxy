package volumeconfig

import (
	"encoding/json"
	"testing"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

func TestApplyConfiguration(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"timeout":      30,
		"max_duration": 3600,
		"disable_gpu":  true,
		"disk":         50,
		"ports":        []string{"-1/443/https"},
		"vlans":        []int32{10},
	})
	conf, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	ss := &persistent.WorkerSession{
		Vm:        &persistent.WorkerInfor{},
		Thinkmay:  &persistent.ThinkmaySession{},
	}
	Apply(ss, "vol-1", conf, nil)

	if ss.Timeout == nil || *ss.Timeout != 30 {
		t.Fatalf("timeout: %v", ss.Timeout)
	}
	if !ss.Vm.DisableGPU {
		t.Fatal("expected disable_gpu")
	}
	if len(ss.Vm.Volumes) != 1 || ss.Vm.Volumes[0].Name != "vol-1" {
		t.Fatalf("volumes: %+v", ss.Vm.Volumes)
	}
	if ss.Vm.Volumes[0].Size == nil || *ss.Vm.Volumes[0].Size != 50*1024*1024*1024 {
		t.Fatalf("disk bytes: %v", ss.Vm.Volumes[0].Size)
	}
	if len(ss.Portfw) != 1 || ss.Portfw[0].Proto != "https" {
		t.Fatalf("portfw: %+v", ss.Portfw)
	}
}
