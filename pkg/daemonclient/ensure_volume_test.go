package daemonclient

import (
	"encoding/json"
	"testing"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
)

func TestVolumeExistsOnCluster(t *testing.T) {
	info := &persistent.WorkerInfor{
		Volumes: []*persistent.Volume{{Name: "vol-a"}},
	}
	if !VolumeExistsOnCluster(info, "vol-a") {
		t.Fatal("expected vol-a")
	}
	if VolumeExistsOnCluster(info, "vol-b") {
		t.Fatal("vol-b should not exist")
	}
}

func TestParseVolumeConfigurationTransient(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"template":  "win11",
		"transient": true,
	})
	conf, err := volumeconfig.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !conf.TransientEnabled() || conf.TemplateName() != "win11.template" {
		t.Fatalf("conf=%+v", conf)
	}
}
