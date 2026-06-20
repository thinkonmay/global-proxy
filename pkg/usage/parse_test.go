package usage

import (
	"testing"
)

const sampleInfo = `{
  "Hostname": "gpu-worker-01",
  "Sessions": [{
    "id": "11111111-1111-1111-1111-111111111111",
    "vm": {
      "Volumes": [{"name": "22222222-2222-2222-2222-222222222222", "node": "gpu-worker-01"}],
      "GPUs": [{"id": "0000:01:00.0", "node": "gpu-worker-01"}]
    }
  }],
  "Volumes": [{"name": "22222222-2222-2222-2222-222222222222", "size": 10737418240, "inuse": true}]
}`

func TestExtractSessionTicksFromVolumes(t *testing.T) {
	info, err := ParseWorkerInfo([]byte(sampleInfo))
	if err != nil {
		t.Fatal(err)
	}
	ticks := ExtractSessionTicks(info, "gpu-worker-01")
	if len(ticks) != 1 {
		t.Fatalf("ticks = %d, want 1", len(ticks))
	}
	if ticks[0].SessionID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("session id = %q", ticks[0].SessionID)
	}
	if ticks[0].VolumeID != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("volume id = %q", ticks[0].VolumeID)
	}
}

func TestExtractSessionTicksNdiskFallback(t *testing.T) {
	raw := `{
	  "Hostname": "gpu-worker-01",
	  "Sessions": [{
	    "id": "sess-1",
	    "vm": {
	      "Ndisks": [{"volume": {"name": "vol-ndisk", "node": "remote-node"}}]
	    }
	  }]
	}`
	info, err := ParseWorkerInfo([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ticks := ExtractSessionTicks(info, "gpu-worker-01")
	if len(ticks) != 1 || ticks[0].VolumeID != "vol-ndisk" || ticks[0].Node != "remote-node" {
		t.Fatalf("unexpected ticks: %+v", ticks)
	}
}

func TestExtractVolumeTicksAverageSize(t *testing.T) {
	info, err := ParseWorkerInfo([]byte(sampleInfo))
	if err != nil {
		t.Fatal(err)
	}
	vols := ExtractVolumeTicks([]WorkerInfo{info})
	if len(vols) != 1 {
		t.Fatalf("volumes = %d", len(vols))
	}
	if vols[0].SizeGB != 10 {
		t.Fatalf("size gb = %d, want 10", vols[0].SizeGB)
	}
}

func TestTickBucket(t *testing.T) {
	if got := TickBucket(310, 300); got != 300 {
		t.Fatalf("bucket = %d", got)
	}
}
