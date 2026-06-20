package usage

import (
	"encoding/json"
	"fmt"
	"strings"
)

// WorkerInfo mirrors the JSON shape of persistent.WorkerInfor pushed by virtdaemon.
type WorkerInfo struct {
	Hostname string          `json:"Hostname"`
	Sessions []WorkerSession `json:"Sessions"`
	Volumes  []Volume        `json:"Volumes"`
	Ndisks   []NetworkDisk   `json:"Ndisks"`
}

type WorkerSession struct {
	ID string      `json:"id"`
	Vm *WorkerInfo `json:"vm"`
}

type Volume struct {
	Name  string `json:"name"`
	Inuse bool   `json:"inuse"`
	Size  *int64 `json:"size"`
	Node  string `json:"node"`
}

type NetworkDisk struct {
	Volume *Volume `json:"volume"`
}

// SessionTick is one billable VM session observation (replaces vm_snapshoot_v4 rows).
type SessionTick struct {
	SessionID string
	VolumeID  string
	Node      string
}

// VolumeTick is one billable storage observation (replaces volume_snapshoot rows).
type VolumeTick struct {
	VolumeID string
	SizeGB   int64
	Node     string
}

// ParseWorkerInfo decodes virtdaemon WorkerInfor JSON.
func ParseWorkerInfo(raw []byte) (WorkerInfo, error) {
	var info WorkerInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return WorkerInfo{}, fmt.Errorf("decode worker info: %w", err)
	}
	return info, nil
}

// ExtractSessionTicks ports snapshoot_v6 session/volume extraction from WorkerInfor.
func ExtractSessionTicks(info WorkerInfo, nodeHostname string) []SessionTick {
	out := make([]SessionTick, 0, len(info.Sessions))
	for _, sess := range info.Sessions {
		if sess.Vm == nil {
			continue
		}
		sessionID := strings.TrimSpace(sess.ID)
		if sessionID == "" {
			continue
		}
		if ticks := sessionTicksFromVM(sess.Vm, sessionID, nodeHostname); len(ticks) > 0 {
			out = append(out, ticks...)
		}
	}
	return out
}

func sessionTicksFromVM(vm *WorkerInfo, sessionID, fallbackNode string) []SessionTick {
	var out []SessionTick
	for _, vol := range vm.Volumes {
		name := strings.TrimSpace(vol.Name)
		if name == "" || name == "app" {
			continue
		}
		out = append(out, SessionTick{
			SessionID: sessionID,
			VolumeID:  name,
			Node:      coalesceNode(vol.Node, fallbackNode),
		})
	}
	if len(out) > 0 {
		return out
	}
	for _, ndisk := range vm.Ndisks {
		if ndisk.Volume == nil {
			continue
		}
		name := strings.TrimSpace(ndisk.Volume.Name)
		if name == "" {
			continue
		}
		out = append(out, SessionTick{
			SessionID: sessionID,
			VolumeID:  name,
			Node:      coalesceNode(ndisk.Volume.Node, fallbackNode),
		})
		if len(out) > 0 {
			break
		}
	}
	return out
}

// ExtractVolumeTicks aggregates volume sizes across nodes (snapshoot_volume_v1 parity).
func ExtractVolumeTicks(infos []WorkerInfo) []VolumeTick {
	type key struct {
		volumeID string
	}
	type acc struct {
		total int64
		count int
		node  string
	}
	byVol := map[key]*acc{}
	for _, info := range infos {
		node := strings.TrimSpace(info.Hostname)
		for _, vol := range info.Volumes {
			name := strings.TrimSpace(vol.Name)
			if name == "" || name == "app" {
				continue
			}
			k := key{volumeID: name}
			a := byVol[k]
			if a == nil {
				a = &acc{node: coalesceNode(vol.Node, node)}
				byVol[k] = a
			}
			if vol.Size != nil && *vol.Size > 0 {
				a.total += *vol.Size
				a.count++
			}
		}
	}
	out := make([]VolumeTick, 0, len(byVol))
	for k, a := range byVol {
		var sizeGB int64
		if a.count > 0 {
			sizeGB = (a.total / int64(a.count)) / (1024 * 1024 * 1024)
		}
		out = append(out, VolumeTick{
			VolumeID: k.volumeID,
			SizeGB:   sizeGB,
			Node:     a.node,
		})
	}
	return out
}

func coalesceNode(primary, fallback string) string {
	if s := strings.TrimSpace(primary); s != "" {
		return s
	}
	return strings.TrimSpace(fallback)
}

// TickBucket returns the UTC bucket start for deduplication.
func TickBucket(unixSec int64, intervalSec int64) int64 {
	if intervalSec <= 0 {
		intervalSec = 300
	}
	return (unixSec / intervalSec) * intervalSec
}
