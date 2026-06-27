package workerinfor

import (
	"slices"
	"strings"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

// Filter keeps sessions/volumes visible to the user (mirrors PocketBase filterVolume).
func Filter(info *persistent.WorkerInfor, volumeIDs []string) *persistent.WorkerInfor {
	if info == nil {
		return &persistent.WorkerInfor{}
	}
	out := cloneInfo(info)
	if len(volumeIDs) == 0 {
		out.Sessions = nil
		out.Volumes = nil
		out.GPUs = nil
		out.Pools = nil
		out.Interfaces = nil
		return out
	}

	var sessions []*persistent.WorkerSession
	for _, session := range info.Sessions {
		if sessionMatchesVolumes(session, volumeIDs) {
			sessions = append(sessions, session)
		}
	}

	var volumes []*persistent.Volume
	for _, volume := range info.Volumes {
		if volume.Pool == "app_data" ||
			strings.Contains(volume.Name, ".template") ||
			slices.Contains(volumeIDs, volume.Name) {
			volumes = append(volumes, volume)
		}
	}

	out.GPUs = nil
	out.Pools = nil
	out.Interfaces = nil
	out.Sessions = sessions
	out.Volumes = volumes
	return out
}

// Merge combines fan-out results from multiple clusters.
func Merge(parts []*persistent.WorkerInfor) *persistent.WorkerInfor {
	if len(parts) == 0 {
		return &persistent.WorkerInfor{}
	}
	out := cloneInfo(parts[0])
	for _, part := range parts[1:] {
		if part == nil {
			continue
		}
		out.Sessions = append(out.Sessions, part.Sessions...)
		out.Volumes = append(out.Volumes, part.Volumes...)
	}
	return out
}

func cloneInfo(in *persistent.WorkerInfor) *persistent.WorkerInfor {
	if in == nil {
		return &persistent.WorkerInfor{}
	}
	out := *in
	if in.Sessions != nil {
		out.Sessions = append([]*persistent.WorkerSession(nil), in.Sessions...)
	}
	if in.Volumes != nil {
		out.Volumes = append([]*persistent.Volume(nil), in.Volumes...)
	}
	return &out
}

func sessionMatchesVolumes(session *persistent.WorkerSession, vols []string) bool {
	if session == nil {
		return false
	}
	if session.Vm != nil {
		for _, volume := range session.Vm.Volumes {
			if slices.Contains(vols, volume.Name) {
				return true
			}
		}
		for _, ndisk := range session.Vm.Ndisks {
			if ndisk.Volume != nil && slices.Contains(vols, ndisk.Volume.Name) {
				return true
			}
		}
	}
	if session.Ndisk != nil && session.Ndisk.Volume != nil &&
		slices.Contains(vols, session.Ndisk.Volume.Name) {
		return true
	}
	for _, pfw := range session.Portfw {
		if slices.Contains(vols, pfw.VolumeID) {
			return true
		}
	}
	return false
}
