package volumeconfig

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

// DefaultVlans matches legacy node PocketBase defVlan when configuration omits vlans.
var DefaultVlans = []int32{-1}

// Configuration mirrors infra.volumes.configuration (node PB + C3 schema).
type Configuration struct {
	Template    *string  `json:"template"`
	MAC         *string  `json:"mac"`
	Timeout     *int32   `json:"timeout"`
	MaxDuration *int32   `json:"max_duration"`
	DiskSizeGB  *int64   `json:"disk"`
	Assistant   *bool    `json:"assistant"`
	TPM         *bool    `json:"tpm"`
	Extend      *bool    `json:"extend"`
	Transient   *bool    `json:"transient"`
	Snapshot    *bool    `json:"snapshot"`
	Headless    *bool    `json:"headless"`
	DisableGPU  *bool    `json:"disable_gpu"`
	PrefNodes   []string `json:"pref_nodes"`
	Ports       []string `json:"ports"`
	Vlans       []int32  `json:"vlans"`
}

// Parse decodes lookup_volume_configuration_v1 JSON.
func Parse(raw json.RawMessage) (Configuration, error) {
	var conf Configuration
	if len(raw) == 0 || string(raw) == "null" {
		return conf, nil
	}
	if err := json.Unmarshal(raw, &conf); err != nil {
		return Configuration{}, err
	}
	return conf, nil
}

// TemplateName returns the clone source template (win11.template default).
func (c Configuration) TemplateName() string {
	if c.Template != nil && strings.TrimSpace(*c.Template) != "" {
		t := strings.TrimSpace(*c.Template)
		if !strings.HasSuffix(t, ".template") {
			return t + ".template"
		}
		return t
	}
	return "win11.template"
}

// TransientEnabled reports whether the volume is ephemeral.
func (c Configuration) TransientEnabled() bool {
	return c.Transient != nil && *c.Transient
}

// AssistantEnabled reports whether the assistant sidecar should boot.
func (c Configuration) AssistantEnabled() bool {
	return c.Assistant != nil && *c.Assistant
}

// Apply merges configuration into a WorkerSession for /new (mirrors PB filterVolumeNew).
func Apply(data *persistent.WorkerSession, volID string, conf Configuration, defaultVlans []int32) {
	if data == nil || data.Vm == nil {
		return
	}
	if len(defaultVlans) == 0 {
		defaultVlans = DefaultVlans
	}

	data.Timeout = conf.Timeout
	data.MaxDuration = conf.MaxDuration
	data.Vm.PrefNode = conf.PrefNodes
	data.Vm.Vlans = conf.Vlans
	data.Vm.MAC = conf.MAC
	data.Vm.RemoteReady = true

	if conf.Headless != nil {
		data.Vm.RemoteReady = !*conf.Headless
	}
	if conf.DisableGPU != nil {
		data.Vm.DisableGPU = *conf.DisableGPU
	}
	if len(data.Vm.Vlans) == 0 {
		data.Vm.Vlans = append([]int32(nil), defaultVlans...)
	}
	if conf.TPM != nil {
		data.Vm.EnableTPM = *conf.TPM
	}
	if conf.Extend != nil && data.Thinkmay != nil {
		data.Vm.ExtendDisplay = *conf.Extend
	}

	var diskBytes *int64
	if conf.DiskSizeGB != nil {
		v := *conf.DiskSizeGB * 1024 * 1024 * 1024
		diskBytes = &v
	}

	data.Vm.Volumes = []*persistent.Volume{{
		Name: volID,
		Size: diskBytes,
	}}

	for _, pp := range conf.Ports {
		parts := strings.Split(pp, "/")
		if len(parts) != 3 {
			continue
		}
		vlan, err1 := strconv.Atoi(parts[0])
		dport, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		data.Portfw = append(data.Portfw, &persistent.Portforward{
			Proto: parts[2],
			DPort: int32(dport),
			Vlan:  int32(vlan),
		})
	}
}
