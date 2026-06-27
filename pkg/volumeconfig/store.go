package volumeconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// Lookup loads configuration for an owned volume.
func Lookup(ctx context.Context, pr *postgrest.Client, email, volumeID string) (Configuration, error) {
	if pr == nil {
		return Configuration{}, fmt.Errorf("postgrest unavailable")
	}
	var raw json.RawMessage
	if err := pr.RPC(ctx, "lookup_volume_configuration_v1", map[string]any{
		"email":     email,
		"volume_id": volumeID,
	}, &raw); err != nil {
		return Configuration{}, err
	}
	return Parse(raw)
}

// Patch merges patch into infra.volumes.configuration for an owned volume.
func Patch(ctx context.Context, pr *postgrest.Client, email, volumeID string, patch map[string]any) error {
	if pr == nil {
		return fmt.Errorf("postgrest unavailable")
	}
	return pr.RPC(ctx, "patch_volume_configuration_v1", map[string]any{
		"email":     email,
		"volume_id": volumeID,
		"patch":     patch,
	}, nil)
}

// SetTemplateSource records the clone source after reallocate (PB updateVolTemplate).
func SetTemplateSource(ctx context.Context, pr *postgrest.Client, email, volumeID, templateSource string) error {
	if pr == nil {
		return fmt.Errorf("postgrest unavailable")
	}
	templateSource = strings.TrimSpace(templateSource)
	if templateSource == "" {
		return fmt.Errorf("empty template source")
	}
	return pr.RPC(ctx, "set_volume_template_source_v1", map[string]any{
		"email":           email,
		"volume_id":       volumeID,
		"template_source": templateSource,
	}, nil)
}

// TransientEnabled reports whether the volume configuration marks it ephemeral.
func TransientEnabled(ctx context.Context, pr *postgrest.Client, email, volumeID string) (bool, error) {
	conf, err := Lookup(ctx, pr, email, volumeID)
	if err != nil {
		return false, err
	}
	return conf.TransientEnabled(), nil
}
