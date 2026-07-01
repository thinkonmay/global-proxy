package streammtls

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	cnPrefix  = "desktop:"
	maxIDLen  = 128
	idPattern = `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`
)

var idRe = regexp.MustCompile(idPattern)

// DesktopCN builds the Vault PKI common name for a desktop QUIC client cert.
func DesktopCN(sessionID, vmID string) string {
	return cnPrefix + sanitizeID(sessionID) + ":" + sanitizeID(vmID)
}

// ValidateIDs checks session_id and vm_id are present and safe for CN embedding.
// Does not verify they exist in cluster state (gateway trusts authenticated caller).
func ValidateIDs(sessionID, vmID string) error {
	sessionID = strings.TrimSpace(sessionID)
	vmID = strings.TrimSpace(vmID)
	if sessionID == "" {
		return fmt.Errorf("session_id required")
	}
	if vmID == "" {
		return fmt.Errorf("vm_id required")
	}
	if len(sessionID) > maxIDLen || len(vmID) > maxIDLen {
		return fmt.Errorf("session_id and vm_id must be at most %d characters", maxIDLen)
	}
	if !idRe.MatchString(sessionID) {
		return fmt.Errorf("session_id has invalid characters")
	}
	if !idRe.MatchString(vmID) {
		return fmt.Errorf("vm_id has invalid characters")
	}
	return nil
}

func sanitizeID(s string) string {
	s = strings.TrimSpace(s)
	if idRe.MatchString(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	if len(out) > maxIDLen {
		out = out[:maxIDLen]
	}
	return out
}
