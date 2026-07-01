package streammtls

import (
	"strings"
	"testing"
)

func TestDesktopCN(t *testing.T) {
	cn := DesktopCN("sess-1", "vm-abc")
	if cn != "desktop:sess-1:vm-abc" {
		t.Fatalf("cn=%q", cn)
	}
}

func TestValidateIDs(t *testing.T) {
	if err := ValidateIDs("", "vm"); err == nil {
		t.Fatal("expected session_id error")
	}
	if err := ValidateIDs("sess", ""); err == nil {
		t.Fatal("expected vm_id error")
	}
	if err := ValidateIDs("ok", "ok"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIDs("bad id", "vm"); err == nil {
		t.Fatal("expected invalid session_id")
	}
}

func TestValidateIDsAcceptsUUIDs(t *testing.T) {
	if err := ValidateIDs(
		"d11a5ff2-1ecc-4260-b2f7-c7502372e01f",
		"ada6a0f7-4317-4026-aafd-547489e7a4eb",
	); err != nil {
		t.Fatal(err)
	}
}

func TestValidateIDsRejectsOversize(t *testing.T) {
	long := strings.Repeat("a", maxIDLen+1)
	if err := ValidateIDs(long, "vm"); err == nil {
		t.Fatal("expected length error")
	}
}
