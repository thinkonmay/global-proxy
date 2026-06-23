package sepay

import (
	"testing"
)

func TestSecretEqualConstantTime(t *testing.T) {
	if !secretEqual("abc", "abc") {
		t.Fatal("equal secrets should match")
	}
	if secretEqual("abc", "abd") {
		t.Fatal("different secrets should not match")
	}
	if secretEqual("abc", "abcd") {
		t.Fatal("different-length secrets should not match")
	}
}
