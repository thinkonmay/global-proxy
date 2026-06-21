package rpc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestPasswordL2Deterministic(t *testing.T) {
	a := PasswordL2("secret")
	b := PasswordL2("secret")
	if a != b {
		t.Fatal("PasswordL2 should be deterministic")
	}
	if len(a) != hex.EncodedLen(64) {
		t.Fatalf("unexpected hash length: %d", len(a))
	}
}

func TestEncryptDecryptJSONRoundTrip(t *testing.T) {
	password := PasswordL2("test-key")
	cases := []any{
		map[string]string{"k": "v"},
		map[string]any{"active": true, "count": float64(3)},
		Request{
			RPC:         "get_subscription_v3",
			Issuer:      "https://node.example.com",
			Args:        json.RawMessage(`{"email":"u@example.com"}`),
			ResponseKey: "resp-key-1234567890123456",
		},
	}
	for i, in := range cases {
		wire, err := EncryptJSON(in, password)
		if err != nil {
			t.Fatalf("case %d encrypt: %v", i, err)
		}
		assertEncryptWireLayout(t, wire)

		switch want := in.(type) {
		case map[string]string:
			var out map[string]string
			if err := DecryptJSON(wire, password, &out); err != nil {
				t.Fatalf("case %d decrypt: %v", i, err)
			}
			if out["k"] != want["k"] {
				t.Fatalf("case %d mismatch: %#v", i, out)
			}
		case map[string]any:
			var out map[string]any
			if err := DecryptJSON(wire, password, &out); err != nil {
				t.Fatalf("case %d decrypt: %v", i, err)
			}
			if out["active"] != want["active"] || out["count"] != want["count"] {
				t.Fatalf("case %d mismatch: %#v", i, out)
			}
		case Request:
			var out Request
			if err := DecryptJSON(wire, password, &out); err != nil {
				t.Fatalf("case %d decrypt: %v", i, err)
			}
			if out.RPC != want.RPC || out.Issuer != want.Issuer || string(out.Args) != string(want.Args) {
				t.Fatalf("case %d mismatch: %#v", i, out)
			}
		default:
			t.Fatalf("case %d: unhandled type %T", i, in)
		}
	}
}

func TestEncryptWireLayout(t *testing.T) {
	wire, err := EncryptJSON(map[string]string{"hello": "world"}, PasswordL2("layout-test"))
	if err != nil {
		t.Fatal(err)
	}
	assertEncryptWireLayout(t, wire)
}

func assertEncryptWireLayout(t *testing.T, wire []byte) {
	t.Helper()
	minLen := saltLength + ivLength + 16 + 1 // AES-GCM tag is 16 bytes
	if len(wire) < minLen {
		t.Fatalf("wire too short: got %d want >= %d", len(wire), minLen)
	}
	iv := wire[saltLength : saltLength+ivLength]
	if !bytes.Equal(iv[gcmNonceSize:], make([]byte, ivLength-gcmNonceSize)) {
		t.Fatalf("IV wire padding must be zero; got %v", iv[gcmNonceSize:])
	}
}

func TestEncryptUsesRandomSaltAndNonce(t *testing.T) {
	password := PasswordL2("entropy")
	in := map[string]string{"same": "payload"}
	first, err := EncryptJSON(in, password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptJSON(in, password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("expected distinct ciphertext for identical plaintext")
	}
}

func TestDecryptJSONWrongPassword(t *testing.T) {
	wire, err := EncryptJSON(map[string]string{"k": "v"}, PasswordL2("good"))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := DecryptJSON(wire, PasswordL2("bad"), &out); err == nil {
		t.Fatal("expected decrypt failure with wrong password")
	} else if !strings.Contains(err.Error(), "rpc: decrypt:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptJSONCiphertextTooShort(t *testing.T) {
	var out map[string]string
	err := DecryptJSON([]byte{1, 2, 3}, PasswordL2("key"), &out)
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected too short error, got %v", err)
	}
}

func TestDecryptJSONTamperedCiphertext(t *testing.T) {
	wire, err := EncryptJSON(map[string]string{"k": "v"}, PasswordL2("key"))
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)-1] ^= 0xff
	var out map[string]string
	if err := DecryptJSON(wire, PasswordL2("key"), &out); err == nil {
		t.Fatal("expected auth failure for tampered ciphertext")
	}
}

func TestDecryptJSONIgnoresIVWirePadding(t *testing.T) {
	password := PasswordL2("padding-test")
	wire, err := EncryptJSON(map[string]string{"ok": "true"}, password)
	if err != nil {
		t.Fatal(err)
	}
	for i := saltLength + gcmNonceSize; i < saltLength+ivLength; i++ {
		wire[i] = 0xff
	}
	var out map[string]string
	if err := DecryptJSON(wire, password, &out); err != nil {
		t.Fatalf("decrypt should ignore IV wire padding: %v", err)
	}
	if out["ok"] != "true" {
		t.Fatalf("unexpected payload: %#v", out)
	}
}

func TestEncryptDecryptWithDefaultPassword1(t *testing.T) {
	password := PasswordL2(DefaultPassword1())
	in := map[string]string{"rpc": "ping"}
	wire, err := EncryptJSON(in, password)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := DecryptJSON(wire, password, &out); err != nil {
		t.Fatal(err)
	}
	if out["rpc"] != "ping" {
		t.Fatalf("unexpected payload: %#v", out)
	}
}

func TestEncryptJSONGoldenVector(t *testing.T) {
	// Fixed salt/nonce so JS (website/utils/crypto.ts) and Go stay byte-compatible.
	salt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	ivWire, _ := hex.DecodeString("aabbccddeeff001122334455")
	if len(salt) != saltLength || len(ivWire) != gcmNonceSize {
		t.Fatal("bad golden vector inputs")
	}
	password := PasswordL2("golden-password")
	plain, err := json.Marshal(map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}

	wire := encryptJSONFixed(t, plain, password, salt, ivWire)
	wantWireHex := "00112233445566778899aabbccddeeff" +
		"aabbccddeeff00112233445500000000" +
		"d44ee959604329bbdc8fd552f2fa8f2dd824524b10d5200dddd71a47456cac25bd"
	if got := hex.EncodeToString(wire); got != wantWireHex {
		t.Fatalf("golden wire mismatch\n got: %s\nwant: %s", got, wantWireHex)
	}

	var out map[string]string
	if err := DecryptJSON(wire, password, &out); err != nil {
		t.Fatalf("decrypt golden vector: %v", err)
	}
	if out["hello"] != "world" {
		t.Fatalf("unexpected payload: %#v", out)
	}
}

// encryptJSONFixed mirrors EncryptJSON with fixed salt and 12-byte GCM nonce.
func encryptJSONFixed(t *testing.T, plain []byte, password string, salt, nonce []byte) []byte {
	t.Helper()
	if len(salt) != saltLength {
		t.Fatalf("salt length: got %d want %d", len(salt), saltLength)
	}
	if len(nonce) != gcmNonceSize {
		t.Fatalf("nonce length: got %d want %d", len(nonce), gcmNonceSize)
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, ivLength)
	copy(iv[:gcmNonceSize], nonce)
	sealed := gcm.Seal(nil, iv[:gcmNonceSize], plain, nil)
	out := make([]byte, 0, saltLength+ivLength+len(sealed))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, sealed...)
	return out
}
