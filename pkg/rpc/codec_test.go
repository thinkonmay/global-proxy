package rpc

import (
	"encoding/json"
	"testing"
)

func TestShuffleRoundTrip(t *testing.T) {
	in := []byte{0, 1, 2, 3, 4, 5, 255, 128}
	out := Unshuffle(Shuffle(in))
	if string(out) != string(in) {
		t.Fatalf("round trip failed: %v != %v", out, in)
	}
}

func TestEncryptDecryptJSON(t *testing.T) {
	type payload struct {
		RPC  string `json:"rpc"`
		Args map[string]any
	}
	in := payload{RPC: "get_plans", Args: map[string]any{"active": true}}
	wire, err := EncryptJSON(in, PasswordL2("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	var out payload
	if err := DecryptJSON(wire, PasswordL2("test-key"), &out); err != nil {
		t.Fatal(err)
	}
	if out.RPC != in.RPC {
		t.Fatalf("rpc mismatch")
	}
}

func TestDecodeEncodeRPCRoundTrip(t *testing.T) {
	args, _ := json.Marshal(map[string]any{"email": "u@example.com"})
	req := Request{
		RPC:         "get_subscription_v3",
		Issuer:      "https://node.example.com",
		Args:        args,
		ResponseKey: "abc123",
	}
	wire, err := EncryptJSON(req, PasswordL2(DefaultPassword1()))
	if err != nil {
		t.Fatal(err)
	}
	wire = Shuffle(wire)
	dec, err := DecodeRPC(wire, DefaultPassword1())
	if err != nil {
		t.Fatal(err)
	}
	if dec.RPC != req.RPC || dec.Issuer != req.Issuer {
		t.Fatalf("decode mismatch")
	}
	resp, err := EncodeRPCResponse(ResponseEnvelope{Data: json.RawMessage(`{"ok":true}`)}, req.ResponseKey)
	if err != nil {
		t.Fatal(err)
	}
	var env ResponseEnvelope
	if err := DecryptJSON(Unshuffle(resp), PasswordL2(req.ResponseKey), &env); err != nil {
		t.Fatal(err)
	}
}

// wireLikeWebCryptoClient builds salt+iv+ciphertext using a 12-byte GCM nonce in the
// 16-byte IV wire slot (matches website/utils/crypto.ts and gateway EncryptJSON).
func wireLikeWebCryptoClient(t *testing.T, v any, password string) []byte {
	t.Helper()
	wire, err := EncryptJSON(v, password)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestDecodeRPCLikeWebCryptoClient(t *testing.T) {
	req := Request{
		RPC:         "get_user",
		Issuer:      "https://pb.example",
		Args:        json.RawMessage(`{"email":"a@b.c"}`),
		ResponseKey: "resp-key-1234567890123456",
	}
	wire := wireLikeWebCryptoClient(t, req, PasswordL2(DefaultPassword1()))
	dec, err := DecodeRPC(Shuffle(wire), DefaultPassword1())
	if err != nil {
		t.Fatal(err)
	}
	if dec.RPC != req.RPC {
		t.Fatalf("rpc mismatch: %q", dec.RPC)
	}
}
