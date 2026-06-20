package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/rpc"
)

func TestGlobalRPCPostgRESTRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/get_plans" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"plans": []string{"basic"}})
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	h := NewGlobalRPCHandler(config.Config{RPC: config.RPC{Password1: rpc.DefaultPassword1()}}, pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	args, _ := json.Marshal(map[string]any{})
	reqBody, err := rpc.EncodeRPCRequest(rpc.Request{
		RPC:         "get_plans",
		Issuer:      "https://pb.example.com",
		Args:        args,
		ResponseKey: "resp-key-1234567890123456",
	}, rpc.DefaultPassword1())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/global_rpc", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	wire, _ := io.ReadAll(rec.Body)
	var env rpc.ResponseEnvelope
	if err := rpc.DecodeRPCResponse(wire, "resp-key-1234567890123456", &env); err != nil {
		t.Fatal(err)
	}
	if env.Error != nil {
		t.Fatalf("unexpected error envelope: %s", env.Error)
	}
}

func TestGlobalRPCRequiresAuthWhenEmailInArgs(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"})
	h := NewGlobalRPCHandler(config.Config{RPC: config.RPC{Password1: rpc.DefaultPassword1()}}, pr, nil, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	email := "user@example.com"
	args, _ := json.Marshal(map[string]any{"email": email})
	reqBody, err := rpc.EncodeRPCRequest(rpc.Request{
		RPC:         "get_subscription_v3",
		Issuer:      "https://pb.example.com",
		Args:        args,
		ResponseKey: "resp-key-1234567890123456",
	}, rpc.DefaultPassword1())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/global_rpc", bytes.NewReader(reqBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
