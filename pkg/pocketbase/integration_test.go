package pocketbase

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestIntegrationSuperuserLoginAndCRUD(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	var created map[string]any
	err := client.CreateRecord(ctx, "volumes", map[string]any{
		"user":     "user-1",
		"local_id": "vol-local-1",
		"name":     "demo",
	}, &created)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("created id empty: %+v", created)
	}

	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := client.ListRecords(ctx, "volumes", nil, &listed); err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(listed.Items) != 1 || listed.Items[0]["local_id"] != "vol-local-1" {
		t.Fatalf("listed: %+v", listed.Items)
	}

	var updated map[string]any
	if err := client.UpdateRecord(ctx, "volumes", id, map[string]any{"tier": "pro"}, &updated); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	if updated["tier"] != "pro" {
		t.Fatalf("updated: %+v", updated)
	}

	if err := client.DeleteRecord(ctx, "volumes", id); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	var afterDelete struct {
		Items []map[string]any `json:"items"`
	}
	if err := client.ListRecords(ctx, "volumes", nil, &afterDelete); err != nil {
		t.Fatalf("ListRecords after delete: %v", err)
	}
	if len(afterDelete.Items) != 0 {
		t.Fatalf("expected empty list, got %+v", afterDelete.Items)
	}
}

func TestIntegrationReusesSuperuserToken(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	if err := client.ListRecords(ctx, "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{}); err != nil {
		t.Fatalf("initial ListRecords: %v", err)
	}
	client.mu.Lock()
	first := client.authToken
	client.mu.Unlock()

	for i := 0; i < 3; i++ {
		if err := client.ListRecords(ctx, "users", nil, &struct {
			Items []map[string]any `json:"items"`
		}{}); err != nil {
			t.Fatalf("ListRecords #%d: %v", i, err)
		}
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	if client.authToken != first {
		t.Fatalf("token changed without refresh interval: %q -> %q", first, client.authToken)
	}
}

func TestIntegrationProactiveRefreshAfterInterval(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	if err := client.ListRecords(ctx, "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{}); err != nil {
		t.Fatalf("initial ListRecords: %v", err)
	}

	client.mu.Lock()
	client.tokenIssuedAt = time.Now().Add(-tokenRefreshInterval - time.Minute)
	client.mu.Unlock()

	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := client.ListRecords(ctx, "users", nil, &listed); err != nil {
		t.Fatalf("ListRecords after interval: %v", err)
	}
}

func TestIntegration401Recovery(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	if err := client.ListRecords(ctx, "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{}); err != nil {
		t.Fatalf("initial ListRecords: %v", err)
	}

	client.mu.Lock()
	client.authToken = "invalid-token"
	client.tokenIssuedAt = time.Now()
	client.mu.Unlock()

	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := client.ListRecords(ctx, "users", nil, &listed); err != nil {
		t.Fatalf("ListRecords after forced 401: %v", err)
	}
}

func TestIntegrationEnsureUserAndVolumeFlow(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	email := "u@example.com"
	pass := "userpass123"
	q := url.Values{}
	q.Set("filter", `(email="`+email+`")`)
	var users struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := client.ListRecords(ctx, "users", q, &users); err != nil {
		t.Fatalf("ListRecords users: %v", err)
	}
	userID := ""
	if len(users.Items) == 0 {
		var created struct {
			ID string `json:"id"`
		}
		if err := client.CreateRecord(ctx, "users", map[string]any{
			"email":           email,
			"password":        pass,
			"passwordConfirm": pass,
			"name":            email,
		}, &created); err != nil {
			t.Fatalf("CreateRecord user: %v", err)
		}
		userID = created.ID
	} else {
		userID = users.Items[0].ID
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", "job-42")
	var vol map[string]any
	if err := client.CreateRecord(ctx, "volumes", map[string]any{
		"user":     userID,
		"local_id": "local-vol",
	}, &vol, WithHeaders(headers)); err != nil {
		t.Fatalf("CreateRecord volume: %v", err)
	}
	if vol["local_id"] != "local-vol" {
		t.Fatalf("volume: %+v", vol)
	}
}

func TestIntegrationWithBaseURLSeparateAuth(t *testing.T) {
	envA := startPocketBase(t)
	envB := startPocketBase(t)

	base := testClient(envA.URL)
	clientA := base
	clientB := base.WithBaseURL(envB.URL)
	ctx := context.Background()

	if err := clientA.ListRecords(ctx, "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{}); err != nil {
		t.Fatalf("cluster A: %v", err)
	}
	if err := clientB.ListRecords(ctx, "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{}); err != nil {
		t.Fatalf("cluster B: %v", err)
	}

	clientA.mu.Lock()
	tokA := clientA.authToken
	clientA.mu.Unlock()
	clientB.mu.Lock()
	tokB := clientB.authToken
	clientB.mu.Unlock()
	if tokA == "" || tokB == "" || tokA == tokB {
		t.Fatalf("expected distinct non-empty tokens, got A=%q B=%q", tokA, tokB)
	}
}

func TestIntegrationUserEmailFromRefresh(t *testing.T) {
	env := startPocketBase(t)
	client := testClient(env.URL)
	ctx := context.Background()

	email := "user@example.com"
	pass := "userpass123"
	if err := client.CreateRecord(ctx, "users", map[string]any{
		"email":           email,
		"password":        pass,
		"passwordConfirm": pass,
		"name":            email,
	}, nil); err != nil {
		t.Fatalf("CreateRecord user: %v", err)
	}

	userTok := userAuthToken(t, env.URL, email, pass)
	got, err := UserEmailFromRefresh(ctx, NewIssuerResolver("", ""), env.URL, userTok, nil)
	if err != nil {
		t.Fatalf("UserEmailFromRefresh: %v", err)
	}
	if got != email {
		t.Fatalf("email = %q, want %q", got, email)
	}
}

func TestIntegrationInvalidCredentials(t *testing.T) {
	env := startPocketBase(t)
	client := New(Config{
		URL:      env.URL,
		Username: testAdminEmail,
		Password: "wrong-password",
	})
	err := client.ListRecords(context.Background(), "users", nil, &struct {
		Items []map[string]any `json:"items"`
	}{})
	if err == nil {
		t.Fatal("expected error for bad password")
	}
	var pe *Error
	if !errors.As(err, &pe) || pe.Status != http.StatusBadRequest {
		t.Fatalf("err = %v", err)
	}
}
