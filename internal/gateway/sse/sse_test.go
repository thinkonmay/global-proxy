package sse

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestSSEHubDispatchRoutesByRecipient(t *testing.T) {
	hub := NewHub()
	c1 := hub.add("alice")
	c2 := hub.add("bob")

	msg := model.SSEMsg{Type: model.SSENotification, Recipient: "alice", Data: json.RawMessage(`{"title":"hi"}`)}
	if err := hub.Dispatch(nil, msg); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-c1.ch:
		if got.Recipient != "alice" {
			t.Fatalf("alice msg: %+v", got)
		}
	default:
		t.Fatal("alice should receive message")
	}
	select {
	case <-c2.ch:
		t.Fatal("bob should not receive targeted message")
	default:
	}
}

func TestSSEHubWriteMsgFormat(t *testing.T) {
	hub := NewHub()
	var buf bytes.Buffer
	hub.writeMsg(&buf, model.SSEMsg{Type: model.SSENotification, Data: json.RawMessage(`{"title":"t"}`)})
	out := buf.String()
	if !strings.HasPrefix(out, "id:1\n") || !strings.Contains(out, "data:") {
		t.Fatalf("sse format: %q", out)
	}
}

func TestSSEHubClients(t *testing.T) {
	hub := NewHub()
	if hub.Clients() != 0 {
		t.Fatal("expected zero clients")
	}
	c := hub.add("u")
	if hub.Clients() != 1 {
		t.Fatal("expected one client")
	}
	hub.remove(c)
	if hub.Clients() != 0 {
		t.Fatal("expected zero after remove")
	}
}
