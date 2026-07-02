package event

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestHubDispatchRoutesByDomainAndRecipient(t *testing.T) {
	hub := NewHub()
	alice := hub.add("payment", "alice")
	bob := hub.add("payment", "bob")
	aliceVolume := hub.add("volume", "alice")

	msg := model.EventRaw{Domain: "payment", Recipient: "alice", Data: json.RawMessage(`{"status":"success"}`)}
	if err := hub.Dispatch(context.TODO(), msg); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-alice.ch:
		if got.Recipient != "alice" || got.Domain != "payment" {
			t.Fatalf("alice msg: %+v", got)
		}
	default:
		t.Fatal("alice should receive the payment message")
	}
	select {
	case <-bob.ch:
		t.Fatal("bob should not receive a message targeted at alice")
	default:
	}
	select {
	case <-aliceVolume.ch:
		t.Fatal("alice's volume stream should not receive a payment event")
	default:
	}
}

func TestHubWriteMsgWritesPayloadVerbatim(t *testing.T) {
	hub := NewHub()
	var buf bytes.Buffer
	hub.writeMsg(&buf, model.EventRaw{Domain: "payment", Data: json.RawMessage(`{"status":"success"}`)})
	out := buf.String()
	if !strings.HasPrefix(out, "id:1\n") || !strings.Contains(out, `data:{"status":"success"}`) {
		t.Fatalf("sse format: %q", out)
	}
}

func TestHubClients(t *testing.T) {
	hub := NewHub()
	if hub.Clients() != 0 {
		t.Fatal("expected zero clients")
	}
	c := hub.add("payment", "u")
	if hub.Clients() != 1 {
		t.Fatal("expected one client")
	}
	hub.remove(c)
	if hub.Clients() != 0 {
		t.Fatal("expected zero after remove")
	}
}
