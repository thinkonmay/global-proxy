package pwa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/sse"
)

const (
	searchPhaseStarting   = "starting"
	searchPhasePersona    = "persona"
	searchPhaseThinking   = "thinking"
	searchPhaseTool       = "tool"
	searchPhaseFinalizing = "finalizing"
	searchPhaseEnriching  = "enriching"
)

// pwaSearchSSEEvent is one frame on POST /v1/search/ai when Accept: text/event-stream.
type pwaSearchSSEEvent struct {
	Type       string          `json:"type"` // progress | result | error
	Phase      string          `json:"phase,omitempty"`
	Message    string          `json:"message,omitempty"`
	Round      int             `json:"round,omitempty"`
	Tool       string          `json:"tool,omitempty"`
	Suggestion string          `json:"suggestion,omitempty"`
	Games      []pwaGameSearch `json:"games,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type searchProgressReporter func(pwaSearchSSEEvent)

func wantsSearchSSE(r *http.Request) bool {
	if r.URL.Query().Get("stream") == "1" {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		return true
	}
	if strings.Contains(accept, "application/json") {
		return false
	}
	// Default to streaming progress for browser clients.
	return true
}

func emitSearchEvent(w http.ResponseWriter, seq *int, evt pwaSearchSSEEvent) error {
	if err := sse.WriteEvent(w, *seq, evt); err != nil {
		return err
	}
	*seq++
	if f, ok := w.(sse.Flusher); ok {
		f.Flush()
	}
	return nil
}

func reportSearchProgress(report searchProgressReporter, phase, message string, round int, tool string) {
	if report == nil {
		return
	}
	report(pwaSearchSSEEvent{
		Type:    "progress",
		Phase:   phase,
		Message: message,
		Round:   round,
		Tool:    tool,
	})
}

func toolProgressMessage(name, arguments string) string {
	switch {
	case strings.HasPrefix(name, "google_search"):
		var args struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal([]byte(arguments), &args)
		q := strings.TrimSpace(args.Query)
		if q == "" {
			return "Searching Google for recommendations..."
		}
		return fmt.Sprintf("Searching Google for \"%s\"...", q)
	case strings.HasPrefix(name, "search_steam"):
		var args struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal([]byte(arguments), &args)
		n := strings.TrimSpace(args.Name)
		if n == "" {
			return "Looking up games on Steam..."
		}
		return fmt.Sprintf("Looking up \"%s\" on Steam...", n)
	default:
		return "Searching..."
	}
}
