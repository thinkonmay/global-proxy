package sse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// WriteHeaders sets standard SSE response headers.
func WriteHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
}

// WriteEvent writes one SSE event (id + data) matching PocketBase writeSSE format.
func WriteEvent(w io.Writer, index int, obj any) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	parts := [][]byte{
		[]byte(fmt.Sprintf("id:%d\n", index)),
		[]byte("data:"),
		data,
		[]byte("\n\n"),
	}
	for _, part := range parts {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

// Flusher is satisfied by http.ResponseWriter when streaming is supported.
type Flusher interface {
	Flush()
}
