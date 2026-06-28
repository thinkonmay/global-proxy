// Package llmtrace provides structured debug logging for LiteLLM chat/completions calls.
package llmtrace

import (
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

const (
	FeatureAISearch   = "ai_search"
	FeaturePersonaCDP = "persona_cdp"
)

const defaultPreviewMax = 512

// CompletionSummary captures high-signal fields from a chat completion response.
type CompletionSummary struct {
	FinishReason  string
	ToolCallNames []string
	ContentLen    int
	ReasoningLen  int
	ChoiceCount   int
}

func TruncateString(s string, max int) string {
	if max <= 0 {
		max = defaultPreviewMax
	}
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func TruncateBytes(b []byte, max int) string {
	return TruncateString(string(b), max)
}

func SummarizeCompletion(raw []byte) CompletionSummary {
	var completion struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content          *string `json:"content"`
				ReasoningContent *string `json:"reasoning_content"`
				ToolCalls        []struct {
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	out := CompletionSummary{}
	if err := json.Unmarshal(raw, &completion); err != nil {
		return out
	}
	out.ChoiceCount = len(completion.Choices)
	if len(completion.Choices) == 0 {
		return out
	}
	choice := completion.Choices[0]
	out.FinishReason = choice.FinishReason
	if choice.Message.Content != nil {
		out.ContentLen = len(strings.TrimSpace(*choice.Message.Content))
	}
	if choice.Message.ReasoningContent != nil {
		out.ReasoningLen = len(strings.TrimSpace(*choice.Message.ReasoningContent))
	}
	for _, tc := range choice.Message.ToolCalls {
		name := strings.TrimSpace(tc.Function.Name)
		if name != "" {
			out.ToolCallNames = append(out.ToolCallNames, name)
		}
	}
	return out
}

func BodyMeta(body map[string]any) (model string, messages, tools int) {
	if body == nil {
		return "", 0, 0
	}
	if v, ok := body["model"].(string); ok {
		model = v
	}
	if msgs, ok := body["messages"].([]any); ok {
		messages = len(msgs)
	} else if msgs, ok := body["messages"].([]map[string]any); ok {
		messages = len(msgs)
	}
	if t, ok := body["tools"].([]any); ok {
		tools = len(t)
	}
	return model, messages, tools
}

func LogCallStart(feature, model string, round int, messages, tools int, attrs ...any) {
	args := []any{
		"feature", feature,
		"model", model,
		"round", round,
		"messages", messages,
		"tools", tools,
	}
	args = append(args, attrs...)
	slog.Debug("llm call start", args...)
}

func LogCallOK(feature string, round int, elapsed time.Duration, summary CompletionSummary, attrs ...any) {
	args := []any{
		"feature", feature,
		"round", round,
		"elapsed_ms", elapsed.Milliseconds(),
		"finish_reason", summary.FinishReason,
		"tool_calls", summary.ToolCallNames,
		"content_len", summary.ContentLen,
		"reasoning_len", summary.ReasoningLen,
		"choices", summary.ChoiceCount,
	}
	args = append(args, attrs...)
	slog.Debug("llm call ok", args...)
}

func LogCallHTTPError(feature string, round int, elapsed time.Duration, status int, body []byte, attrs ...any) {
	args := []any{
		"feature", feature,
		"round", round,
		"elapsed_ms", elapsed.Milliseconds(),
		"status", status,
		"body", TruncateBytes(body, defaultPreviewMax),
	}
	args = append(args, attrs...)
	slog.Warn("llm call http error", args...)
}

func LogCallTransportError(feature string, round int, err error, attrs ...any) {
	args := []any{
		"feature", feature,
		"round", round,
		"err", err,
	}
	args = append(args, attrs...)
	slog.Warn("llm call transport error", args...)
}

func LogParseError(feature string, round int, err error, raw []byte, attrs ...any) {
	args := []any{
		"feature", feature,
		"round", round,
		"err", err,
		"body", TruncateBytes(raw, defaultPreviewMax),
	}
	args = append(args, attrs...)
	slog.Warn("llm response parse error", args...)
}

func LogDecodeError(feature string, err error, preview string, attrs ...any) {
	args := []any{
		"feature", feature,
		"err", err,
		"preview", TruncateString(preview, defaultPreviewMax),
	}
	args = append(args, attrs...)
	slog.Warn("llm response decode error", args...)
}

func LogToolInvoke(feature string, round int, tool, args string, attrs ...any) {
	a := []any{
		"feature", feature,
		"round", round,
		"tool", tool,
		"args", TruncateString(args, 256),
	}
	a = append(a, attrs...)
	slog.Debug("llm tool invoke", a...)
}

func LogFeatureStart(feature string, attrs ...any) {
	args := append([]any{"feature", feature}, attrs...)
	slog.Debug("llm feature start", args...)
}

func LogFeatureOK(feature string, attrs ...any) {
	args := append([]any{"feature", feature}, attrs...)
	slog.Debug("llm feature ok", args...)
}

func LogFeatureError(feature string, err error, attrs ...any) {
	args := append([]any{"feature", feature, "err", err}, attrs...)
	slog.Warn("llm feature error", args...)
}
