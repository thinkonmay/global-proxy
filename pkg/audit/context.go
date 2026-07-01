package audit

import (
	"context"

	"google.golang.org/grpc/metadata"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyUserEmail
	keyAction
)

const (
	MetadataRequestID = "x-request-id"
)

// WithRequestID stores the correlation id on ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, keyRequestID, id)
}

// RequestID returns the correlation id from ctx, if any.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyRequestID).(string)
	return v
}

// WithUserEmail stores the authenticated user email for audit/trace (server-side only).
func WithUserEmail(ctx context.Context, email string) context.Context {
	if email == "" {
		return ctx
	}
	return context.WithValue(ctx, keyUserEmail, email)
}

// UserEmail returns the user email attached to ctx, if any.
func UserEmail(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyUserEmail).(string)
	return v
}

// WithAction overrides the default http.access action for this request.
func WithAction(ctx context.Context, action string) context.Context {
	if action == "" {
		return ctx
	}
	return context.WithValue(ctx, keyAction, action)
}

// Action returns an explicit action override from ctx, if any.
func Action(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(keyAction).(string)
	return v
}

// OutgoingGRPCMetadata returns outgoing gRPC metadata with request_id when present.
func OutgoingGRPCMetadata(ctx context.Context) context.Context {
	id := RequestID(ctx)
	if id == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, MetadataRequestID, id)
}
