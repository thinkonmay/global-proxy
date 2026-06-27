package mail

import (
	"context"

	"github.com/google/uuid"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// Publish enqueues a mail job on the bus. When msg.RequestID is empty a new id
// is generated and returned implicitly via the published message.
func Publish(ctx context.Context, b bus.Client, msg model.MailJobMsg) error {
	if msg.RequestID == "" {
		msg.RequestID = uuid.NewString()
	}
	if msg.Email == "" {
		return ErrMissingEmail
	}
	return bus.Publish(ctx, b, model.TopicMailJob, msg)
}
