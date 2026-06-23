package model

import (
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/payment"
)

type PaymentMsg = struct {
	payment.Event

	Provider string // provider name (e.g. "stripe")
}

var TopicPayment = bus.NewTopic[PaymentMsg]("billing.payment.event")
