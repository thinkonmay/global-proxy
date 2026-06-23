package model

import "testing"

func TestPaymentTopicName(t *testing.T) {
	if TopicPaymentEvent.Name != "billing.payment.event" {
		t.Fatalf("topic = %s", TopicPaymentEvent.Name)
	}
}
