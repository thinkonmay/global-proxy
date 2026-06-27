package main

import (
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestInitMetricsStackNilWithoutRedis(t *testing.T) {
	stack, err := initMetricsStack(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if stack != nil {
		t.Fatal("expected nil stack when redis url empty")
	}
}
