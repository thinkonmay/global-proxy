package validator

import "testing"

func TestValidateRequiredURL(t *testing.T) {
	type sample struct {
		URL string `validate:"required,url"`
	}
	if err := Validate(&sample{URL: "https://example.com"}); err != nil {
		t.Fatalf("valid url: %v", err)
	}
	if err := Validate(&sample{}); err == nil {
		t.Fatal("expected validation error for missing url")
	}
}

func TestValidateIso4217(t *testing.T) {
	type money struct {
		Currency string `validate:"iso4217"`
	}
	if err := Validate(&money{Currency: "USD"}); err != nil {
		t.Fatalf("USD: %v", err)
	}
	if err := Validate(&money{Currency: "NOTREAL"}); err == nil {
		t.Fatal("expected invalid currency error")
	}
}
