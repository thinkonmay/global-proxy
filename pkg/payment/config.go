package payment

import (
	gwconfig "github.com/thinkonmay/global-proxy/api/config"
)

// ConfigFromGateway maps gateway YAML/env payment settings to the worker service config.
func ConfigFromGateway(p gwconfig.Payment) providerConfig {
	return providerConfig{
		PayOS: payOSConfig{
			ClientID:     p.PayOS.ClientID,
			ClientSecret: p.PayOS.ClientSecret,
			ChecksumKey:  p.PayOS.ChecksumKey,
		},
		Stripe: stripeConfig{
			SecretKey: p.Stripe.SecretKey,
		},
		PayerMax: payerMaxConfig{
			AppID:      p.PayerMax.AppID,
			MerchantNo: p.PayerMax.MerchantNo,
			BaseURL:    p.PayerMax.BaseURL,
			PrivateKey: p.PayerMax.PrivateKey,
			PublicKey:  p.PayerMax.PublicKey,
		},
		Payssion: payssionConfig{
			APIKey:    p.Payssion.APIKey,
			PMID:      p.Payssion.PMID,
			SecretKey: p.Payssion.SecretKey,
			Link:      p.Payssion.Link,
		},
	}
}
