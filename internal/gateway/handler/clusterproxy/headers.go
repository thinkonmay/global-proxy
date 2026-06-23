package clusterproxy

const (
	InternalHeader     = "X-Thinkmay-Gateway-Internal"
	SecretHeader       = "X-Thinkmay-Gateway-Secret"
	UserEmailHeader    = "X-Thinkmay-User-Email"
	DefaultTimeout     = 120
	SSETimeoutSeconds  = 0 // no client timeout — long-lived SSE
)
