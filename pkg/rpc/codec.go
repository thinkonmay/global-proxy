package rpc

import "encoding/json"

type Request struct {
	RPC         string          `json:"rpc"`
	Issuer      string          `json:"issuer"`
	Args        json.RawMessage `json:"args"`
	ResponseKey string          `json:"responseKey"`
}

type ResponseEnvelope struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error json.RawMessage `json:"error,omitempty"`
}

type ArgsEmail struct {
	Email  *string `json:"email"`
	PEmail *string `json:"p_email"`
}

func Shuffle(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for i := range result {
		b := result[i]
		var reversed byte
		for j := 0; j < 8; j++ {
			reversed = (reversed << 1) | ((b >> j) & 1)
		}
		result[i] = reversed ^ byte((i*127)&0xff)
	}
	for i := range result {
		b := result[i]
		result[i] = ((b & 0x0f) << 4) | ((b & 0xf0) >> 4)
	}
	for i := 0; i < len(result)-1; i += 2 {
		result[i], result[i+1] = result[i+1], result[i]
	}
	return result
}

func Unshuffle(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for i := 0; i < len(result)-1; i += 2 {
		result[i], result[i+1] = result[i+1], result[i]
	}
	for i := range result {
		b := result[i]
		result[i] = ((b & 0x0f) << 4) | ((b & 0xf0) >> 4)
	}
	for i := range result {
		b := result[i] ^ byte((i*127)&0xff)
		var original byte
		for j := 0; j < 8; j++ {
			original = (original << 1) | ((b >> j) & 1)
		}
		result[i] = original
	}
	return result
}

func DecodeRPC(wire []byte, password1 string) (*Request, error) {
	if password1 == "" {
		password1 = DefaultPassword1()
	}
	unshuffled := Unshuffle(wire)
	var req Request
	if err := DecryptJSON(unshuffled, PasswordL2(password1), &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// EncodeRPCRequest encrypts and shuffles a legacy RPC request (tests only).
func EncodeRPCRequest(req Request, password1 string) ([]byte, error) {
	if password1 == "" {
		password1 = DefaultPassword1()
	}
	wire, err := EncryptJSON(req, PasswordL2(password1))
	if err != nil {
		return nil, err
	}
	return Shuffle(wire), nil
}

// DecodeRPCResponse decrypts an encrypted RPC response body.
func DecodeRPCResponse(wire []byte, responseKey string, dest *ResponseEnvelope) error {
	return DecryptJSON(Unshuffle(wire), PasswordL2(responseKey), dest)
}

func EncodeRPCResponse(body ResponseEnvelope, responseKey string) ([]byte, error) {
	wire, err := EncryptJSON(body, PasswordL2(responseKey))
	if err != nil {
		return nil, err
	}
	return Shuffle(wire), nil
}

func RequestEmail(args json.RawMessage) (string, bool) {
	var a ArgsEmail
	if len(args) == 0 {
		return "", false
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return "", false
	}
	if a.Email != nil && *a.Email != "" {
		return *a.Email, true
	}
	if a.PEmail != nil && *a.PEmail != "" {
		return *a.PEmail, true
	}
	return "", false
}
