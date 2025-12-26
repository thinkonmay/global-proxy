package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// RequestPayload represents the incoming JSON body
type RequestPayload struct {
	Content    string `json:"content"`
	PrivateKey string `json:"private_key"` // Expects Raw Base64 PKCS#8 String (No PEM headers)
}

// ResponsePayload represents the outgoing JSON body
type ResponsePayload struct {
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	http.HandleFunc("/sign-rsa", signHandler)

	port := ":8080"
	log.Printf("PayerMax Signing API (Java logic) listening on port %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Method Check
	if r.Method != http.MethodPost {
		writeJSONResponse(w, ResponsePayload{Error: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	// 2. Read Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONResponse(w, ResponsePayload{Error: "Failed to read body"}, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// 3. Parse JSON
	var payload RequestPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		writeJSONResponse(w, ResponsePayload{Error: "Invalid JSON payload"}, http.StatusBadRequest)
		return
	}

	// 4. Validate Inputs
	if payload.Content == "" || payload.PrivateKey == "" {
		writeJSONResponse(w, ResponsePayload{Error: "Missing content or private_key"}, http.StatusBadRequest)
		return
	}

	// 5. Perform Signing (Using Java RsaUtils Logic)
	signature, err := SignForRSA(payload.Content, payload.PrivateKey)
	if err != nil {
		log.Printf("Signing Error: %v", err)
		writeJSONResponse(w, ResponsePayload{Error: fmt.Sprintf("Signing failed: %v", err)}, http.StatusBadRequest)
		return
	}

	// 6. Return Success
	writeJSONResponse(w, ResponsePayload{Signature: signature}, http.StatusOK)
}

// SignForRSA implements the exact logic of com.payermax.sdk.utils.RsaUtils.signForRSA
// It expects a Base64 encoded PKCS#8 private key string.
func SignForRSA(body string, privateKeyBase64 string) (string, error) {
	// 1. Decode Base64 string to bytes
	// Java: Base64.getDecoder().decode(privateKey)
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key base64: %w", err)
	}

	// 2. Parse PKCS#8 Private Key
	// Java: new PKCS8EncodedKeySpec(bytes) -> keyFactory.generatePrivate(priPKCS8)
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is PKCS#8 but not an RSA private key")
	}

	// 3. Hash the body (SHA256)
	// Java: body.getBytes(charSet) -> UTF-8 implied
	hashed := sha256.Sum256([]byte(body))

	// 4. Sign (SHA256WithRSA)
	// Java: Signature.getInstance("SHA256WithRSA")
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("rsa signing failed: %w", err)
	}

	// 5. Encode result to Base64
	// Java: Base64.getEncoder().encodeToString(signed)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func writeJSONResponse(w http.ResponseWriter, payload ResponsePayload, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(payload)
}
