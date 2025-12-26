package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
)

// RequestPayload defines the expected JSON structure
type RequestPayload struct {
	Content    string `json:"content"`
	PrivateKey string `json:"private_key"`
}

// ResponsePayload defines the JSON response structure
type ResponsePayload struct {
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	http.HandleFunc("/sign-rsa", signRSAHandler)

	port := ":8080"
	fmt.Printf("Server listening on port %s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func signRSAHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON body
	var payload RequestPayload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, &payload); err != nil {
		writeJSONError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if payload.Content == "" || payload.PrivateKey == "" {
		writeJSONError(w, "Missing content or private_key", http.StatusBadRequest)
		return
	}

	// Perform Signing
	signature, err := signPKCS1v15(payload.Content, payload.PrivateKey)
	if err != nil {
		log.Printf("Signing error: %v", err)
		writeJSONError(w, fmt.Sprintf("Signing failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Return Success Response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ResponsePayload{
		Signature: signature,
	})
}

// signPKCS1v15 signs the content using SHA256 and PKCS#1 v1.5 padding
func signPKCS1v15(content, pemKey string) (string, error) {
	// 1. Decode the PEM block
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", errors.New("failed to parse PEM block containing the key")
	}

	// 2. Parse the Private Key
	// Try PKCS#8 first (standard), then PKCS#1
	var privateKey *rsa.PrivateKey
	var err error

	// Attempt PKCS#8
	if key, err8 := x509.ParsePKCS8PrivateKey(block.Bytes); err8 == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("found key but it is not an RSA private key")
		}
	} else {
		// Attempt PKCS#1
		if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return "", errors.New("failed to parse private key (tried PKCS#8 and PKCS#1)")
		}
	}

	// 3. Hash the content
	hashed := sha256.Sum256([]byte(content))

	// 4. Sign
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	// 5. Encode to Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ResponsePayload{
		Error: message,
	})
}
