package rpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength   = 16
	ivLength     = 16
	gcmNonceSize = 12 // Web Crypto AES-GCM; wire stores 16 bytes (12 random + pad)
	iterations   = 100000
	keyLength    = 32
	defaultPass1 = "thinkmay protect your data"
)

func PasswordL2(password string) string {
	sum := sha512.Sum512([]byte(password))
	return hex.EncodeToString(sum[:])
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)
}

// EncryptJSON marshals v, encrypts with password (PBKDF2 + AES-GCM), returns salt+iv+ciphertext.
func EncryptJSON(v any, password string) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, ivLength)
	if _, err := io.ReadFull(rand.Reader, iv[:gcmNonceSize]); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, iv[:gcmNonceSize], plain, nil)
	out := make([]byte, 0, saltLength+ivLength+len(sealed))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, sealed...)
	return out, nil
}

// DecryptJSON decrypts wire bytes with password into dest.
func DecryptJSON(wire []byte, password string, dest any) error {
	if len(wire) < saltLength+ivLength+1 {
		return fmt.Errorf("rpc: ciphertext too short")
	}
	salt := wire[:saltLength]
	iv := wire[saltLength : saltLength+ivLength]
	data := wire[saltLength+ivLength:]
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, iv[:gcmNonceSize], data, nil)
	if err != nil {
		return fmt.Errorf("rpc: decrypt: %w", err)
	}
	return json.Unmarshal(plain, dest)
}

func DefaultPassword1() string { return defaultPass1 }
