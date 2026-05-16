package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// platformKey is the shared secret between scanner and platform.
// Both must have the SAME key. Change this before production.
// The key is derived via SHA-256 so any string works.
const platformSecret = "Securthy-HealthGuard-DZ-2024-Platform-Key-v1"

func getPlatformKey() []byte {
	hash := sha256.Sum256([]byte(platformSecret))
	return hash[:]
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Output is base64-encoded: nonce(12) + ciphertext + tag(16)
func Encrypt(plaintext []byte) (string, error) {
	key := getPlatformKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
func Decrypt(encoded string) ([]byte, error) {
	key := getPlatformKey()

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// EncryptFile encrypts a file and writes the result.
// The output file has .sec extension and can only be decrypted by the platform.
func EncryptReport(content []byte) ([]byte, error) {
	encrypted, err := Encrypt(content)
	if err != nil {
		return nil, err
	}

	// Add header so platform knows it's a Securthy report
	header := []byte("SECURTHY-REPORT-V1\n")
	return append(header, []byte(encrypted)...), nil
}
