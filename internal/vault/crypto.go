package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

const keySize = 32 // AES-256

func GenerateKey() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return key, nil
}

func SaveKey(path string, key []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.WriteFile(path, key, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

func LoadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if len(key) != keySize {
		return nil, errors.New("invalid key size")
	}
	return key, nil
}

func Encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// nonce is prepended to ciphertext
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

const (
	scryptN      = 1 << 17
	scryptR      = 8
	scryptP      = 1
	saltSize     = 16
	shareCodeLen = 12 // raw bytes → 20 base32 chars → formatted as XXXX-XXXX-XXXX-XXXX-XXXX
)

// GenerateShareCode creates a random human-readable share code.
func GenerateShareCode() (string, error) {
	raw := make([]byte, shareCodeLen)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate share code: %w", err)
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return formatCode(encoded), nil
}

func formatCode(s string) string {
	var result []byte
	for i, c := range []byte(s) {
		if i > 0 && i%4 == 0 {
			result = append(result, '-')
		}
		result = append(result, c)
	}
	return string(result)
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// EncryptWithPassphrase encrypts data using a passphrase via scrypt + AES-256-GCM.
// Output format: [16 bytes salt][12 bytes nonce][ciphertext + GCM tag]
func EncryptWithPassphrase(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	// prepend salt to the encrypted output (which already has nonce prepended)
	result := make([]byte, 0, saltSize+len(ciphertext))
	result = append(result, salt...)
	result = append(result, ciphertext...)
	return result, nil
}

// DecryptWithPassphrase decrypts data that was encrypted with EncryptWithPassphrase.
func DecryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	if len(data) < saltSize {
		return nil, errors.New("share file too short")
	}

	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}

	return Decrypt(ciphertext, key)
}
