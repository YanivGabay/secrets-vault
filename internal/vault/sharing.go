package vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
)

const (
	pubkeyPrefix  = "vault1" // human-readable prefix for public keys
	shareV2Magic  = "VAULTSHARE2" // header to distinguish from passphrase-based shares
)

// GenerateIdentity creates an X25519 keypair and saves to the vault directory.
func GenerateIdentity(vaultDir string) error {
	privKeyPath := filepath.Join(vaultDir, "identity")
	pubKeyPath := filepath.Join(vaultDir, "identity.pub")

	// Don't overwrite existing identity
	if _, err := os.Stat(privKeyPath); err == nil {
		return nil
	}

	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	if err := os.WriteFile(privKeyPath, privKey.Bytes(), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	pubEncoded := EncodePubKey(privKey.PublicKey())
	if err := os.WriteFile(pubKeyPath, []byte(pubEncoded+"\n"), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

func EncodePubKey(pub *ecdh.PublicKey) string {
	return pubkeyPrefix + base64.RawStdEncoding.EncodeToString(pub.Bytes())
}

func DecodePubKey(s string) (*ecdh.PublicKey, error) {
	if len(s) < len(pubkeyPrefix) || s[:len(pubkeyPrefix)] != pubkeyPrefix {
		return nil, fmt.Errorf("invalid public key format (expected %s prefix)", pubkeyPrefix)
	}

	raw, err := base64.RawStdEncoding.DecodeString(s[len(pubkeyPrefix):])
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	curve := ecdh.X25519()
	return curve.NewPublicKey(raw)
}

func LoadPrivateKey(vaultDir string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Join(vaultDir, "identity"))
	if err != nil {
		return nil, fmt.Errorf("no identity found — run 'vault init': %w", err)
	}

	curve := ecdh.X25519()
	return curve.NewPrivateKey(data)
}

func LoadPublicKey(vaultDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(vaultDir, "identity.pub"))
	if err != nil {
		return "", fmt.Errorf("no identity found — run 'vault init': %w", err)
	}
	return string(data[:len(data)-1]), nil // trim trailing newline
}

// Recipients are stored in a JSON file in the vault directory.
type Recipients map[string]string // name → encoded public key

func recipientsPath(vaultDir string) string {
	return filepath.Join(vaultDir, "recipients.json")
}

func LoadRecipients(vaultDir string) (Recipients, error) {
	data, err := os.ReadFile(recipientsPath(vaultDir))
	if err != nil {
		if os.IsNotExist(err) {
			return make(Recipients), nil
		}
		return nil, err
	}
	var r Recipients
	return r, json.Unmarshal(data, &r)
}

func SaveRecipients(vaultDir string, r Recipients) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(recipientsPath(vaultDir), data, 0600)
}

// shareV2Header is prepended to public-key encrypted share files.
type shareV2Header struct {
	Magic     string `json:"m"`
	Sender    string `json:"s"` // sender's public key
	Recipient string `json:"r"` // recipient's public key
}

// EncryptForRecipient encrypts data so only the recipient's private key can decrypt it.
// Uses X25519 ECDH to derive a shared secret, then HKDF+AES-256-GCM.
func EncryptForRecipient(plaintext []byte, senderPriv *ecdh.PrivateKey, recipientPub *ecdh.PublicKey) ([]byte, error) {
	// ECDH: derive shared secret
	shared, err := senderPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// HKDF: derive encryption key from shared secret
	encKey, err := deriveHKDF(shared, senderPriv.PublicKey().Bytes(), recipientPub.Bytes())
	if err != nil {
		return nil, err
	}

	// Encrypt with AES-256-GCM
	ciphertext, err := Encrypt(plaintext, encKey)
	if err != nil {
		return nil, err
	}

	// Prepend header
	header := shareV2Header{
		Magic:     shareV2Magic,
		Sender:    EncodePubKey(senderPriv.PublicKey()),
		Recipient: EncodePubKey(recipientPub),
	}
	headerBytes, _ := json.Marshal(header)

	// Format: [4 bytes header length][header JSON][ciphertext]
	headerLen := uint32(len(headerBytes))
	result := make([]byte, 4+len(headerBytes)+len(ciphertext))
	result[0] = byte(headerLen >> 24)
	result[1] = byte(headerLen >> 16)
	result[2] = byte(headerLen >> 8)
	result[3] = byte(headerLen)
	copy(result[4:], headerBytes)
	copy(result[4+len(headerBytes):], ciphertext)

	return result, nil
}

// DecryptFromSender decrypts data that was encrypted with EncryptForRecipient.
func DecryptFromSender(data []byte, recipientPriv *ecdh.PrivateKey) (*shareV2Header, []byte, error) {
	if len(data) < 4 {
		return nil, nil, errors.New("share file too short")
	}

	headerLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+headerLen {
		return nil, nil, errors.New("share file corrupted")
	}

	var header shareV2Header
	if err := json.Unmarshal(data[4:4+headerLen], &header); err != nil {
		return nil, nil, fmt.Errorf("parse share header: %w", err)
	}

	if header.Magic != shareV2Magic {
		return nil, nil, errors.New("not a v2 share file")
	}

	senderPub, err := DecodePubKey(header.Sender)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sender key: %w", err)
	}

	// ECDH: derive same shared secret
	shared, err := recipientPriv.ECDH(senderPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}

	encKey, err := deriveHKDF(shared, senderPub.Bytes(), recipientPriv.PublicKey().Bytes())
	if err != nil {
		return nil, nil, err
	}

	ciphertext := data[4+headerLen:]
	plaintext, err := Decrypt(ciphertext, encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt failed — wrong recipient or corrupted file")
	}

	return &header, plaintext, nil
}

// IsV2ShareFile checks if the data looks like a public-key encrypted share.
func IsV2ShareFile(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	headerLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+headerLen || headerLen > 1024 {
		return false
	}
	var header shareV2Header
	if err := json.Unmarshal(data[4:4+headerLen], &header); err != nil {
		return false
	}
	return header.Magic == shareV2Magic
}

func deriveHKDF(shared, senderPub, recipientPub []byte) ([]byte, error) {
	// info binds the key to both parties
	info := append(append([]byte("vault-share-v2:"), senderPub...), recipientPub...)
	hk := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, fmt.Errorf("HKDF: %w", err)
	}
	return key, nil
}
