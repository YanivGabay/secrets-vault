package vault

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	configFile     = "config.json"
	dropInfoPrefix = "vault-drop-v1:"
)

type Config struct {
	RelayURL string `json:"relay_url"`
}

func LoadConfig(vaultDir string) (*Config, error) {
	data, err := os.ReadFile(filepath.Join(vaultDir, configFile))
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	return &c, json.Unmarshal(data, &c)
}

func SaveConfig(vaultDir string, c *Config) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(vaultDir, configFile), data, 0600)
}

// PublishPubKey uploads a public key to the relay's key registry.
func PublishPubKey(relayURL, username, pubkey string) error {
	url := strings.TrimRight(relayURL, "/") + "/k/" + username
	req, err := http.NewRequest("PUT", url, strings.NewReader(pubkey))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("relay unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("publish failed %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// FetchPubKey retrieves a public key from the relay's key registry.
func FetchPubKey(relayURL, username string) (string, error) {
	url := strings.TrimRight(relayURL, "/") + "/k/" + username
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("relay unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("no key published for %q — they need to run: vault pubkey --publish --as %s", username, username)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch failed %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// DeriveMailbox computes a deterministic mailbox ID from the ECDH shared secret
// between sender and recipient, bucketed by day for forward privacy.
func DeriveMailbox(senderPriv *ecdh.PrivateKey, recipientPub *ecdh.PublicKey) (string, error) {
	shared, err := senderPriv.ECDH(recipientPub)
	if err != nil {
		return "", fmt.Errorf("ECDH: %w", err)
	}

	// Day bucket for forward privacy
	day := time.Now().UTC().Format("2006-01-02")

	info := []byte(dropInfoPrefix + day)
	hk := hkdf.New(sha256.New, shared, nil, info)
	id := make([]byte, 32)
	if _, err := io.ReadFull(hk, id); err != nil {
		return "", fmt.Errorf("HKDF: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(id), nil
}

// DeriveMailboxForDate computes the mailbox ID for a specific date.
func DeriveMailboxForDate(senderPriv *ecdh.PrivateKey, recipientPub *ecdh.PublicKey, date string) (string, error) {
	shared, err := senderPriv.ECDH(recipientPub)
	if err != nil {
		return "", fmt.Errorf("ECDH: %w", err)
	}

	info := []byte(dropInfoPrefix + date)
	hk := hkdf.New(sha256.New, shared, nil, info)
	id := make([]byte, 32)
	if _, err := io.ReadFull(hk, id); err != nil {
		return "", fmt.Errorf("HKDF: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(id), nil
}

// DropSend encrypts and uploads a share to the relay.
func DropSend(relayURL string, mailbox string, blob []byte) error {
	url := strings.TrimRight(relayURL, "/") + "/m/" + mailbox
	req, err := http.NewRequest("PUT", url, bytes.NewReader(blob))
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("relay unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("relay error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// DropReceive downloads and burns a share from the relay.
// Returns nil, nil if the mailbox is empty (no drop waiting).
func DropReceive(relayURL string, mailbox string) ([]byte, error) {
	url := strings.TrimRight(relayURL, "/") + "/m/" + mailbox
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("relay unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("relay error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return io.ReadAll(resp.Body)
}
