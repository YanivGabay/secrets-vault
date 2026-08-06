package vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
)

func generateTestKeypair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	curve := ecdh.X25519()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestGenerateIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateIdentity(dir); err != nil {
		t.Fatal(err)
	}

	pubkey, err := LoadPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pubkey, pubkeyPrefix) {
		t.Fatalf("pubkey should start with %s: %s", pubkeyPrefix, pubkey)
	}

	privKey, err := LoadPrivateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if privKey == nil {
		t.Fatal("private key should not be nil")
	}
}

func TestGenerateIdentity_Idempotent(t *testing.T) {
	dir := t.TempDir()
	GenerateIdentity(dir)

	pub1, _ := LoadPublicKey(dir)
	GenerateIdentity(dir) // should not overwrite
	pub2, _ := LoadPublicKey(dir)

	if pub1 != pub2 {
		t.Fatal("second GenerateIdentity overwrote the first keypair")
	}
}

func TestEncodeDecode_PubKey(t *testing.T) {
	key := generateTestKeypair(t)
	encoded := EncodePubKey(key.PublicKey())

	if !strings.HasPrefix(encoded, pubkeyPrefix) {
		t.Fatalf("encoded should start with %s: %s", pubkeyPrefix, encoded)
	}

	decoded, err := DecodePubKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if !decoded.Equal(key.PublicKey()) {
		t.Fatal("decoded key does not match original")
	}
}

func TestDecodePubKey_Invalid(t *testing.T) {
	_, err := DecodePubKey("garbage")
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestEncryptDecryptForRecipient(t *testing.T) {
	sender := generateTestKeypair(t)
	recipient := generateTestKeypair(t)
	plaintext := []byte(`{"project":"test","secrets":{"KEY":"secret-value"}}`)

	ciphertext, err := EncryptForRecipient(plaintext, sender, recipient.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	if !IsV2ShareFile(ciphertext) {
		t.Fatal("should be detected as v2 share file")
	}

	header, decrypted, err := DecryptFromSender(ciphertext, recipient)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	if header.Sender != EncodePubKey(sender.PublicKey()) {
		t.Fatal("wrong sender in header")
	}
	if header.Recipient != EncodePubKey(recipient.PublicKey()) {
		t.Fatal("wrong recipient in header")
	}
}

func TestDecryptForRecipient_WrongKey(t *testing.T) {
	sender := generateTestKeypair(t)
	recipient := generateTestKeypair(t)
	wrongRecipient := generateTestKeypair(t)

	ciphertext, _ := EncryptForRecipient([]byte("secret"), sender, recipient.PublicKey())

	_, _, err := DecryptFromSender(ciphertext, wrongRecipient)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

func TestIsV2ShareFile(t *testing.T) {
	if IsV2ShareFile([]byte("short")) {
		t.Fatal("short data should not be v2")
	}
	if IsV2ShareFile([]byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatal("non-JSON header should not be v2")
	}

	// Passphrase-encrypted data should not be v2
	ct, _ := EncryptWithPassphrase([]byte("test"), "code")
	if IsV2ShareFile(ct) {
		t.Fatal("passphrase-encrypted data should not be v2")
	}
}

func TestRecipients_SaveLoad(t *testing.T) {
	dir := t.TempDir()

	r := Recipients{"alice": "vault1abc123", "bob": "vault1xyz789"}
	if err := SaveRecipients(dir, r); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadRecipients(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["alice"] != "vault1abc123" || loaded["bob"] != "vault1xyz789" {
		t.Fatalf("recipients mismatch: %v", loaded)
	}
}

func TestRecipients_EmptyOnMissing(t *testing.T) {
	dir := t.TempDir()
	r, err := LoadRecipients(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(r) != 0 {
		t.Fatal("expected empty recipients for new dir")
	}
}
