package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != keySize {
		t.Fatalf("key length = %d, want %d", len(key), keySize)
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, key2) {
		t.Fatal("two generated keys should not be equal")
	}
}

func TestSaveLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "key")

	key, _ := GenerateKey()
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file permissions = %o, want 0600", perm)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, loaded) {
		t.Fatal("loaded key does not match saved key")
	}
}

func TestLoadKey_InvalidSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	os.WriteFile(path, []byte("too-short"), 0600)

	_, err := LoadKey(path)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestLoadKey_NotFound(t *testing.T) {
	_, err := LoadKey("/nonexistent/path/key")
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := GenerateKey()

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"json", []byte(`{"project":{"KEY":"value"}}`)},
		{"binary", bytes.Repeat([]byte{0x00, 0xFF}, 512)},
		{"large", bytes.Repeat([]byte("secret-data\n"), 10000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Equal(ciphertext, tt.plaintext) && len(tt.plaintext) > 0 {
				t.Fatal("ciphertext should differ from plaintext")
			}

			decrypted, err := Decrypt(ciphertext, key)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Fatalf("decrypted = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEncrypt_UniqueNonce(t *testing.T) {
	key, _ := GenerateKey()
	plaintext := []byte("same data")

	c1, _ := Encrypt(plaintext, key)
	c2, _ := Encrypt(plaintext, key)

	if bytes.Equal(c1, c2) {
		t.Fatal("encrypting the same plaintext twice should produce different ciphertext (unique nonce)")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	ciphertext, _ := Encrypt([]byte("secret"), key1)

	_, err := Decrypt(ciphertext, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateKey()
	ciphertext, _ := Encrypt([]byte("secret"), key)

	// flip a byte in the ciphertext (after the nonce)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	_, err := Decrypt(tampered, key)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key, _ := GenerateKey()
	_, err := Decrypt([]byte("short"), key)
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than nonce")
	}
}
