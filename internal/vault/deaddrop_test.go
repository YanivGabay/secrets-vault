package vault

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// mockRelay simulates the Cloudflare Worker relay.
func mockRelay() *httptest.Server {
	var mu sync.Mutex
	drops := map[string][]byte{}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mailbox := r.URL.Path[len("/m/"):]
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "PUT":
			data, _ := io.ReadAll(r.Body)
			if len(data) == 0 {
				http.Error(w, "empty", 400)
				return
			}
			if len(data) > 65536 {
				http.Error(w, "too large", 413)
				return
			}
			drops[mailbox] = data
			w.WriteHeader(201)
		case "GET":
			data, ok := drops[mailbox]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			delete(drops, mailbox) // burn on read
			w.Write(data)
		default:
			http.Error(w, "method not allowed", 405)
		}
	}))
}

func TestDeriveMailbox_Deterministic(t *testing.T) {
	alice := generateTestKeypair(t)
	bob := generateTestKeypair(t)

	m1, err := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Fatal("same inputs should produce same mailbox")
	}
}

func TestDeriveMailbox_BothSidesMatch(t *testing.T) {
	alice := generateTestKeypair(t)
	bob := generateTestKeypair(t)

	// Alice sends to Bob: derives with (alice_priv, bob_pub)
	mAlice, _ := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")
	// Bob checks from Alice: derives with (bob_priv, alice_pub)
	mBob, _ := DeriveMailboxForDate(bob, alice.PublicKey(), "2026-08-12")

	if mAlice != mBob {
		t.Fatalf("mailbox mismatch: alice=%s bob=%s", mAlice, mBob)
	}
}

func TestDeriveMailbox_DifferentDays(t *testing.T) {
	alice := generateTestKeypair(t)
	bob := generateTestKeypair(t)

	m1, _ := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")
	m2, _ := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-13")

	if m1 == m2 {
		t.Fatal("different days should produce different mailboxes")
	}
}

func TestDeriveMailbox_DifferentPairs(t *testing.T) {
	alice := generateTestKeypair(t)
	bob := generateTestKeypair(t)
	charlie := generateTestKeypair(t)

	m1, _ := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")
	m2, _ := DeriveMailboxForDate(alice, charlie.PublicKey(), "2026-08-12")

	if m1 == m2 {
		t.Fatal("different pairs should produce different mailboxes")
	}
}

func TestDropSendReceive_RoundTrip(t *testing.T) {
	relay := mockRelay()
	defer relay.Close()

	alice := generateTestKeypair(t)
	bob := generateTestKeypair(t)
	plaintext := []byte(`{"project":"test","secrets":{"KEY":"value"}}`)

	// Alice encrypts for Bob
	blob, err := EncryptForRecipient(plaintext, alice, bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	// Derive mailbox
	mailbox, _ := DeriveMailboxForDate(alice, bob.PublicKey(), "2026-08-12")

	// Send
	if err := DropSend(relay.URL, mailbox, blob); err != nil {
		t.Fatal(err)
	}

	// Bob derives the same mailbox
	bobMailbox, _ := DeriveMailboxForDate(bob, alice.PublicKey(), "2026-08-12")
	if mailbox != bobMailbox {
		t.Fatal("mailbox mismatch")
	}

	// Receive
	received, err := DropReceive(relay.URL, bobMailbox)
	if err != nil {
		t.Fatal(err)
	}
	if received == nil {
		t.Fatal("expected a drop")
	}

	// Decrypt
	_, decrypted, err := DecryptFromSender(received, bob)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDropReceive_BurnOnRead(t *testing.T) {
	relay := mockRelay()
	defer relay.Close()

	mailbox := "test-burn-on-read-mailbox-id-12345"

	// Send
	DropSend(relay.URL, mailbox, []byte("secret-blob"))

	// First read succeeds
	data, err := DropReceive(relay.URL, mailbox)
	if err != nil || data == nil {
		t.Fatal("first read should succeed")
	}

	// Second read should find nothing (burned)
	data, err = DropReceive(relay.URL, mailbox)
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatal("drop should be burned after first read")
	}
}

func TestDropReceive_EmptyMailbox(t *testing.T) {
	relay := mockRelay()
	defer relay.Close()

	data, err := DropReceive(relay.URL, "nonexistent-mailbox-id-99999")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatal("expected nil for empty mailbox")
	}
}

func TestConfig_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	c := &Config{RelayURL: "https://relay.example.com"}
	if err := SaveConfig(dir, c); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RelayURL != "https://relay.example.com" {
		t.Fatalf("relay URL = %q", loaded.RelayURL)
	}
}
