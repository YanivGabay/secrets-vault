package main

import (
	"bufio"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/yaniv242/secrets-vault/internal/clipboard"
	syncpkg "github.com/yaniv242/secrets-vault/internal/sync"
	"github.com/yaniv242/secrets-vault/internal/vault"
)

func vaultDir() string {
	if dir := os.Getenv("VAULT_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secrets-vault")
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	v := vault.New(vaultDir())

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(v)
	case "add":
		err = cmdAdd(v)
	case "rm", "remove":
		err = cmdRemove(v)
	case "list", "ls":
		err = cmdList(v)
	case "get":
		err = cmdGet(v)
	case "sync":
		err = cmdSync(v)
	case "import":
		err = cmdImport(v)
	case "export":
		err = cmdExport(v)
	case "import-share":
		err = cmdImportShare(v)
	case "pubkey":
		err = cmdPubKey(v)
	case "add-recipient":
		err = cmdAddRecipient(v)
	case "list-recipients":
		err = cmdListRecipients(v)
	case "send":
		err = cmdSend(v)
	case "receive":
		err = cmdReceive(v)
	case "relay":
		err = cmdRelay(v)
	case "onboard":
		err = cmdOnboard(v)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `secrets-vault — encrypted secrets manager

Commands:
  init                          Create a new vault
  add <project> <KEY> [flags]   Add a secret (default: from clipboard)
  get <project> <KEY>           Output secret value to stdout (for piping)
  rm  <project> <KEY>           Remove a secret
  list [project]                List projects or keys
  sync <project> <target>       Sync to target (github, cloudflare, env)
  sync <dir>                    Sync using .vault.json manifest
  import <project> <.env path>  Import secrets from .env file
  export <project> [flags]      Export encrypted share file
  import-share <file>           Import from a .vault-share file
  pubkey                        Print your public key
  add-recipient <name> <key>    Save a recipient's public key
  list-recipients               List saved recipients
  send <project> --to <name>    Dead-drop secrets to a recipient
  receive                       Check dead-drops and import waiting secrets
  relay set-url <url>           Set your relay URL
  onboard [dir]                 Auto-detect .env files, import, create .vault.json

Add flags:
  --stdin                       Read value from stdin pipe
  --prompt                      Prompt for value in terminal (hidden input)

Sync flags:
  --repo owner/repo             GitHub repo to sync to
  --name worker-name            Cloudflare Worker name to target
  --dir /path                   Project directory for cloudflare/env sync
  --keys KEY1,KEY2              Only sync these keys (default: all)

Export flags:
  --to <name|pubkey>            Recipient (name from add-recipient, or raw pubkey)
  --keys KEY1,KEY2              Only export these keys
  --out <file>                  Output file (default: <project>.vault-share)
  (without --to: passphrase mode, prints share code)

Import-share flags:
  --code XXXX-XXXX-...          Share code for passphrase-mode files
  (public-key mode files auto-decrypt with your identity)`)
}

func cmdInit(v *vault.Vault) error {
	if err := v.Init(); err != nil {
		return err
	}
	pubkey, _ := vault.LoadPublicKey(v.Dir())
	fmt.Println("Vault initialized at", vaultDir())
	fmt.Println("Your public key:", pubkey)
	return nil
}

func cmdPubKey(v *vault.Vault) error {
	if err := vault.GenerateIdentity(v.Dir()); err != nil {
		return err
	}
	pubkey, err := vault.LoadPublicKey(v.Dir())
	if err != nil {
		return err
	}

	if hasFlag("--publish") {
		config, err := vault.LoadConfig(v.Dir())
		if err != nil {
			return err
		}
		if config.RelayURL == "" {
			return fmt.Errorf("no relay configured — run: vault relay set-url <url>")
		}

		username := flagValue("--as")
		if username == "" {
			return fmt.Errorf("usage: vault pubkey --publish --as <username>")
		}

		if err := vault.PublishPubKey(config.RelayURL, username, pubkey); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Published as %s\n", username)
	}

	fmt.Print(pubkey)
	return nil
}

func cmdAddRecipient(v *vault.Vault) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: vault add-recipient <name> [pubkey]\n       vault add-recipient <name>  (fetches from relay)")
	}
	name := os.Args[2]

	var pubkey string
	if len(os.Args) >= 4 {
		pubkey = os.Args[3]
	} else {
		// Fetch from relay
		config, err := vault.LoadConfig(v.Dir())
		if err != nil {
			return err
		}
		if config.RelayURL == "" {
			return fmt.Errorf("no relay configured — run: vault relay set-url <url>")
		}
		fetched, err := vault.FetchPubKey(config.RelayURL, name)
		if err != nil {
			return fmt.Errorf("fetch key for %s: %w", name, err)
		}
		pubkey = fetched
		fmt.Fprintf(os.Stderr, "Fetched key for %s from relay\n", name)
	}

	if _, err := vault.DecodePubKey(pubkey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	recipients, err := vault.LoadRecipients(v.Dir())
	if err != nil {
		return err
	}
	recipients[name] = pubkey
	if err := vault.SaveRecipients(v.Dir(), recipients); err != nil {
		return err
	}

	fmt.Printf("Added recipient %s (%s)\n", name, pubkey)
	return nil
}

func cmdListRecipients(v *vault.Vault) error {
	recipients, err := vault.LoadRecipients(v.Dir())
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		fmt.Println("(no recipients)")
		return nil
	}
	for name, key := range recipients {
		fmt.Printf("%s  %s\n", name, key)
	}
	return nil
}

func cmdSend(v *vault.Vault) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: vault send <project> --to <name> [--keys KEY1,KEY2]")
	}
	project := os.Args[2]
	toName := flagValue("--to")
	if toName == "" {
		return fmt.Errorf("--to <recipient> is required")
	}

	config, err := vault.LoadConfig(v.Dir())
	if err != nil {
		return err
	}
	if config.RelayURL == "" {
		return fmt.Errorf("no relay configured — run: vault relay set-url <url>")
	}

	secrets, err := v.GetProject(project)
	if err != nil {
		return err
	}

	if keysFlag := flagValue("--keys"); keysFlag != "" {
		secrets = syncpkg.FilterKeys(secrets, strings.Split(keysFlag, ","))
		if len(secrets) == 0 {
			return fmt.Errorf("no matching keys for filter")
		}
	}

	recipientKey, err := resolveRecipient(v, toName)
	if err != nil {
		return err
	}

	if err := vault.GenerateIdentity(v.Dir()); err != nil {
		return err
	}
	senderPriv, err := vault.LoadPrivateKey(v.Dir())
	if err != nil {
		return err
	}

	// Encrypt the payload
	payload := SharePayload{Project: project, Secrets: secrets}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	blob, err := vault.EncryptForRecipient(plaintext, senderPriv, recipientKey)
	if err != nil {
		return err
	}

	// Derive mailbox and send
	mailbox, err := vault.DeriveMailbox(senderPriv, recipientKey)
	if err != nil {
		return err
	}

	if err := vault.DropSend(config.RelayURL, mailbox, blob); err != nil {
		return err
	}

	keyNames := make([]string, 0, len(secrets))
	for k := range secrets {
		keyNames = append(keyNames, k)
	}
	slices.Sort(keyNames)

	fmt.Printf("Dropped %d keys from %s for %s\n", len(secrets), project, toName)
	fmt.Printf("Keys: %s\n", strings.Join(keyNames, ", "))
	fmt.Printf("Burns on pickup, expires in 24h.\n")
	fmt.Printf("%s just runs: vault receive\n", toName)
	return nil
}

func cmdReceive(v *vault.Vault) error {
	config, err := vault.LoadConfig(v.Dir())
	if err != nil {
		return err
	}
	if config.RelayURL == "" {
		return fmt.Errorf("no relay configured — run: vault relay set-url <url>")
	}

	if err := vault.GenerateIdentity(v.Dir()); err != nil {
		return err
	}
	myPriv, err := vault.LoadPrivateKey(v.Dir())
	if err != nil {
		return err
	}

	recipients, err := vault.LoadRecipients(v.Dir())
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured — nobody can send you drops")
	}

	// Check today and yesterday (clock skew tolerance)
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	dates := []string{today, yesterday}

	found := 0
	for name, pubkeyStr := range recipients {
		recipientPub, err := vault.DecodePubKey(pubkeyStr)
		if err != nil {
			continue
		}

		for _, date := range dates {
			// Derive the mailbox from THEIR perspective (they sent TO us)
			mailbox, err := vault.DeriveMailboxForDate(myPriv, recipientPub, date)
			if err != nil {
				continue
			}

			blob, err := vault.DropReceive(config.RelayURL, mailbox)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed checking drop from %s: %v\n", name, err)
				continue
			}
			if blob == nil {
				continue
			}

			// Decrypt
			_, plaintext, err := vault.DecryptFromSender(blob, myPriv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed decrypting drop from %s: %v\n", name, err)
				continue
			}

			var payload SharePayload
			if err := json.Unmarshal(plaintext, &payload); err != nil {
				fmt.Fprintf(os.Stderr, "warning: invalid payload from %s: %v\n", name, err)
				continue
			}

			count := 0
			for key, value := range payload.Secrets {
				if err := v.Add(payload.Project, key, value); err != nil {
					return fmt.Errorf("import %s: %w", key, err)
				}
				count++
			}

			keyNames := make([]string, 0, len(payload.Secrets))
			for k := range payload.Secrets {
				keyNames = append(keyNames, k)
			}
			slices.Sort(keyNames)

			fmt.Printf("Pickup from %s: %s (%d keys: %s)\n", name, payload.Project, count, strings.Join(keyNames, ", "))
			fmt.Println("Imported into vault. Drop burned.")
			found++
		}
	}

	if found == 0 {
		fmt.Println("No drops waiting.")
	}
	return nil
}

func cmdRelay(v *vault.Vault) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: vault relay set-url <url>")
	}

	switch os.Args[2] {
	case "set-url":
		if len(os.Args) < 4 {
			return fmt.Errorf("usage: vault relay set-url <url>")
		}
		url := os.Args[3]
		config, err := vault.LoadConfig(v.Dir())
		if err != nil {
			return err
		}
		config.RelayURL = url
		if err := vault.SaveConfig(v.Dir(), config); err != nil {
			return err
		}
		fmt.Printf("Relay URL set to %s\n", url)
		return nil
	case "status":
		config, err := vault.LoadConfig(v.Dir())
		if err != nil {
			return err
		}
		if config.RelayURL == "" {
			fmt.Println("No relay configured")
			return nil
		}
		fmt.Printf("Relay: %s\n", config.RelayURL)
		return nil
	default:
		return fmt.Errorf("unknown relay command: %s (use: set-url, status)", os.Args[2])
	}
}

func cmdAdd(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault add <project> <KEY> [--stdin|--prompt]")
	}
	project, key := os.Args[2], os.Args[3]

	var value string
	var err error

	switch {
	case hasFlag("--stdin"):
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return fmt.Errorf("read stdin: %w", readErr)
		}
		value = strings.TrimRight(string(data), "\r\n")
	case hasFlag("--prompt"):
		fmt.Fprintf(os.Stderr, "Enter value for %s: ", key)
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			value = scanner.Text()
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return fmt.Errorf("read input: %w", scanErr)
		}
	default:
		value, err = clipboard.Read()
		if err != nil {
			return fmt.Errorf("read clipboard: %w", err)
		}
		defer func() {
			if clearErr := clipboard.Clear(); clearErr != nil {
				slog.Warn("failed to clear clipboard", "error", clearErr)
			}
		}()
	}

	if value == "" {
		return fmt.Errorf("empty value")
	}

	if err := v.Add(project, key, value); err != nil {
		return err
	}

	fmt.Printf("Added %s to %s\n", key, project)
	return nil
}

func cmdGet(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault get <project> <KEY>")
	}
	project, key := os.Args[2], os.Args[3]

	value, err := v.Get(project, key)
	if err != nil {
		return err
	}

	// Raw value to stdout — no newline, so piping is clean
	fmt.Print(value)
	return nil
}

func cmdRemove(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault rm <project> <KEY>")
	}
	project, key := os.Args[2], os.Args[3]

	if err := v.Remove(project, key); err != nil {
		return err
	}

	fmt.Printf("Removed %s from %s\n", key, project)
	return nil
}

func cmdList(v *vault.Vault) error {
	if len(os.Args) >= 3 {
		project := os.Args[2]
		keys, err := v.ListKeys(project)
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}

	projects, err := v.Projects()
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		fmt.Println("(empty vault)")
		return nil
	}

	for _, project := range sortedKeys(projects) {
		keys := projects[project]
		fmt.Printf("%s (%d keys)\n", project, len(keys))
		for _, k := range keys {
			fmt.Printf("  %s\n", k)
		}
	}
	return nil
}

func cmdSync(v *vault.Vault) error {
	// If no target specified, try manifest-based sync
	if len(os.Args) < 4 {
		dir := "."
		if len(os.Args) >= 3 {
			dir = os.Args[2]
		}
		absDir, _ := filepath.Abs(dir)
		return cmdSyncFromManifest(v, absDir)
	}
	project, targetName := os.Args[2], os.Args[3]

	secrets, err := v.GetProject(project)
	if err != nil {
		return err
	}

	// Filter keys if --keys flag is provided
	if keysFlag := flagValue("--keys"); keysFlag != "" {
		secrets = syncpkg.FilterKeys(secrets, strings.Split(keysFlag, ","))
		if len(secrets) == 0 {
			return fmt.Errorf("no matching keys found for filter")
		}
	}

	var target syncpkg.Target
	switch targetName {
	case "github", "gh":
		gh := &syncpkg.GitHub{}
		if repo := flagValue("--repo"); repo != "" {
			gh.Repo = repo
		}
		target = gh
	case "cloudflare", "cf", "wrangler":
		cf := &syncpkg.Cloudflare{}
		if dir := flagValue("--dir"); dir != "" {
			cf.ProjectDir = dir
		}
		if name := flagValue("--name"); name != "" {
			cf.WorkerName = name
		}
		target = cf
	case "env", "dotenv":
		de := &syncpkg.DotEnv{}
		if dir := flagValue("--dir"); dir != "" {
			de.ProjectDir = dir
		}
		target = de
	default:
		return fmt.Errorf("unknown target: %s (use: github, cloudflare, env)", targetName)
	}

	results := syncpkg.All(project, secrets, target)
	fmt.Print(syncpkg.FormatResults(results))

	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("sync had failures")
		}
	}
	return nil
}

func cmdImport(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault import <project> <.env path>")
	}
	project, envPath := os.Args[2], os.Args[3]

	data, err := os.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", envPath, err)
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if err := v.Add(project, key, value); err != nil {
			return fmt.Errorf("add %s: %w", key, err)
		}
		count++
	}

	fmt.Printf("Imported %d keys into %s\n", count, project)
	return nil
}

// SharePayload is the JSON structure inside a .vault-share file.
type SharePayload struct {
	Project string            `json:"project"`
	Secrets map[string]string `json:"secrets"`
}

func cmdExport(v *vault.Vault) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: vault export <project> [--to name|pubkey] [--keys KEY1,KEY2] [--out file]")
	}
	project := os.Args[2]

	secrets, err := v.GetProject(project)
	if err != nil {
		return err
	}

	if keysFlag := flagValue("--keys"); keysFlag != "" {
		secrets = syncpkg.FilterKeys(secrets, strings.Split(keysFlag, ","))
		if len(secrets) == 0 {
			return fmt.Errorf("no matching keys for filter")
		}
	}

	payload := SharePayload{Project: project, Secrets: secrets}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	outFile := flagValue("--out")
	if outFile == "" {
		outFile = project + ".vault-share"
	}

	keyNames := make([]string, 0, len(secrets))
	for k := range secrets {
		keyNames = append(keyNames, k)
	}
	slices.Sort(keyNames)

	toFlag := flagValue("--to")
	if toFlag != "" {
		// Public key mode
		recipientKey, err := resolveRecipient(v, toFlag)
		if err != nil {
			return err
		}

		if err := vault.GenerateIdentity(v.Dir()); err != nil {
			return err
		}
		senderPriv, err := vault.LoadPrivateKey(v.Dir())
		if err != nil {
			return err
		}

		ciphertext, err := vault.EncryptForRecipient(plaintext, senderPriv, recipientKey)
		if err != nil {
			return err
		}

		if err := os.WriteFile(outFile, ciphertext, 0644); err != nil {
			return fmt.Errorf("write share file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Exported %d keys from %s to %s (for %s)\n", len(secrets), project, outFile, toFlag)
		fmt.Fprintf(os.Stderr, "Keys: %s\n", strings.Join(keyNames, ", "))
		fmt.Fprintf(os.Stderr, "Recipient decrypts with: vault import-share %s\n", outFile)
		return nil
	}

	// Passphrase mode (fallback)
	code, err := vault.GenerateShareCode()
	if err != nil {
		return err
	}

	ciphertext, err := vault.EncryptWithPassphrase(plaintext, code)
	if err != nil {
		return err
	}

	if err := os.WriteFile(outFile, ciphertext, 0644); err != nil {
		return fmt.Errorf("write share file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Exported %d keys from %s to %s\n", len(secrets), project, outFile)
	fmt.Fprintf(os.Stderr, "Keys: %s\n", strings.Join(keyNames, ", "))
	fmt.Print(code)
	return nil
}

func resolveRecipient(v *vault.Vault, nameOrKey string) (*ecdh.PublicKey, error) {
	// Try as a saved recipient name first
	recipients, _ := vault.LoadRecipients(v.Dir())
	if pubkey, ok := recipients[nameOrKey]; ok {
		return vault.DecodePubKey(pubkey)
	}
	// Try as a raw public key
	return vault.DecodePubKey(nameOrKey)
}

func cmdImportShare(v *vault.Vault) error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: vault import-share <file.vault-share> [--code XXXX-...]")
	}
	shareFile := os.Args[2]

	data, err := os.ReadFile(shareFile)
	if err != nil {
		return fmt.Errorf("read share file: %w", err)
	}

	var plaintext []byte

	if vault.IsV2ShareFile(data) {
		// Public key mode — auto-decrypt with our private key
		privKey, err := vault.LoadPrivateKey(v.Dir())
		if err != nil {
			return err
		}
		header, pt, err := vault.DecryptFromSender(data, privKey)
		if err != nil {
			return fmt.Errorf("decrypt failed — this file may not be for you: %w", err)
		}
		plaintext = pt
		fmt.Fprintf(os.Stderr, "Decrypted share from %s\n", header.Sender)
	} else {
		// Passphrase mode — need share code
		var code string
		switch {
		case flagValue("--code") != "":
			code = flagValue("--code")
		case hasFlag("--prompt"):
			fmt.Fprint(os.Stderr, "Enter share code: ")
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				code = scanner.Text()
			}
		default:
			stdinData, readErr := io.ReadAll(os.Stdin)
			if readErr != nil {
				return fmt.Errorf("read code from stdin: %w", readErr)
			}
			code = strings.TrimSpace(string(stdinData))
		}

		if code == "" {
			return fmt.Errorf("share code required (use --code or --prompt)")
		}

		pt, err := vault.DecryptWithPassphrase(data, code)
		if err != nil {
			return fmt.Errorf("invalid share code or corrupted file")
		}
		plaintext = pt
	}

	var payload SharePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return fmt.Errorf("invalid share file format")
	}

	count := 0
	for key, value := range payload.Secrets {
		if err := v.Add(payload.Project, key, value); err != nil {
			return fmt.Errorf("add %s: %w", key, err)
		}
		count++
	}

	fmt.Printf("Imported %d keys into %s\n", count, payload.Project)
	return nil
}

// SyncTarget is the per-target config in .vault.json.
// Accepts either a string (shorthand) or an object with dir/name/repo fields.
type SyncTarget struct {
	Dir  string   `json:"dir,omitempty"`
	Name string   `json:"name,omitempty"` // worker name for cloudflare
	Repo string   `json:"repo,omitempty"` // owner/repo for github
	Keys []string `json:"keys,omitempty"` // allowlist — only sync these keys (empty = all)
}

func (s *SyncTarget) UnmarshalJSON(data []byte) error {
	var str string
	if json.Unmarshal(data, &str) == nil {
		s.Repo = str
		s.Dir = str
		return nil
	}
	type alias SyncTarget
	return json.Unmarshal(data, (*alias)(s))
}

// Manifest is the .vault.json schema that lives in each project repo.
type Manifest struct {
	Project string                `json:"project"`
	Keys    []string              `json:"keys"`
	Sync    map[string]SyncTarget `json:"sync,omitempty"`
}

func cmdOnboard(v *vault.Vault) error {
	dir := "."
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	project := filepath.Base(absDir)

	envFiles := []string{".env", ".env.local", ".env.production", ".env.development", ".dev.vars"}
	var imported []string
	allKeys := map[string]bool{}

	for _, name := range envFiles {
		path := filepath.Join(absDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			value = strings.Trim(value, `"'`)

			if err := v.Add(project, key, value); err != nil {
				return fmt.Errorf("add %s from %s: %w", key, name, err)
			}
			allKeys[key] = true
			count++
		}

		if count > 0 {
			imported = append(imported, fmt.Sprintf("%s (%d keys)", name, count))
		}
	}

	if len(imported) == 0 {
		return fmt.Errorf("no .env files found in %s", absDir)
	}

	// Create .vault.json manifest
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	manifest := Manifest{
		Project: project,
		Keys:    keys,
		Sync:    map[string]SyncTarget{},
	}

	// Auto-detect sync targets
	if _, err := os.Stat(filepath.Join(absDir, ".github")); err == nil {
		manifest.Sync["github"] = SyncTarget{}
	}
	if _, err := os.Stat(filepath.Join(absDir, "wrangler.toml")); err == nil {
		manifest.Sync["cloudflare"] = SyncTarget{}
	}
	if _, err := os.Stat(filepath.Join(absDir, "wrangler.jsonc")); err == nil {
		manifest.Sync["cloudflare"] = SyncTarget{}
	}

	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(absDir, ".vault.json")
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("write .vault.json: %w", err)
	}

	for _, f := range imported {
		fmt.Printf("Imported %s\n", f)
	}
	fmt.Printf("Created %s (project: %s, %d keys)\n", manifestPath, project, len(keys))

	return nil
}

// cmdSync now also supports manifest-based sync (no target arg needed from inside a project).
func cmdSyncFromManifest(v *vault.Vault, absDir string) error {
	data, err := os.ReadFile(filepath.Join(absDir, ".vault.json"))
	if err != nil {
		return fmt.Errorf("no .vault.json found — run 'vault onboard' first or specify a target")
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse .vault.json: %w", err)
	}

	secrets, err := v.GetProject(m.Project)
	if err != nil {
		return err
	}

	type targetWithKeys struct {
		target syncpkg.Target
		keys   []string
	}

	var pairs []targetWithKeys
	for targetName, cfg := range m.Sync {
		switch targetName {
		case "github":
			pairs = append(pairs, targetWithKeys{&syncpkg.GitHub{Repo: cfg.Repo}, cfg.Keys})
		case "cloudflare":
			dir := absDir
			if cfg.Dir != "" {
				dir = cfg.Dir
			}
			pairs = append(pairs, targetWithKeys{&syncpkg.Cloudflare{ProjectDir: dir, WorkerName: cfg.Name}, cfg.Keys})
		case "env":
			dir := absDir
			if cfg.Dir != "" {
				dir = cfg.Dir
			}
			pairs = append(pairs, targetWithKeys{&syncpkg.DotEnv{ProjectDir: dir}, cfg.Keys})
		}
	}

	if len(pairs) == 0 {
		return fmt.Errorf("no sync targets defined in .vault.json")
	}

	var allResults []syncpkg.Result
	for _, p := range pairs {
		filtered := syncpkg.FilterKeys(secrets, p.keys)
		results := syncpkg.All(m.Project, filtered, p.target)
		allResults = append(allResults, results...)
	}

	fmt.Print(syncpkg.FormatResults(allResults))

	for _, r := range allResults {
		if r.Err != nil {
			return fmt.Errorf("sync had failures")
		}
	}
	return nil
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == name {
			return true
		}
	}
	return false
}

func flagValue(name string) string {
	for i, arg := range os.Args {
		if arg == name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
