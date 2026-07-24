package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
)

// Data is the decrypted vault: project name → key name → secret value.
type Data map[string]map[string]string

type Vault struct {
	path    string
	keyPath string
}

func New(vaultDir string) *Vault {
	return &Vault{
		path:    filepath.Join(vaultDir, "vault.enc"),
		keyPath: filepath.Join(vaultDir, "key"),
	}
}

func (v *Vault) Init() error {
	if _, err := os.Stat(v.keyPath); err == nil {
		return errors.New("vault already initialized")
	}

	key, err := GenerateKey()
	if err != nil {
		return err
	}
	if err := SaveKey(v.keyPath, key); err != nil {
		return err
	}

	empty := make(Data)
	return v.save(empty)
}

func (v *Vault) load() (Data, []byte, error) {
	key, err := LoadKey(v.keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("vault not initialized: %w", err)
	}

	ciphertext, err := os.ReadFile(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(Data), key, nil
		}
		return nil, nil, fmt.Errorf("read vault: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt vault: %w", err)
	}

	var data Data
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil, fmt.Errorf("parse vault: %w", err)
	}

	return data, key, nil
}

func (v *Vault) save(data Data) error {
	key, err := LoadKey(v.keyPath)
	if err != nil {
		return err
	}

	plaintext, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vault: %w", err)
	}

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		return err
	}

	dir := filepath.Dir(v.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	return os.WriteFile(v.path, ciphertext, 0600)
}

func (v *Vault) Add(project, key, value string) error {
	data, _, err := v.load()
	if err != nil {
		return err
	}

	if data[project] == nil {
		data[project] = make(map[string]string)
	}
	data[project][key] = value

	return v.save(data)
}

func (v *Vault) Remove(project, key string) error {
	data, _, err := v.load()
	if err != nil {
		return err
	}

	secrets, ok := data[project]
	if !ok {
		return fmt.Errorf("project %q not found", project)
	}
	if _, ok := secrets[key]; !ok {
		return fmt.Errorf("key %q not found in project %q", key, project)
	}

	delete(secrets, key)
	if len(secrets) == 0 {
		delete(data, project)
	}

	return v.save(data)
}

func (v *Vault) ListProjects() ([]string, error) {
	data, _, err := v.load()
	if err != nil {
		return nil, err
	}

	projects := make([]string, 0, len(data))
	for p := range data {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	return projects, nil
}

func (v *Vault) ListKeys(project string) ([]string, error) {
	data, _, err := v.load()
	if err != nil {
		return nil, err
	}

	secrets, ok := data[project]
	if !ok {
		return nil, fmt.Errorf("project %q not found", project)
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (v *Vault) Get(project, key string) (string, error) {
	data, _, err := v.load()
	if err != nil {
		return "", err
	}

	secrets, ok := data[project]
	if !ok {
		return "", fmt.Errorf("project %q not found", project)
	}

	value, ok := secrets[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in project %q", key, project)
	}

	return value, nil
}

// GetProject returns all key-value pairs for a project.
func (v *Vault) GetProject(project string) (map[string]string, error) {
	data, _, err := v.load()
	if err != nil {
		return nil, err
	}

	secrets, ok := data[project]
	if !ok {
		return nil, fmt.Errorf("project %q not found", project)
	}

	return secrets, nil
}

// Projects returns a summary: project name → sorted list of key names.
func (v *Vault) Projects() (map[string][]string, error) {
	data, _, err := v.load()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(data))
	for project, secrets := range data {
		keys := make([]string, 0, len(secrets))
		for k := range secrets {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		result[project] = keys
	}

	return result, nil
}
