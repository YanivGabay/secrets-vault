---
name: secrets
description: Manage encrypted secrets vault. Add, remove, list, sync, and import secrets. Secret values NEVER appear in conversation — all operations pipe through shell.
user_invocable: true
---

# /secrets — Encrypted Secrets Vault

**CRITICAL: Secret values must NEVER appear in Claude's conversation context.** All commands pipe values through the `vault` CLI binary. You only see key names, never values.

## Prerequisites

The `vault` binary must be in PATH. If not, build it:
```bash
cd ~/repos/secrets-vault && go install ./cmd/vault/
```

## Commands

### `/secrets init`
Initialize a new vault (only needed once).
```bash
vault init
```

### `/secrets add <project> <KEY>`
Add a secret from clipboard. User must copy the secret value to clipboard first.
```bash
vault add <project> <KEY>
```
The vault binary reads the clipboard directly, adds the encrypted entry, and clears the clipboard. Claude never sees the value.

### `/secrets rm <project> <KEY>`
Remove a secret from the vault.
```bash
vault rm <project> <KEY>
```

### `/secrets list [project]`
List all projects and key names, or keys for a specific project. No values are shown.
```bash
vault list
vault list <project>
```

### `/secrets sync <project> <target>`
Sync secrets to a target. Values flow through shell pipes, never through Claude.

**GitHub Actions:**
```bash
vault sync <project> github
vault sync <project> github --repo owner/repo
```

**Cloudflare Workers:**
```bash
vault sync <project> cloudflare
vault sync <project> cloudflare --dir /path/to/worker
```

**.env file:**
```bash
vault sync <project> env
vault sync <project> env --dir /path/to/project
```

### `/secrets import <project> <path>`
Import secrets from an existing .env file into the vault.
```bash
vault import <project> /path/to/.env
```

## Workflow Examples

**User wants to add a Supabase key:**
1. User copies the key to clipboard
2. User says: `/secrets add zapedit SUPABASE_ANON_KEY`
3. Run: `vault add zapedit SUPABASE_ANON_KEY`
4. Report: "Added SUPABASE_ANON_KEY to zapedit"

**User wants to sync to GitHub Actions:**
1. User says: `/secrets sync zapedit github --repo yaniv242/zapedit`
2. Run: `vault sync zapedit github --repo yaniv242/zapedit`
3. Report the result (OK/FAIL per target)

**User wants to onboard an existing project:**
1. User says: `/secrets import myapp ~/repos/myapp/.env`
2. Run: `vault import myapp ~/repos/myapp/.env`
3. Report: "Imported N keys into myapp"
