# Secrets Vault — Project Context

## What This Is

A personal secrets manager for a solo developer (Yaniv) who manages ~56 repos from ~/repos. The goal is ONE encrypted vault on the local machine that Claude Code can use to sync secrets to all targets — without secrets ever appearing in Claude's conversation context.

## Problem Being Solved

- Secrets scattered across .env files, GitHub Actions secrets, Cloudflare Wrangler secrets
- When a key rotates, some targets get updated, others don't (e.g., Supabase keep-alive cron broke because GitHub Actions had a stale SUPABASE_ANON_KEY)
- No single source of truth
- Adding/reading secrets through Claude would expose them to the conversation — unacceptable

## Core Architecture Requirement

**Secrets must NEVER flow through Claude's context.** Claude only knows project names and key names, never values.

### How secrets get added:
1. User copies secret value to clipboard
2. Tells Claude: `/secrets add <project> <KEY_NAME>`
3. A local script reads the value from clipboard (WSL: `powershell.exe -command Get-Clipboard`)
4. Script decrypts vault, adds entry, re-encrypts
5. Script clears clipboard
6. Claude only sees output: "Added KEY_NAME to project"

### How secrets get synced:
- Script handles all piping — values go through shell pipes, not Claude's context
- `gh secret set KEY < value` for GitHub Actions
- `wrangler secret put KEY < value` for Cloudflare Workers
- Direct file write for .env files
- Claude only sees: "Synced 3 keys to github-actions"

## Vault Structure

Encrypted with `age` (modern, simple alternative to GPG).

```
~/.secrets/
  vault.age          # encrypted YAML file with all secrets
  key.txt            # age private key (chmod 600)
```

Decrypted vault format (YAML):
```yaml
zapedit:
  SUPABASE_URL: "https://xfbfhyqbedyehuqfbrwi.supabase.co"
  SUPABASE_ANON_KEY: "eyJ..."
  OPENROUTER_API_KEY: "sk-or-..."

store-agent:
  SUPABASE_URL: "https://mvoxckiqssdxwfpszsqq.supabase.co"
  CF_WORKER_SECRET: "..."

hebclaude:
  SOME_KEY: "..."
```

## Planned Skill Commands

| Command | What it does | Secret exposed to Claude? |
|---|---|---|
| `/secrets add <project> <KEY>` | Read value from clipboard, store in vault | NO |
| `/secrets list` | Show all projects and key names (no values) | NO |
| `/secrets get <project>` | Show key names for a project (no values) | NO |
| `/secrets sync <project> github` | Push secrets to GitHub Actions via `gh secret set` | NO |
| `/secrets sync <project> wrangler` | Push to Cloudflare Workers via `wrangler secret put` | NO |
| `/secrets sync <project> env` | Write .env file in the project directory | NO |
| `/secrets rm <project> <KEY>` | Remove a key from vault | NO |

## Tech Stack

- **Encryption**: `age` (https://github.com/FiloSottile/age) — simple, modern, no GPG complexity
- **Vault format**: YAML (human-readable when decrypted for debugging)
- **Scripts**: Bash scripts that handle all secret operations
- **Skill**: Claude Code skill that calls the bash scripts
- **Clipboard**: `powershell.exe -command Get-Clipboard` (WSL) / `xclip` (native Linux)

## Environment

- WSL2 Ubuntu on Windows
- Claude Code v2.1.215
- Herdr terminal multiplexer
- ~56 repos in ~/repos
- GitHub CLI (`gh`) available
- Wrangler CLI available
- Node.js via nvm

## Infisical Comparison — Build vs Use

Yaniv wants to understand: why build this when Infisical (https://github.com/Infisical/infisical) exists and is open-source?

Key questions to explore:
- What does Infisical offer that covers our needs?
- What's MISSING from Infisical for our specific Claude Code workflow? (the clipboard-based secret injection, the skill integration, the "secrets never in conversation" guarantee)
- Could we fork Infisical and add what's missing?
- Or is Infisical overkill for a solo dev and a simple age-encrypted vault is better?
- Or should we use Infisical as the backend but build a thin Claude skill on top?

## What To Discuss With Yaniv

1. Infisical vs custom vault — what's the right approach?
2. Should the vault be one flat YAML or nested (project > environment > keys)?
3. Should there be a `secrets audit` command that checks all targets are in sync?
4. Should there be a `secrets import` command that reads existing .env files into the vault?
5. Backup strategy for the vault file?
6. Should key names be visible to Claude or also hidden? (currently: names visible, values hidden)
7. Multiple vaults (personal vs work) or one vault with tags?
