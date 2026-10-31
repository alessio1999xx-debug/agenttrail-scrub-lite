# agenttrail-scrub-lite: scan Claude Code transcripts for leaked secrets

Claude Code saves every session transcript as local JSONL under `~/.claude`, including any API key, token or `.env` value that passed through the terminal or a pasted file. agenttrail-scrub-lite helps you find those secrets with a read-only scan using only the standard library: it reports where they are and never modifies your files.

- One file, Python 3.9+. Nothing to `pip install`.
- Default target: `~/.claude/projects/**/*.jsonl` (override with `--path`).
- Masked previews only; exit code `1` when at least one secret pattern is reported.

## Install

```bash
curl -fsSLO https://raw.githubusercontent.com/alessio1999xx-debug/agenttrail-scrub-lite/main/agenttrail_scrub_lite.py
chmod +x agenttrail_scrub_lite.py
python agenttrail_scrub_lite.py --help
```

(Until the repo is public, copy `agenttrail_scrub_lite.py` from this tree instead of curling.)

## Where Claude Code stores transcripts (and why secrets end up there)

Claude Code keeps project session logs under `~/.claude/projects/`, usually as `.jsonl` files (one JSON object per line). Anything you typed, pasted, or that an agent echoed — including `export` lines, `.env` snippets, and provider tokens — can sit there in plaintext. Sharing a transcript, opening a bug report, or syncing that folder to a backup is how keys leak.

agenttrail-scrub-lite walks that tree (or a path you pass), opens each `.jsonl` as text, and matches **common patterns** for provider credentials. It does not claim to find every possible secret.

Patterns currently checked:

| Provider / kind | Example shape (not a real key) |
|---|---|
| Anthropic API key | `sk-ant-api03-…` |
| Anthropic legacy key | `sk-ant-…` |
| OpenAI API key | `sk-…` / `sk-proj-…` |
| Google Gemini / Cloud | `AIzaSy…` |
| GitHub PAT / OAuth | `ghp_` / `gho_` / … |
| GitHub fine-grained | `github_pat_…` |
| AWS access key id | `AKIA…` / `ASIA…` |
| AWS secret access key | `aws_secret_access_key=…` |
| Stripe secret / restricted | `sk_live_` / `sk_test_` / `rk_…` |
| Slack token | `xoxb-` / `xoxp-` / … |
| Private key header | `-----BEGIN … PRIVATE KEY-----` |
| JWT | `eyJh….….…` |
| Generic `.env` assignment | `API_KEY=` / `TOKEN=` / … |

## Scan Claude Code logs for API keys and tokens

```bash
# default: ~/.claude/projects
python agenttrail_scrub_lite.py

# one project folder or a single .jsonl file
python agenttrail_scrub_lite.py --path ~/.claude/projects/my-encoded-path
python agenttrail_scrub_lite.py --path ./session.jsonl
```

The report lists provider, file path, line number and a masked preview (`abcd...xyz`). Nothing is written back to disk. If matches appear, rotate the real credentials at the provider — this tool only helps you find them.

## Run it before sharing a transcript or a bug report

```bash
python agenttrail_scrub_lite.py --path ./transcript-to-share.jsonl
echo $?   # 0 = no common patterns found; 1 = at least one match
```

Use the exit code in a pre-share checklist or a local hook so you do not paste a log that still holds keys.

## agenttrail-scrub-lite vs AgentTrail Scrub (redact and clean)

agenttrail-scrub-lite checks **Claude Code** JSONL transcripts only, with regex patterns and a text report. It is read-only.

The full **[AgentTrail Scrub AI transcript secret cleaner](https://py-forge.com/products/agenttrail-scrub-ai-transcript-secret-cleaner?utm_source=github&utm_medium=lite_repo&utm_content=agenttrail-scrub-lite)** adds:

- other AI coding agents and any `--paths` you pass
- Shannon entropy checks on top of the regexes
- `--redact` with timestamped backups
- allowlist for known-safe values
- retention / scheduled cleanup of old transcripts
- per-provider rotation checklist

One-time payment, yours to keep. No subscription.

Or get every PyForge tool, current and future, with the [All-Access Pass](https://py-forge.com/pass?utm_source=github&utm_medium=lite_repo&utm_content=agenttrail-scrub-lite).

## Need more?

Need the full version? **AgentTrail Scrub** on PyForge: https://py-forge.com/products/agenttrail-scrub-ai-transcript-secret-cleaner?utm_source=github&utm_medium=lite_repo&utm_content=agenttrail-scrub-lite

Or get every PyForge tool, current and future, with the All-Access Pass: https://py-forge.com/pass?utm_source=github&utm_medium=lite_repo&utm_content=agenttrail-scrub-lite

## Tests

```bash
python3 test_agenttrail_scrub_lite.py
```

## License

MIT (this lite version). The full AgentTrail Scrub tool is sold separately under its own license.
