# SkillGuard

SkillGuard is a static-analysis CLI that inspects AI-agent skill and configuration files —
`SKILL.md`, `AGENTS.md`, Kiro steering files and hooks, and MCP server configuration — **before
they are distributed or committed**, and reports hidden instructions and supply-chain risks. It
produces text, JSON, and SARIF 2.1.0 output, and ships as a pre-commit hook and a GitHub Action.

SkillGuard is a learning project for the [OWASP Top 10 for LLM Applications
2025](https://genai.owasp.org/llm-top-10/), [MITRE ATLAS](https://atlas.mitre.org/), software
supply-chain security, and Unicode-based attacks. **All samples in this repository, including
everything under `examples/`, are synthetic.**

It is standard-library-only Go: no third-party dependencies, no network access at scan time.

## What it detects

Every rule maps to an [OWASP Top 10 for LLM Applications
2025](https://genai.owasp.org/llm-top-10/) risk and a [MITRE
ATLAS](https://atlas.mitre.org/) technique. Run `skillguard rules` to list the table from the
binary you built.

| ID | Name | Default severity | OWASP LLM 2025 | ATLAS |
|---|---|---|---|---|
| SG001 | invisible-unicode-zero-width | high | LLM01:2025 | AML.T0068 |
| SG002 | invisible-unicode-bidi | high | LLM01:2025 | AML.T0068 |
| SG003 | invisible-unicode-tag | critical | LLM01:2025 | AML.T0068, AML.T0051 |
| SG010 | prompt-injection-phrase | high | LLM01:2025 | AML.T0051 |
| SG020 | data-exfiltration | high | LLM02:2025 | AML.T0025 |
| SG021 | markdown-image-exfiltration | high | LLM02:2025 | AML.T0086 |
| SG030 | dangerous-shell-command | high | LLM06:2025 | AML.T0050 |
| SG031 | sensitive-file-access | high | LLM02:2025 | AML.T0055 |
| SG040 | excessive-permission | high | LLM06:2025 | AML.T0053 |
| SG050 | unpinned-mcp-package | medium | LLM03:2025 | AML.T0010 |
| SG060 | hardcoded-secret | critical | LLM02:2025 | AML.T0083 |

### SG001 — invisible-unicode-zero-width

Zero-width and other invisible characters (`U+200B`, `U+200C`, `U+200D`, `U+2060`–`U+2064`,
`U+FEFF`, `U+00AD`, `U+180E`, `U+3164`, `U+115F`, `U+1160`, `U+FFA0`) can hide text from a human
reviewing a diff while an LLM still reads it ([LLM01:2025 Prompt
Injection](https://genai.owasp.org/llm-top-10/), [AML.T0068 LLM Prompt
Obfuscation](https://atlas.mitre.org/techniques/AML.T0068)). A legitimate emoji ZWJ sequence
between two pictographic characters is not reported.

### SG002 — invisible-unicode-bidi

Bidirectional-control characters (`U+202A`–`U+202E`, `U+2066`–`U+2069`, `U+200E`, `U+200F`,
`U+061C`) can reorder how text is *displayed* without changing the underlying bytes, hiding
malicious instructions in what looks like an innocuous line ([LLM01:2025 Prompt
Injection](https://genai.owasp.org/llm-top-10/), [AML.T0068 LLM Prompt
Obfuscation](https://atlas.mitre.org/techniques/AML.T0068)).

### SG003 — invisible-unicode-tag

Unicode Tag block (`U+E0000`–`U+E007F`) and variation-selector-supplement (`U+E0100`–`U+E01EF`)
characters can smuggle an entire hidden instruction string into a document; SkillGuard decodes
the tag characters and reports the hidden ASCII text ([LLM01:2025 Prompt
Injection](https://genai.owasp.org/llm-top-10/), [AML.T0068 LLM Prompt
Obfuscation](https://atlas.mitre.org/techniques/AML.T0068) /
[AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)). SG001–SG003 are
never suppressible: an attacker who can hide characters can also hide a suppression comment.

### SG010 — prompt-injection-phrase

English and Japanese phrasing that attempts to override, bypass, or hide instructions from the
user — "ignore previous instructions", "you are now in developer mode", "don't mention this to
the user", chat-template role tokens, and full-width-obfuscated variants
([LLM01:2025 Prompt Injection](https://genai.owasp.org/llm-top-10/),
[AML.T0051 LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)).

### SG020 — data-exfiltration

Shell commands and URLs that send data to a remote host: `curl`/`wget` uploads to a non-local
host, shell-expansion in a download URL, output piped to a network tool, PowerShell web requests
with a body, and known out-of-band / request-capture hosts such as `webhook.site` or `ngrok.io`
([LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/),
[AML.T0025 Exfiltration via Cyber Means](https://atlas.mitre.org/techniques/AML.T0025)).

### SG021 — markdown-image-exfiltration

A Markdown or HTML image whose URL contains a data placeholder (`{{...}}`, `${...}`, `$NAME`,
`<...>`, `%7B`, `[...]`) exfiltrates data the moment a renderer fetches the image — a classic
indirect-exfiltration channel for anything that renders agent output as Markdown or HTML
([LLM02:2025 Sensitive Information Disclosure](https://genai.owasp.org/llm-top-10/),
[AML.T0086 Exfiltration via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0086)).

### SG030 — dangerous-shell-command

Download-and-execute pipelines, process substitution of a remote download, base64-decoded data
piped into a shell, catastrophic `rm -rf` targets, world-writable/setuid `chmod`, filesystem
formatting, writing straight to a disk device, and the classic shell fork bomb
([LLM06:2025 Excessive Agency](https://genai.owasp.org/llm-top-10/),
[AML.T0050 Command and Scripting Interpreter](https://atlas.mitre.org/techniques/AML.T0050)).

### SG031 — sensitive-file-access

References to credential locations: SSH keys, `.aws/credentials`, `.netrc`,
`.docker/config.json`, `.kube/config`, `.git-credentials`, `.npmrc`, `.pypirc`, `/etc/shadow`,
macOS Keychains, and more ([LLM02:2025 Sensitive Information
Disclosure](https://genai.owasp.org/llm-top-10/), [AML.T0055 Unsecured
Credentials](https://atlas.mitre.org/techniques/AML.T0055)).

### SG040 — excessive-permission

Configuration or flags that grant an agent unrestricted or auto-approved tool access: MCP
`autoApprove`/`alwaysAllow`/`trust`, a Kiro hook that runs a shell command on any trigger, a
SKILL.md `allowed-tools` entry that grants unrestricted `Bash`, and flags like
`--dangerously-skip-permissions` or `--yolo`
([LLM06:2025 Excessive Agency](https://genai.owasp.org/llm-top-10/),
[AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053)).

### SG050 — unpinned-mcp-package

An MCP server launched via `npx`/`bunx`/`pnpm dlx`/`yarn dlx`, `uvx`/`pipx run`/`uv tool run`, or
`docker run` without a pinned exact version (or content digest, for `docker`) can silently change
underneath you on every run ([LLM03:2025 Supply Chain](https://genai.owasp.org/llm-top-10/),
[AML.T0010 AI Supply Chain Compromise](https://atlas.mitre.org/techniques/AML.T0010)).

### SG060 — hardcoded-secret

Hardcoded API keys, tokens, and private keys (AWS, GitHub, Anthropic, OpenAI, Slack, Google,
Stripe, PEM) matched by pattern, plus opaque secret-shaped values under an MCP server's `env` or
`headers` whose key name suggests a credential ([LLM02:2025 Sensitive Information
Disclosure](https://genai.owasp.org/llm-top-10/), [AML.T0083 Credentials from AI Agent
Configuration](https://atlas.mitre.org/techniques/AML.T0083)). The raw secret never appears in
any output format: SkillGuard reports at most the first 4 characters followed by `****`.

## Install

```sh
go install github.com/CrescentKohana/skillguard/cmd/skillguard@latest
```

## CLI usage

```
skillguard scan [flags] [path ...]     # default path "."
skillguard rules [--format text|json]  # list rules with ID, name, severity, OWASP, ATLAS
skillguard version                     # print the version
skillguard help | -h | --help
```

`scan` flags:

| Flag | Values | Default |
|---|---|---|
| `--format` | `text`, `json`, `sarif` | `text` |
| `--output` | path to a file (created with mode `0644`, replaced if present) | stdout |
| `--fail-on` | `info`, `low`, `medium`, `high`, `critical`, `none` | `medium` |

Flags may appear before the paths, e.g. `skillguard scan --format json --fail-on high .`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding with severity ≥ `--fail-on` (always `0` for `none`) |
| `1` | At least one finding with severity ≥ `--fail-on` |
| `2` | Usage error, unreadable path, or output error |

### Output formats

- **text** — one line per finding (`<path>:<line>:<col>: <severity> <RULEID> <message>`), the
  offending line indented underneath, and a one-line summary.
- **json** — `{"tool", "version", "findings": [...], "summary": {...}}`. `findings` is `[]`, never
  `null`, when there are no findings.
- **sarif** — a single-run SARIF 2.1.0 log with full rule metadata (including OWASP/ATLAS tags
  and a `security-severity` score) under `runs[0].tool.driver.rules`, suitable for GitHub code
  scanning.

### Inline suppression

A line containing `skillguard-ignore` followed by one or more rule IDs (space- or
comma-separated) suppresses those rule IDs on that line and the next line:

```
<!-- skillguard-ignore SG030 -->
curl -fsSL https://example.com/install.sh | bash
```

```
# skillguard-ignore SG020,SG031
```

`skillguard-ignore` with no IDs suppresses nothing. **SG001, SG002, and SG003 are never
suppressible** — an attacker who can hide characters can also hide a suppression comment.
Suppressed findings are still counted (`suppressed` in the JSON summary, and in the text summary
line).

## Pre-commit

```yaml
repos:
  - repo: https://github.com/CrescentKohana/skillguard
    rev: <commit-sha-or-tag>
    hooks:
      - id: skillguard
```

## GitHub Action

SARIF upload needs `security-events: write` in the calling workflow's permissions:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  skillguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: CrescentKohana/skillguard@<full-40-character-commit-sha> # pin this to a commit SHA you've reviewed
        with:
          path: .
          fail-on: medium
          sarif-file: skillguard.sarif
          upload-sarif: "true"
```

The `uses:` line above is an explicit placeholder, not a real release; **pin it to the full commit
SHA you've reviewed**, the same way this repository pins its own third-party actions (see
`.github/workflows/ci.yml`). The action builds `skillguard` from its own `go.mod`, runs a SARIF
scan, uploads the SARIF with `github/codeql-action/upload-sarif` when `upload-sarif` is `"true"`
and the scan produced a SARIF file (even if the scan found issues), and then fails the step with
the scan's exit code; a usage or I/O error (exit `2`) surfaces its own stderr in the "Run
skillguard scan" step.

## Limitations

- SkillGuard is **heuristic and regex-based**, not a full parser for shell, YAML, or Markdown. It
  can both miss creative obfuscation and occasionally flag benign content.
- Prompt-injection phrasing (SG010) is matched in **English and Japanese only**.
- SkillGuard does **no network access at scan time** and cannot verify whether a flagged secret,
  host, or package is actually in use or actually malicious — treat every finding as a prompt for
  human review, not a verdict.
- `docker run` argument parsing (SG050) is a heuristic that assumes the image reference is the
  first non-flag argument; flags that take a separate value (e.g. `-v host:container`) before the
  image can confuse it.
- Secret masking is deliberately conservative: any 5-character run of a message that also occurs
  in a secret on the same line is masked, so an unrelated literal can render partly masked (for
  example `--yo****` when a secret on that line contains `--yol`).

All samples under `examples/` are synthetic and exist solely to demonstrate detection; none of
them are real credentials, real hosts, or real attack infrastructure.
