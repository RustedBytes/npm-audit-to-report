# npm-audit-to-report

[![build](https://github.com/RustedBytes/npm-audit-to-report/actions/workflows/build.yml/badge.svg)](https://github.com/RustedBytes/npm-audit-to-report/actions/workflows/build.yml)

A lightweight Rust CLI for turning newline-delimited `npm audit --json` or `yarn audit --json` output into a readable Markdown report. Drop the generated file into GitHub issues, Slack, release notes, or wherever you track security work.

## Features
- Converts raw audit JSON lines into a clear Markdown summary with dependency totals, severities, and detailed advisories.
- Prints to `stdout` **and** writes a Markdown file (default `security-audit.md`) so you can inspect locally or archive in CI runs.
- Understands both npm and Yarn audit formats without any pre-processing.
- Offers `--fail-if-no-vulnerabilities` so downstream steps (issue creation, notifications) only trigger when problems are detected.

## Prerequisites
- Rust toolchain (Rust 1.75+ recommended).
- An audit report generated with `npm audit --json` or `yarn audit --json`. The CLI expects newline-delimited JSON (NDJSON), which is the default for both commands.

## Installation

Install straight from the repository:

```bash
cargo install --locked --git https://github.com/RustedBytes/npm-audit-to-report.git
```

Or build once and copy the binary wherever you need it:

```bash
cargo build --release
cp target/release/npm-audit-to-report /usr/local/bin
```

## Usage

1. Capture audit output:
   ```bash
   # npm
   npm audit --json > security-audit.json

   # Yarn (classic or Berry)
   yarn audit --json > security-audit.json
   ```
2. Convert it to Markdown:
   ```bash
   npm-audit-to-report \
     --audit-file security-audit.json \
     --output-file security-audit.md
   ```
3. Read the generated report from `stdout` or open `security-audit.md`.

### Sample Output

```markdown
# Security Audit: 2024-05-15 09:31:07 (UTC)

## Vulnerabilities
- 🔵 Info: 1
- 🟢 Low: 0
- 🟡 Moderate: 2
- 🟠 High: 0
- 🔴 Critical: 0
```

<img loading="lazy" alt="npm-audit-to-report demo" width="800px" src="https://github.com/RustedBytes/npm-audit-to-report/raw/main/demo.png" />

## CLI Options

```text
Convert npm audit JSON lines into a Markdown summary.

Usage: npm-audit-to-report [OPTIONS]

Options:
  -i, --audit-file <AUDIT_FILE>     [default: security-audit.json]
  -o, --output-file <OUTPUT_FILE>   [default: security-audit.md]
  -f, --fail-if-no-vulnerabilities  return a non-zero exit code when no issues are found
  -h, --help                        Print help
  -V, --version                     Print version
```

When `--fail-if-no-vulnerabilities` is set, the process exits with a non-zero status if all severity counts are zero. This makes it easy to gate issue creation or notifications behind real findings (use `continue-on-error: true` in GitHub Actions to let subsequent steps run conditionally).

## CI Integration

This repository includes two ready-to-use GitHub Actions workflows:

- [`dependency-audit.yml`](https://github.com/RustedBytes/npm-audit-to-report/blob/main/dependency-audit.yml) – always generates a report and opens an issue every successful run.
- [`dependency-audit-only-when-detected.yml`](https://github.com/RustedBytes/npm-audit-to-report/blob/main/dependency-audit-only-when-detected.yml) – combines `--fail-if-no-vulnerabilities` with conditional steps so issues appear only when vulnerabilities exist.

Both examples install dependencies, run `yarn audit --json`, build the CLI, and post the Markdown as the issue body. Adapt them to your own workflow, or copy the relevant steps into other CI providers.

## Development

```bash
just fmt   # cargo fmt
just lint  # cargo clippy --all-targets --all-features -- -D warnings
just test  # cargo test
```

### Release

```bash
cargo build --release
```
