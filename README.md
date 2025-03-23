# npm-audit-to-report

A simple Go program that converts `security-audit.json` to `security-audit.md` so you can use it in CI pipeline.

## Install

```bash
go install github.com/egorsmkv/npm-audit-to-report
```

## Usage

```
npm-audit-to-report [FLAGS]

  Flags:
       --version                      Displays the program version string.
    -h --help                         Displays help with available flag, subcommand, and positional value parameters.
    -i --audit-file                   Path to the audit file (default: security-audit.json)
    -o --output-file                  Path to the output file (default: security-audit.md)
    -f --fail-if-no-vulnerabilities   Fail if no vulnerabilities found
```
