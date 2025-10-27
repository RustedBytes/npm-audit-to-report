use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use serde::Deserialize;

const APP_VERSION: &str = "0.4.0";

#[derive(Parser, Debug, Clone)]
#[command(version = APP_VERSION, about = "Convert npm audit JSON lines into a Markdown summary.")]
struct Cli {
    #[arg(
        short = 'i',
        long = "audit-file",
        default_value = "security-audit.json"
    )]
    audit_file: PathBuf,

    #[arg(short = 'o', long = "output-file", default_value = "security-audit.md")]
    output_file: PathBuf,

    #[arg(short = 'f', long = "fail-if-no-vulnerabilities")]
    fail_if_no_vulnerabilities: bool,
}

impl Cli {
    #[cfg(test)]
    fn new(audit_file: PathBuf, output_file: PathBuf, fail_if_no_vulnerabilities: bool) -> Self {
        Self {
            audit_file,
            output_file,
            fail_if_no_vulnerabilities,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuditLine {
    #[serde(rename = "type")]
    kind: String,
    data: AuditData,
}

#[derive(Debug, Deserialize)]
struct AuditData {
    #[serde(default)]
    advisory: Option<Advisory>,

    #[serde(default)]
    vulnerabilities: Vulnerabilities,

    #[serde(rename = "dependencies", default)]
    dependencies: i64,

    #[serde(rename = "devDependencies", default)]
    dev_dependencies: i64,

    #[serde(rename = "optionalDependencies", default)]
    optional_dependencies: i64,

    #[serde(rename = "totalDependencies", default)]
    total_dependencies: i64,
}

#[derive(Debug, Deserialize)]
struct Advisory {
    #[serde(default)]
    title: String,

    #[serde(default)]
    severity: String,

    #[serde(default)]
    url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Vulnerabilities {
    info: i64,
    low: i64,
    moderate: i64,
    high: i64,
    critical: i64,
}

fn parse_json(path: &PathBuf) -> Result<Vec<AuditLine>> {
    let file = File::open(path)
        .with_context(|| format!("unable to open audit file {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();

    for (index, line_result) in reader.lines().enumerate() {
        let line = line_result
            .with_context(|| format!("error reading line {} from {}", index + 1, path.display()))?;
        if line.trim().is_empty() {
            continue;
        }

        let parsed: AuditLine = serde_json::from_str(&line).with_context(|| {
            format!(
                "error parsing JSON on line {} of {}",
                index + 1,
                path.display()
            )
        })?;
        lines.push(parsed);
    }

    if lines.is_empty() {
        return Err(anyhow!("no data in the audit file"));
    }

    Ok(lines)
}

fn generate_markdown(lines: &[AuditLine]) -> Result<String> {
    if lines.is_empty() {
        return Err(anyhow!("no data in the audit file"));
    }

    let summary = lines
        .iter()
        .find(|line| line.kind == "auditSummary")
        .ok_or_else(|| anyhow!("no summary audit line found"))?;

    let data = &summary.data;
    let vulnerabilities = &data.vulnerabilities;
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut text = Vec::new();
    text.push(format!("# Security Audit: {} (UTC)", now));
    text.push(String::new());

    text.push("## Dependencies".to_string());
    text.push(String::new());
    text.push(format!("- Project: {}", data.dependencies));
    text.push(format!("- Dev: {}", data.dev_dependencies));
    text.push(format!("- Optional: {}", data.optional_dependencies));
    text.push(format!("- Total: {}", data.total_dependencies));
    text.push(String::new());

    text.push("## Vulnerabilities".to_string());
    text.push(String::new());
    text.push(format!("- 🔵 Info: {}", vulnerabilities.info));
    text.push(format!("- 🟢 Low: {}", vulnerabilities.low));
    text.push(format!("- 🟡 Moderate: {}", vulnerabilities.moderate));
    text.push(format!("- 🟠 High: {}", vulnerabilities.high));
    text.push(format!("- 🔴 Critical: {}", vulnerabilities.critical));
    text.push(String::new());

    if lines.len() > 1 {
        let mut advisories_added = false;

        for line in lines.iter().filter(|line| line.kind == "auditAdvisory") {
            if let Some(advisory) = &line.data.advisory {
                if !advisories_added {
                    text.push("## Advisories".to_string());
                    text.push(String::new());
                    advisories_added = true;
                }

                text.push(format!("### `{}`: {}", advisory.severity, advisory.title));
                text.push(String::new());
                text.push(format!("- URL: {}", advisory.url));
                text.push(String::new());
            }
        }
    }

    Ok(text.join("\n"))
}

fn run(cli: Cli) -> Result<()> {
    if cli.audit_file.as_os_str().is_empty() {
        bail!("audit file is required");
    }

    let lines = parse_json(&cli.audit_file)?;
    let total_vulnerabilities: i64 = lines
        .iter()
        .filter(|line| line.kind == "auditSummary")
        .map(|line| {
            let v = &line.data.vulnerabilities;
            v.info + v.low + v.moderate + v.high + v.critical
        })
        .sum();

    if total_vulnerabilities == 0 && cli.fail_if_no_vulnerabilities {
        bail!("no vulnerabilities found");
    }

    let markdown = generate_markdown(&lines)?;

    println!("{}", markdown);
    std::fs::write(&cli.output_file, markdown)
        .with_context(|| format!("failed to write {}", cli.output_file.display()))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli) {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    use tempfile::{tempdir, NamedTempFile};

    fn sample_summary_line() -> String {
        r#"{"type":"auditSummary","data":{"vulnerabilities":{"info":1,"low":2,"moderate":3,"high":4,"critical":5},"dependencies":10,"devDependencies":4,"optionalDependencies":1,"totalDependencies":15}}"#.to_string()
    }

    fn sample_advisory_line() -> String {
        r#"{"type":"auditAdvisory","data":{"advisory":{"title":"Prototype Pollution","severity":"high","url":"https://example.com/advisory"}}}"#.to_string()
    }

    #[test]
    fn parse_json_reads_each_line() {
        let mut file = NamedTempFile::new().expect("create temp file");
        writeln!(file, "{}", sample_summary_line()).unwrap();
        writeln!(file, "{}", sample_advisory_line()).unwrap();

        let lines = parse_json(&file.path().to_path_buf()).expect("parse JSON lines");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].kind, "auditSummary");
        assert_eq!(lines[1].kind, "auditAdvisory");
    }

    #[test]
    fn parse_json_errors_on_empty_file() {
        let file = NamedTempFile::new().expect("create temp file");
        let err = parse_json(&file.path().to_path_buf()).expect_err("expected error");
        assert_eq!(err.root_cause().to_string(), "no data in the audit file");
    }

    #[test]
    fn generate_markdown_includes_dependencies_and_advisories() {
        let vulnerabilities = Vulnerabilities {
            info: 1,
            low: 2,
            moderate: 3,
            high: 4,
            critical: 5,
        };
        let summary = AuditLine {
            kind: "auditSummary".into(),
            data: AuditData {
                advisory: None,
                vulnerabilities,
                dependencies: 10,
                dev_dependencies: 4,
                optional_dependencies: 1,
                total_dependencies: 15,
            },
        };
        let advisory = AuditLine {
            kind: "auditAdvisory".into(),
            data: AuditData {
                advisory: Some(Advisory {
                    title: "Prototype Pollution".into(),
                    severity: "high".into(),
                    url: "https://example.com/advisory".into(),
                }),
                vulnerabilities: Vulnerabilities::default(),
                dependencies: 0,
                dev_dependencies: 0,
                optional_dependencies: 0,
                total_dependencies: 0,
            },
        };

        let markdown =
            generate_markdown(&[summary, advisory]).expect("markdown should generate successfully");

        assert!(
            markdown.starts_with("# Security Audit:"),
            "expected timestamp header"
        );
        assert!(
            markdown.contains("## Dependencies"),
            "expected dependencies section"
        );
        assert!(
            markdown.contains("- Total: 15"),
            "expected total dependency count"
        );
        assert!(
            markdown.contains("## Advisories"),
            "expected advisories section"
        );
        assert!(
            markdown.contains("`high`: Prototype Pollution"),
            "expected advisory title"
        );
    }

    #[test]
    fn run_writes_output_file() {
        let dir = tempdir().expect("create temp dir");
        let audit_path = dir.path().join("audit.json");
        let output_path = dir.path().join("report.md");

        let content = format!("{}\n{}", sample_summary_line(), sample_advisory_line());
        fs::write(&audit_path, content).expect("write audit file");

        let cli = Cli::new(audit_path.clone(), output_path.clone(), false);
        run(cli).expect("run should succeed");

        let output = fs::read_to_string(output_path).expect("read output");
        assert!(
            output.contains("## Vulnerabilities"),
            "expected vulnerabilities section"
        );
    }

    #[test]
    fn run_fails_when_requested_and_no_vulnerabilities() {
        let dir = tempdir().expect("create temp dir");
        let audit_path = dir.path().join("audit.json");
        let output_path = dir.path().join("report.md");

        let empty_summary = r#"{"type":"auditSummary","data":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":0,"critical":0},"dependencies":0,"devDependencies":0,"optionalDependencies":0,"totalDependencies":0}}"#;
        fs::write(&audit_path, empty_summary).expect("write audit file");

        let cli = Cli::new(audit_path, output_path, true);
        let err = run(cli).expect_err("run should fail");
        assert_eq!(err.to_string(), "no vulnerabilities found");
    }
}
