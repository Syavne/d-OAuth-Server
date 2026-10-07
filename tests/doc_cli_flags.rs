//! Guards that the PII/TOTP migration commands documented in
//! `docs/OPERATIONS.md` match the real CLI.
//!
//! The docs are part of the change, so a flag added to (or removed from) these
//! commands without updating the runbook must fail here. The flags are parsed
//! from the real binary's `--help`, so the check cannot drift from the CLI the
//! way a hand-maintained list would. `unwrap`/`expect`/`panic` are denied
//! workspace-wide, so the body returns a `Result`.

use std::{collections::BTreeSet, path::PathBuf, process::Command};

/// Test body result (no `unwrap`/`expect` under the deny lints).
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The migration commands, as the CLI path segments that select them.
const COMMANDS: &[&[&str]] = &[
  &["pii", "backfill"],
  &["pii", "verify"],
  &["pii", "rotate"],
  &["totp", "rewrap"],
];

/// The real binary Cargo builds for the integration test target.
fn binary() -> PathBuf {
  PathBuf::from(env!("CARGO_BIN_EXE_d-oauth-server"))
}

/// Run `<command> --help` and return its stdout.
fn run_help(command: &[&str]) -> TestResult<String> {
  let output = Command::new(binary())
    .args(command)
    .arg("--help")
    .output()?;
  if !output.status.success() {
    return Err(
      format!(
        "`d-oauth-server {} --help` exited with {}",
        command.join(" "),
        output.status
      )
      .into(),
    );
  }
  Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Long flags in the `Options:` section of a clap help page, excluding the
/// universal `--help` / `--version`.
fn help_flags(help: &str) -> BTreeSet<String> {
  let mut flags = BTreeSet::new();
  let mut in_options = false;
  for line in help.lines() {
    if line.trim() == "Options:" {
      in_options = true;
      continue;
    }
    if !in_options {
      continue;
    }
    // A blank line ends the Options block; the block is the last section of a
    // clap help page.
    if line.trim().is_empty() {
      in_options = false;
      continue;
    }
    for token in line.split_whitespace() {
      let token = token.trim_end_matches(',');
      if let Some(name) = token.strip_prefix("--")
        && name != "help"
        && name != "version"
      {
        flags.insert(format!("--{name}"));
      }
    }
  }
  flags
}

/// Long flags a `docs/OPERATIONS.md` line documents for a command.
fn doc_flags(docs: &str, command: &[&str]) -> BTreeSet<String> {
  let needle = format!("d-oauth-server {}", command.join(" "));
  let mut flags = BTreeSet::new();
  for line in docs.lines() {
    if !line.contains(&needle) {
      continue;
    }
    for token in line.split_whitespace() {
      let token = token.trim_matches(|ch| ch == '`' || ch == ',');
      if let Some(name) = token.strip_prefix("--")
        && name != "help"
        && name != "version"
      {
        flags.insert(format!("--{name}"));
      }
    }
  }
  flags
}

#[test]
fn doc_cli_flags_match_help() -> TestResult {
  let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/OPERATIONS.md");
  let docs = std::fs::read_to_string(&docs_path)?;

  for command in COMMANDS {
    let label = command.join(" ");
    let help = run_help(command)?;
    // The resolved help must name the command, so a renamed or removed command
    // fails instead of silently checking the wrong surface.
    let usage = format!("d-oauth-server {label}");
    if !help.contains(&usage) {
      return Err(format!("`{label} --help` did not show usage `{usage}`").into());
    }
    let from_help = help_flags(&help);
    let from_docs = doc_flags(&docs, command);
    if from_help != from_docs {
      return Err(
        format!("flag mismatch for `{label}`: help={from_help:?} docs={from_docs:?}").into(),
      );
    }
  }
  Ok(())
}
