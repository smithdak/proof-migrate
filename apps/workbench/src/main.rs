#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use proof_migrate::{PreflightConfig, RunConfig, run_pipeline, run_preflight};
use proof_migrate_evaluate::EvaluationVerdict;
use proof_migrate_preflight::PreflightStatus;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "proof-migrate",
    version,
    about = "Offline Sitecore-to-Proof migration workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Normalize evidence, project a candidate, improve safely, and evaluate it.
    Run {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "contracts/proof/contract.v1.json")]
        contract: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value = "en-US")]
        source_locale: String,
    },
    /// Validate a content-free estate observation and emit a read-only readiness manifest.
    Preflight {
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run {
            source,
            contract,
            output,
            source_locale,
        } => match run_pipeline(&RunConfig {
            source,
            target_contract: contract,
            output,
            source_locale,
        }) {
            Ok(summary) => {
                if let Err(exit) = print_summary(&summary) {
                    return exit;
                }
                if summary.evaluation_verdict == EvaluationVerdict::Pass {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(error) => fail(&error),
        },
        Command::Preflight {
            observation,
            output,
        } => match run_preflight(&PreflightConfig {
            observation,
            output,
        }) {
            Ok(summary) => {
                if let Err(exit) = print_summary(&summary) {
                    return exit;
                }
                if summary.status == PreflightStatus::Ready {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(2)
                }
            }
            Err(error) => fail(&error),
        },
    }
}

fn print_summary(summary: &impl Serialize) -> Result<(), ExitCode> {
    match serde_json::to_string_pretty(summary) {
        Ok(serialized) => {
            println!("{serialized}");
            Ok(())
        }
        Err(error) => {
            eprintln!("failed to serialize command summary: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn fail(error: &anyhow::Error) -> ExitCode {
    eprintln!("{error:#}");
    ExitCode::FAILURE
}
