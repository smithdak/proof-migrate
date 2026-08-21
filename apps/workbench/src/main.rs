#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use proof_migrate::{RunConfig, run_pipeline};
use proof_migrate_evaluate::EvaluationVerdict;

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
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Run {
            source,
            contract,
            output,
            source_locale,
        } => run_pipeline(&RunConfig {
            source,
            target_contract: contract,
            output,
            source_locale,
        }),
    };
    match result {
        Ok(summary) => {
            match serde_json::to_string_pretty(&summary) {
                Ok(serialized) => println!("{serialized}"),
                Err(error) => {
                    eprintln!("failed to serialize run summary: {error}");
                    return ExitCode::FAILURE;
                }
            }
            if summary.evaluation_verdict == EvaluationVerdict::Pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}
