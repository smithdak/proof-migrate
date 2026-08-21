#![forbid(unsafe_code)]

//! Complete offline Sitecore-to-Proof candidate pipeline.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use proof_migrate_evaluate::{EvaluationReportV1, EvaluationVerdict, evaluate};
use proof_migrate_evidence::{EvidenceBundleV1, SitecoreExportV1, canonical_json, domain_digest};
use proof_migrate_improve::{ImprovementReportV1, improve};
use proof_migrate_normalize::normalize;
use proof_migrate_projector::{ProofCandidateBundleV1, ProofTargetContractV1};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

const MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunConfig {
    pub source: PathBuf,
    pub target_contract: PathBuf,
    pub output: PathBuf,
    pub source_locale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunSummaryV1 {
    pub api_version: String,
    pub output: String,
    pub source_snapshot_id: String,
    pub evaluation_verdict: EvaluationVerdict,
    pub promoted_candidate_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunManifestV1 {
    api_version: String,
    source_snapshot_id: String,
    artifacts: Vec<ArtifactManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifestEntryV1 {
    path: String,
    byte_length: u64,
    digest: String,
}

/// Runs the complete offline pipeline and atomically publishes its artifact bundle.
///
/// # Errors
///
/// Returns an error when inputs violate their contracts, projection or evaluation cannot finish,
/// the output already exists, or the complete bundle cannot be staged and published.
pub fn run_pipeline(config: &RunConfig) -> Result<RunSummaryV1> {
    if config.output.exists() {
        bail!(
            "output path already exists; choose a new directory to preserve prior evidence: {}",
            config.output.display()
        );
    }
    let source_bytes = read_bounded(&config.source, MAX_SOURCE_BYTES)
        .with_context(|| format!("failed to read source export {}", config.source.display()))?;
    let source = serde_json::from_slice::<SitecoreExportV1>(&source_bytes)
        .context("source export did not satisfy the versioned Sitecore export contract")?;
    let contract_bytes = read_bounded(&config.target_contract, 1024 * 1024).with_context(|| {
        format!(
            "failed to read Proof target contract {}",
            config.target_contract.display()
        )
    })?;
    let contract = serde_json::from_slice::<ProofTargetContractV1>(&contract_bytes)
        .context("Proof target contract is invalid")?;

    let evidence =
        normalize(source, &source_bytes).context("source evidence normalization failed")?;
    let improved = improve(&evidence, &contract, &config.source_locale)
        .context("automatic improvement loop failed")?;
    let evaluation = evaluate(&evidence, &improved.projection, &improved.report);

    let parent = config.output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output parent {}", parent.display()))?;
    let stage = Builder::new()
        .prefix(".proof-migrate-stage-")
        .tempdir_in(parent)
        .context("failed to create an isolated output staging directory")?;
    write_artifacts(
        stage.path(),
        &evidence,
        &improved.projection,
        &evaluation,
        &improved.report,
    )?;
    let stage_path = stage.keep();
    fs::rename(&stage_path, &config.output).with_context(|| {
        format!(
            "failed to publish the complete output bundle to {}",
            config.output.display()
        )
    })?;

    Ok(RunSummaryV1 {
        api_version: "proof-migrate.dev/run-summary/v1".to_owned(),
        output: config.output.display().to_string(),
        source_snapshot_id: evidence.snapshot_id,
        evaluation_verdict: evaluation.verdict,
        promoted_candidate_count: improved
            .report
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.status == proof_migrate_improve::CandidateStatus::PromotedNonProduction
            })
            .count() as u64,
    })
}

fn write_artifacts(
    output: &Path,
    evidence: &EvidenceBundleV1,
    projection: &ProofCandidateBundleV1,
    evaluation: &EvaluationReportV1,
    improvement: &ImprovementReportV1,
) -> Result<()> {
    let mut manifest_entries = Vec::new();
    write_one(output, "evidence.json", evidence, &mut manifest_entries)?;
    write_one(
        output,
        "proof-candidate.json",
        projection,
        &mut manifest_entries,
    )?;
    write_one(output, "evaluation.json", evaluation, &mut manifest_entries)?;
    write_one(
        output,
        "improvement.json",
        improvement,
        &mut manifest_entries,
    )?;
    let manifest = RunManifestV1 {
        api_version: "proof-migrate.dev/run-manifest/v1".to_owned(),
        source_snapshot_id: evidence.snapshot_id.clone(),
        artifacts: manifest_entries,
    };
    write_canonical(&output.join("run-manifest.json"), &manifest)?;
    Ok(())
}

fn write_one<T: Serialize>(
    output: &Path,
    name: &str,
    value: &T,
    manifest: &mut Vec<ArtifactManifestEntryV1>,
) -> Result<()> {
    let path = output.join(name);
    let bytes = write_canonical(&path, value)?;
    manifest.push(ArtifactManifestEntryV1 {
        path: name.to_owned(),
        byte_length: bytes.len() as u64,
        digest: domain_digest("proof-migrate:run-artifact:v1", &bytes),
    });
    Ok(())
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json(value).map_err(anyhow::Error::msg)?;
    let bytes = canonical.into_bytes();
    fs::write(path, &bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(bytes)
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }
    if metadata.len() > max_bytes {
        bail!(
            "file exceeds the {} byte safety limit: {}",
            max_bytes,
            path.display()
        );
    }
    fs::read(path).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use proof_migrate_evaluate::EvaluationVerdict;
    use proof_migrate_improve::{CandidateStatus, ImprovementReportV1};
    use tempfile::tempdir;

    use super::{RunConfig, run_pipeline};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn complete_pipeline_is_byte_reproducible() {
        let temp = tempdir().unwrap();
        let config = |name: &str| RunConfig {
            source: root().join("evaluations/fixtures/sitecore-export.synthetic.json"),
            target_contract: root().join("contracts/proof/contract.v1.json"),
            output: temp.path().join(name),
            source_locale: "en-US".to_owned(),
        };
        let first = run_pipeline(&config("first")).unwrap();
        let second = run_pipeline(&config("second")).unwrap();
        assert_eq!(first.evaluation_verdict, EvaluationVerdict::Pass);
        assert_eq!(second.evaluation_verdict, EvaluationVerdict::Pass);
        for name in [
            "evidence.json",
            "proof-candidate.json",
            "evaluation.json",
            "improvement.json",
            "run-manifest.json",
        ] {
            assert_eq!(
                fs::read(temp.path().join("first").join(name)).unwrap(),
                fs::read(temp.path().join("second").join(name)).unwrap(),
                "{name} differed across identical runs"
            );
        }
        let improvement: ImprovementReportV1 =
            serde_json::from_slice(&fs::read(temp.path().join("first/improvement.json")).unwrap())
                .unwrap();
        assert_eq!(improvement.model_calls_on_known_path, 0);
        assert!(
            improvement
                .candidates
                .iter()
                .any(|candidate| { candidate.status == CandidateStatus::PromotedNonProduction })
        );
    }

    #[test]
    fn existing_output_is_never_overwritten() {
        let temp = tempdir().unwrap();
        let output = temp.path().join("existing");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("keep.txt"), "user data").unwrap();
        let result = run_pipeline(&RunConfig {
            source: root().join("evaluations/fixtures/sitecore-export.synthetic.json"),
            target_contract: root().join("contracts/proof/contract.v1.json"),
            output: output.clone(),
            source_locale: "en-US".to_owned(),
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(output.join("keep.txt")).unwrap(),
            "user data"
        );
    }
}
